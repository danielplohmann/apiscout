#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
capture_aslr_geometry.py -- ASLR / module-geometry capture for the relative-IAT-recovery study.

Records everything needed to (a) use a memory dump as ground truth for ASLR-agnostic import
recovery and (b) retrieve the exact reference binaries later, without shipping the DLLs.

Stdlib + ctypes only. No pip installs. Python 3.7+ on Windows (the --selftest and --inspect
subcommands also run on Linux/macOS).

--------------------------------------------------------------------------------------------
QUICK RECIPE (run as Administrator, from an elevated 64-bit Python; see NOTES for 32-bit)
--------------------------------------------------------------------------------------------
  # 1. once per boot, before anything else -- the environment reference
  py -3 capture_aslr_geometry.py --exports --tag "win11-vm-A boot1" survey

  # 2. per target: launch, let it run, dump its main image + record its module list
  py -3 capture_aslr_geometry.py run --exe C:\Windows\System32\notepad.exe --wait 3 --kill

  # 3. or attach to something already running
  py -3 capture_aslr_geometry.py dump --pid 1234

  # 4. reboot the VM and repeat steps 1-3 with --tag "... boot2"  (tests base-per-boot)

  # everything lands in .\aslr_capture_<host>_<bootid>\ and is zipped at the end of each run.
  # Ship the zip(s). Nothing else needed.

--------------------------------------------------------------------------------------------
WHAT IS RECORDED
--------------------------------------------------------------------------------------------
manifest.json        OS build/UBR/edition/arch, BuildLabEx, boot id + boot time, allocation
                     granularity (empirically confirms the 64KB image-base claim), MoveImages
                     registry value, Get-ProcessMitigation -System raw output, tool version.
modules/*.json       per process: pid, name, path, bitness, and for every loaded module:
                       base, size_of_image (from MODULEINFO and from the PE header),
                       path, file_version, product_version, pe_timestamp, pe_size_of_image,
                       machine, dll_characteristics (DYNAMICBASE / HIGH_ENTROPY_VA / etc),
                       sha256 of the on-disk file, preferred_image_base, aslr_delta,
                       base_64k_aligned
                     -> pe_timestamp + pe_size_of_image is the Microsoft symbol-server key
                     -> sha256 is the winbindex key
                     Both together mean the exact reference binary stays retrievable.
exports/apiscout_db.json
                     apiscout-compatible reference DB (same schema as dbs/*.json):
                     dlls -> "<bitness>_<version>_<name>_0x<base>" -> exports[{address,name,ordinal}]
                     plus forwarders and, with --argcounts, heuristic x86 stdcall arg counts.
dumps/*              Malpedia-style mapped-image dumps: <sha256>_dump_0x<base>
                     (8 hex digits for 32-bit targets, 16 for 64-bit), sha256 of the on-disk
                     image file, base in hex -- ingests into apiscout/SMDA unchanged.
geometry_check.txt   immediate pass/fail on the invariants: all bases 64KB aligned?
                     observed base entropy? duplicate bases across processes (per-boot sharing)?

--------------------------------------------------------------------------------------------
NOTES / GOTCHAS
--------------------------------------------------------------------------------------------
* Run elevated, otherwise most processes are not enumerable.
* A 64-bit Python can enumerate and read 32-bit (WOW64) processes fine (LIST_MODULES_ALL).
  For 32-bit *targets* that is enough. Only run a 32-bit Python additionally if you want a
  WOW64 view of the system DLL set (SysWOW64 copies) -- `survey --exports` from 64-bit
  already walks every module path it sees, including SysWOW64 ones.
* --exports parses export tables from the files ON DISK (deterministic, matches winbindex),
  not from memory.
* --argcounts is a documented heuristic (last `ret imm16` inside the export's byte range);
  it is advisory only and x86-32 only. Prefer microsoft/win32metadata for authoritative
  prototypes; this exists for DLLs with no metadata.
* Nothing is uploaded, nothing is executed except what you pass to `run`.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import hashlib
import json
import os
import platform
import struct
import subprocess
import sys
import time
import zipfile

TOOL_VERSION = "1.0"
IS_WIN = sys.platform == "win32"

# ============================================================================================
# PE parsing (pure, operates on bytes -- unit-tested by --selftest)
# ============================================================================================

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
DLL_CHARACTERISTICS = [
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
]
MACHINE = {0x014C: "i386", 0x8664: "amd64", 0x01C4: "armnt", 0xAA64: "arm64", 0x0200: "ia64"}


class PEError(Exception):
    pass


class PEFile:
    """Minimal read-only PE reader: headers, sections, export directory."""

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEError("not an MZ image")
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew <= 0 or e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PEError("bad PE signature")
        self.pe_off = e_lfanew
        (self.machine, self.num_sections, self.timestamp, _sym, _nsym,
         self.size_of_opt_hdr, self.characteristics) = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
        opt = e_lfanew + 24
        if opt + 2 > len(data):
            raise PEError("truncated optional header")
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic == 0x20B:
            self.pe32plus = True
        elif magic == 0x10B:
            self.pe32plus = False
        else:
            raise PEError("unknown optional header magic 0x%x" % magic)
        if self.pe32plus:
            (self.size_of_image,) = struct.unpack_from("<I", data, opt + 56)
            (self.image_base,) = struct.unpack_from("<Q", data, opt + 24)
            (self.dll_characteristics,) = struct.unpack_from("<H", data, opt + 70)
            (self.num_dirs,) = struct.unpack_from("<I", data, opt + 108)
            dir_off = opt + 112
        else:
            (self.size_of_image,) = struct.unpack_from("<I", data, opt + 56)
            (self.image_base,) = struct.unpack_from("<I", data, opt + 28)
            (self.dll_characteristics,) = struct.unpack_from("<H", data, opt + 70)
            (self.num_dirs,) = struct.unpack_from("<I", data, opt + 92)
            dir_off = opt + 96
        self.dirs = []
        for i in range(min(self.num_dirs, 16)):
            if dir_off + i * 8 + 8 <= len(data):
                self.dirs.append(struct.unpack_from("<II", data, dir_off + i * 8))
            else:
                self.dirs.append((0, 0))
        sec_off = opt + self.size_of_opt_hdr
        self.sections = []
        for i in range(self.num_sections):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\0").decode("latin-1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            (flags,) = struct.unpack_from("<I", data, o + 36)
            self.sections.append(dict(name=name, vaddr=vaddr, vsize=vsize,
                                      rawsize=rawsize, rawptr=rawptr, flags=flags))

    # -- helpers ---------------------------------------------------------------------------
    @property
    def machine_name(self) -> str:
        return MACHINE.get(self.machine, "0x%04x" % self.machine)

    @property
    def bitness(self) -> int:
        return 64 if self.pe32plus else 32

    def characteristics_list(self):
        return [n for bit, n in DLL_CHARACTERISTICS if self.dll_characteristics & bit]

    def rva_to_off(self, rva: int):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                delta = rva - s["vaddr"]
                if delta < s["rawsize"]:
                    return s["rawptr"] + delta
                return None
        # images with no section covering it (header area)
        if rva < (self.sections[0]["vaddr"] if self.sections else self.size_of_image):
            return rva
        return None

    def _cstr(self, rva: int, limit: int = 512):
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            return None
        return self.data[off:end].decode("latin-1")

    def exports(self):
        """-> (list of dicts {name, ordinal, address(RVA), forwarder}, export_dir_range)"""
        edir_rva, edir_size = self.dirs[IMAGE_DIRECTORY_ENTRY_EXPORT] if self.dirs else (0, 0)
        if not edir_rva:
            return [], (0, 0)
        off = self.rva_to_off(edir_rva)
        if off is None or off + 40 > len(self.data):
            return [], (edir_rva, edir_size)
        (_flags, _ts, _mj, _mn, _name_rva, ordinal_base, n_funcs, n_names,
         funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", self.data, off)
        out = []
        f_off = self.rva_to_off(funcs_rva)
        n_off = self.rva_to_off(names_rva) if names_rva else None
        o_off = self.rva_to_off(ords_rva) if ords_rva else None
        named = {}
        if n_off is not None and o_off is not None:
            for i in range(n_names):
                if n_off + i * 4 + 4 > len(self.data) or o_off + i * 2 + 2 > len(self.data):
                    break
                (nm_rva,) = struct.unpack_from("<I", self.data, n_off + i * 4)
                (idx,) = struct.unpack_from("<H", self.data, o_off + i * 2)
                nm = self._cstr(nm_rva)
                if nm is not None:
                    named[idx] = nm
        if f_off is None:
            return [], (edir_rva, edir_size)
        for i in range(n_funcs):
            if f_off + i * 4 + 4 > len(self.data):
                break
            (addr,) = struct.unpack_from("<I", self.data, f_off + i * 4)
            if addr == 0:
                continue
            name = named.get(i)
            fwd = None
            if edir_rva <= addr < edir_rva + edir_size:
                fwd = self._cstr(addr)
            out.append(dict(name=name if name else "#%d" % (ordinal_base + i),
                            ordinal=ordinal_base + i, address=addr, forwarder=fwd))
        out.sort(key=lambda e: (e["address"], e["name"]))
        return out, (edir_rva, edir_size)

    # -- heuristic x86 stdcall argument counts ---------------------------------------------
    def stdcall_argcounts(self, exports, max_scan: int = 0x800):
        """HEURISTIC, x86-32 only. For each export, look at the byte range up to the next
        export (capped) and take the last plausible `ret imm16` (0xC2 imm16, imm16 % 4 == 0).
        Returns {name: {"args": n, "how": "ret_imm16"|"ret_void"|None}}.
        Advisory only -- no disassembly, so misaligned 0xC2 bytes can fool it."""
        if self.pe32plus:
            return {}
        code = [e for e in exports if e["forwarder"] is None]
        addrs = sorted({e["address"] for e in code})
        nxt = {a: (addrs[i + 1] if i + 1 < len(addrs) else None) for i, a in enumerate(addrs)}
        sec_end = {}
        for s in self.sections:
            sec_end[s["name"]] = s["vaddr"] + max(s["vsize"], s["rawsize"])

        def containing_end(rva):
            for s in self.sections:
                if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                    return s["vaddr"] + min(s["vsize"] or s["rawsize"], s["rawsize"])
            return None

        res = {}
        PAD = (0x00, 0xCC, 0x90)
        for e in code:
            start = e["address"]
            hard = containing_end(start)
            if hard is None:
                continue
            end = nxt[start] or (start + max_scan)
            end = min(end, start + max_scan, hard)
            if end - start < 3:
                continue
            o1, o2 = self.rva_to_off(start), self.rva_to_off(end - 1)
            if o1 is None or o2 is None or o2 <= o1:
                continue
            blob = self.data[o1:o2 + 1]
            # trim trailing alignment padding, keeping 2 bytes of slack for a ret's imm16
            last = len(blob) - 1
            while last >= 0 and blob[last] in PAD:
                last -= 1
            scan = min(len(blob), last + 4)
            best = None
            for p in range(scan - 1, -1, -1):
                if blob[p] == 0xC2 and p + 3 <= scan:
                    (imm,) = struct.unpack_from("<H", blob, p + 1)
                    if imm % 4 == 0 and 0 < imm <= 0x200:
                        best = imm // 4
                        break
                if blob[p] == 0xC3:
                    best = 0
                    break
            if best is not None:
                res[e["name"]] = dict(args=best, how="ret_imm16" if best else "ret_void")
        return res


def sha256_file(path: str):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


# ============================================================================================
# Windows plumbing
# ============================================================================================

if IS_WIN:
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    ver = ctypes.WinDLL("version", use_last_error=True)

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    LIST_MODULES_ALL = 0x03

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", wintypes.DWORD),
                    ("EntryPoint", ctypes.c_void_p)]

    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                    ("wReserved", wintypes.WORD),
                    ("dwPageSize", wintypes.DWORD),
                    ("lpMinimumApplicationAddress", ctypes.c_void_p),
                    ("lpMaximumApplicationAddress", ctypes.c_void_p),
                    ("dwActiveProcessorMask", ctypes.c_void_p),
                    ("dwNumberOfProcessors", wintypes.DWORD),
                    ("dwProcessorType", wintypes.DWORD),
                    ("dwAllocationGranularity", wintypes.DWORD),
                    ("wProcessorLevel", wintypes.WORD),
                    ("wProcessorRevision", wintypes.WORD)]

    def system_info():
        si = SYSTEM_INFO()
        k32.GetNativeSystemInfo(ctypes.byref(si))
        return dict(page_size=si.dwPageSize,
                    allocation_granularity=si.dwAllocationGranularity,
                    num_processors=si.dwNumberOfProcessors,
                    max_app_address=si.lpMaximumApplicationAddress or 0)

    def enum_pids():
        n = 4096
        while True:
            arr = (wintypes.DWORD * n)()
            need = wintypes.DWORD()
            if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(need)):
                return []
            if need.value < ctypes.sizeof(arr):
                return [arr[i] for i in range(need.value // ctypes.sizeof(wintypes.DWORD)) if arr[i]]
            n *= 2

    def open_proc(pid, access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
        h = k32.OpenProcess(access, False, pid)
        if not h:
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
        return h or None

    def is_wow64(h):
        b = wintypes.BOOL()
        try:
            if k32.IsWow64Process(h, ctypes.byref(b)):
                return bool(b.value)
        except Exception:
            pass
        return False

    def proc_image_path(h):
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        try:
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
        except Exception:
            pass
        n = psapi.GetModuleFileNameExW(h, None, buf, len(buf))
        return buf.value if n else None

    def enum_modules(h):
        n = 1024
        while True:
            arr = (ctypes.c_void_p * n)()
            need = wintypes.DWORD()
            ok = psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr),
                                            ctypes.byref(need), LIST_MODULES_ALL)
            if not ok:
                return []
            if need.value <= ctypes.sizeof(arr):
                cnt = need.value // ctypes.sizeof(ctypes.c_void_p)
                return [arr[i] for i in range(cnt) if arr[i]]
            n = (need.value // ctypes.sizeof(ctypes.c_void_p)) + 64

    def module_info(h, base):
        mi = MODULEINFO()
        if not psapi.GetModuleInformation(h, ctypes.c_void_p(base), ctypes.byref(mi),
                                          ctypes.sizeof(mi)):
            return None
        return dict(base=mi.lpBaseOfDll or 0, size=mi.SizeOfImage, entry=mi.EntryPoint or 0)

    def module_path(h, base):
        buf = ctypes.create_unicode_buffer(32768)
        n = psapi.GetModuleFileNameExW(h, ctypes.c_void_p(base), buf, len(buf))
        return buf.value if n else None

    def read_mem(h, addr, size):
        buf = (ctypes.c_char * size)()
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
        if not ok and got.value == 0:
            return None
        return bytes(buf[:got.value])

    def file_versions(path):
        """-> (file_version, product_version) from the VS_FIXEDFILEINFO block."""
        try:
            size = ver.GetFileVersionInfoSizeW(path, None)
            if not size:
                return None, None
            buf = ctypes.create_string_buffer(size)
            if not ver.GetFileVersionInfoW(path, 0, size, buf):
                return None, None
            p = ctypes.c_void_p()
            ln = wintypes.UINT()
            if not ver.VerQueryValueW(buf, "\\", ctypes.byref(p), ctypes.byref(ln)):
                return None, None
            blob = ctypes.string_at(p, ln.value)
            if len(blob) < 52:
                return None, None
            fv_ms, fv_ls, pv_ms, pv_ls = struct.unpack_from("<IIII", blob, 8)
            def fmt(ms, ls):
                return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
            return fmt(fv_ms, fv_ls), fmt(pv_ms, pv_ls)
        except Exception:
            return None, None

    def boot_identity():
        try:
            up_ms = k32.GetTickCount64()
        except Exception:
            up_ms = k32.GetTickCount()
        now = time.time()
        boot_ts = now - up_ms / 1000.0
        return dict(uptime_ms=int(up_ms),
                    boot_time_utc=_dt.datetime.utcfromtimestamp(boot_ts).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    boot_id="%d" % int(boot_ts))

    def os_registry_info():
        out = {}
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
                for name in ("ProductName", "EditionID", "DisplayVersion", "ReleaseId",
                             "CurrentBuild", "CurrentBuildNumber", "BuildLabEx",
                             "CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "UBR",
                             "InstallationType"):
                    try:
                        out[name] = winreg.QueryValueEx(k, name)[0]
                    except OSError:
                        pass
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") as k:
                for name in ("MoveImages",):
                    try:
                        out[name] = winreg.QueryValueEx(k, name)[0]
                    except OSError:
                        out[name] = "<unset>"
        except Exception as e:
            out["registry_error"] = repr(e)
        return out

    def powershell(cmd, timeout=90):
        try:
            p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                               capture_output=True, text=True, timeout=timeout)
            return (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        except Exception as e:
            return "<failed: %r>" % (e,)


# ============================================================================================
# Collection logic
# ============================================================================================

_pe_cache = {}


def pe_facts(path):
    """Parse the on-disk file once; cache by path."""
    if path in _pe_cache:
        return _pe_cache[path]
    facts = dict(path=path, sha256=None, pe_timestamp=None, pe_size_of_image=None,
                 machine=None, bitness=None, dll_characteristics=None,
                 preferred_image_base=None, parse_error=None,
                 symsrv_key=None, num_exports=None)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        facts["parse_error"] = "read: %r" % (e,)
        _pe_cache[path] = (facts, None)
        return _pe_cache[path]
    facts["sha256"] = hashlib.sha256(data).hexdigest()
    facts["file_size"] = len(data)
    pe = None
    try:
        pe = PEFile(data)
        facts.update(pe_timestamp=pe.timestamp, pe_size_of_image=pe.size_of_image,
                     machine=pe.machine_name, bitness=pe.bitness,
                     dll_characteristics=pe.characteristics_list(),
                     preferred_image_base=pe.image_base,
                     symsrv_key="%08X%X" % (pe.timestamp, pe.size_of_image))
    except PEError as e:
        facts["parse_error"] = "pe: %s" % (e,)
    _pe_cache[path] = (facts, pe)
    return _pe_cache[path]


def collect_process(pid, want_paths):
    h = open_proc(pid)
    if not h:
        return None
    try:
        img = proc_image_path(h)
        wow = is_wow64(h)
        mods = []
        for base in enum_modules(h):
            base = int(base)
            mi = module_info(h, base) or {}
            path = module_path(h, base)
            facts, _pe = pe_facts(path) if path else ({}, None)
            fv, pv = (file_versions(path) if path else (None, None))
            rec = dict(base=base, base_hex="0x%X" % base,
                       size_of_image=mi.get("size"), entry_point=mi.get("entry"),
                       path=path, file_version=fv, product_version=pv,
                       base_64k_aligned=(base % 0x10000 == 0),
                       base_4k_aligned=(base % 0x1000 == 0))
            for k in ("sha256", "pe_timestamp", "pe_size_of_image", "machine", "bitness",
                      "dll_characteristics", "preferred_image_base", "symsrv_key",
                      "parse_error", "file_size"):
                rec[k] = facts.get(k)
            if rec.get("preferred_image_base") is not None:
                rec["aslr_delta"] = base - rec["preferred_image_base"]
            mods.append(rec)
            if path:
                want_paths.add(path)
        mods.sort(key=lambda m: m["base"])
        return dict(pid=pid, image=img, wow64=wow,
                    bitness=(32 if wow else (64 if ctypes.sizeof(ctypes.c_void_p) == 8 else 32)),
                    module_count=len(mods), modules=mods)
    finally:
        k32.CloseHandle(h)


def build_apiscout_db(paths, os_name, os_version, argcounts=False, progress=True):
    """Reference DB in apiscout's own JSON schema, from the files on disk."""
    dlls = {}
    total = 0
    paths = sorted(paths)
    for i, path in enumerate(paths):
        if progress and i % 25 == 0:
            print("    exports %d/%d ..." % (i, len(paths)), flush=True)
        facts, pe = pe_facts(path)
        if pe is None:
            continue
        try:
            exps, _rng = pe.exports()
        except Exception as e:
            continue
        if not exps:
            continue
        name = os.path.basename(path)
        version = facts.get("file_version") or "0.0.0.0"
        key = "%d_%s_%s_0x%x" % (pe.bitness, version, name, pe.image_base)
        if key in dlls:
            continue
        entry = dict(aslr_offset=0, base_address=pe.image_base, bitness=pe.bitness,
                     filepath=path, version=version,
                     sha256=facts.get("sha256"), pe_timestamp=facts.get("pe_timestamp"),
                     pe_size_of_image=facts.get("pe_size_of_image"),
                     symsrv_key=facts.get("symsrv_key"),
                     exports=[dict(address=e["address"], name=e["name"], ordinal=e["ordinal"])
                              for e in exps if e["forwarder"] is None],
                     forwarders=[dict(name=e["name"], ordinal=e["ordinal"], target=e["forwarder"])
                                 for e in exps if e["forwarder"] is not None])
        if argcounts and pe.bitness == 32:
            try:
                entry["stdcall_argcounts_heuristic"] = pe.stdcall_argcounts(exps)
            except Exception:
                pass
        dlls[key] = entry
        total += len(entry["exports"])
    return dict(aslr_offsets=True, crawled_paths=["<from live module list>"], dlls=dlls,
                filtered=False, num_apis=total, num_dlls=len(dlls),
                os_name=os_name, os_version=os_version,
                generator="capture_aslr_geometry.py %s" % TOOL_VERSION)


def geometry_report(procs):
    lines = []
    all_mods = [(p["pid"], m) for p in procs for m in p["modules"]]
    if not all_mods:
        return "no modules collected\n"
    bad64 = [(pid, m) for pid, m in all_mods if not m["base_64k_aligned"]]
    bad4 = [(pid, m) for pid, m in all_mods if not m["base_4k_aligned"]]
    lines.append("modules observed:              %d (across %d processes)" % (len(all_mods), len(procs)))
    lines.append("INVARIANT I2  64KB-aligned:    %s  (%d violations)"
                 % ("PASS" if not bad64 else "FAIL", len(bad64)))
    lines.append("              4KB-aligned:     %s  (%d violations)"
                 % ("PASS" if not bad4 else "FAIL", len(bad4)))
    for pid, m in bad64[:20]:
        lines.append("    !! pid %-6d %-40s base=0x%X" % (pid, os.path.basename(m["path"] or "?"), m["base"]))
    # I3: same module -> same base across processes?
    bybase = {}
    conflicts = []
    for pid, m in all_mods:
        key = (m.get("sha256"), (m["path"] or "").lower())
        if not key[0]:
            continue
        if key in bybase and bybase[key][0] != m["base"]:
            conflicts.append((key[1], bybase[key], (m["base"], pid)))
        else:
            bybase.setdefault(key, (m["base"], pid))
    lines.append("INVARIANT I3  one base per module per boot: %s  (%d modules with >1 base)"
                 % ("PASS" if not conflicts else "PARTIAL", len(conflicts)))
    for path, a, b in conflicts[:20]:
        lines.append("    ~ %-50s 0x%X (pid %d) vs 0x%X (pid %d)"
                     % (os.path.basename(path), a[0], a[1], b[0], b[1]))
    lines.append("  (32-bit WOW64 copies of a DLL legitimately differ from the 64-bit copy;")
    lines.append("   check the paths above before treating a PARTIAL as a violation.)")
    # entropy-ish view
    uniq = sorted({m["base"] for _, m in all_mods})
    lines.append("distinct module bases:         %d   min=0x%X max=0x%X" % (len(uniq), uniq[0], uniq[-1]))
    dyn = sum(1 for _, m in all_mods if m.get("dll_characteristics") and "DYNAMIC_BASE" in m["dll_characteristics"])
    hev = sum(1 for _, m in all_mods if m.get("dll_characteristics") and "HIGH_ENTROPY_VA" in m["dll_characteristics"])
    lines.append("modules with DYNAMIC_BASE:     %d / %d   HIGH_ENTROPY_VA: %d" % (dyn, len(all_mods), hev))
    nonrel = [(pid, m) for pid, m in all_mods
              if m.get("dll_characteristics") is not None and "DYNAMIC_BASE" not in m["dll_characteristics"]]
    if nonrel:
        lines.append("non-DYNAMICBASE modules (expected at preferred base -- useful anchors):")
        for pid, m in nonrel[:15]:
            lines.append("    %-40s base=0x%X preferred=0x%X" %
                         (os.path.basename(m["path"] or "?"), m["base"], m.get("preferred_image_base") or 0))
    return "\n".join(lines) + "\n"


# ============================================================================================
# Dumping
# ============================================================================================

def dump_module(h, mod, outdir, chunk=1 << 20):
    """Malpedia-style mapped-image dump: <sha256>_dump_0x<base>."""
    base, size = mod["base"], mod.get("size_of_image") or mod.get("pe_size_of_image")
    if not size:
        return None, "no size"
    sha = mod.get("sha256") or ("nosha_%X" % base)
    bits = mod.get("bitness") or (64 if base > 0xFFFFFFFF else 32)
    width = 16 if bits == 64 else 8
    fname = "%s_dump_0x%0*x" % (sha, width, base)
    path = os.path.join(outdir, fname)
    got = 0
    holes = 0
    with open(path, "wb") as f:
        off = 0
        while off < size:
            n = min(chunk, size - off)
            data = read_mem(h, base + off, n)
            if data is None or len(data) < n:
                # page-granular retry so one unreadable page doesn't kill the dump
                buf = bytearray(n)
                for p in range(0, n, 0x1000):
                    d = read_mem(h, base + off + p, min(0x1000, n - p))
                    if d:
                        buf[p:p + len(d)] = d
                    else:
                        holes += 1
                data = bytes(buf)
            f.write(data)
            got += len(data)
            off += n
    return dict(file=fname, bytes=got, unreadable_pages=holes,
                base="0x%0*x" % (width, base), size_of_image=size,
                source_path=mod.get("path"), sha256_of_file=mod.get("sha256")), None


# ============================================================================================
# Commands
# ============================================================================================

def out_root(args):
    if IS_WIN:
        bid = boot_identity()["boot_id"]
    else:
        bid = "nonwin"
    host = platform.node() or "host"
    d = args.out or ("aslr_capture_%s_%s" % (host, bid))
    os.makedirs(d, exist_ok=True)
    for sub in ("modules", "exports", "dumps"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return d


def write_manifest(root, args, extra=None):
    reg = os_registry_info()
    man = dict(tool="capture_aslr_geometry.py", tool_version=TOOL_VERSION,
               captured_utc=_dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
               tag=args.tag, hostname=platform.node(),
               python=dict(version=sys.version, bitness=8 * ctypes.sizeof(ctypes.c_void_p)),
               platform=dict(machine=platform.machine(), release=platform.release(),
                             version=platform.version()),
               registry=reg, boot=boot_identity(), system_info=system_info(),
               notes=dict(
                   allocation_granularity_is_image_base_granularity=
                   "image bases are expected to be multiples of dwAllocationGranularity",
                   symsrv_key_format="<TimeDateStamp:08X><SizeOfImage:X> -- "
                                     "https://msdl.microsoft.com/download/symbols/<name>/<key>/<name>",
                   winbindex_key="sha256 of the on-disk file"))
    if not args.no_powershell:
        man["process_mitigation_system"] = powershell("Get-ProcessMitigation -System | Out-String -Width 200")
        man["secureboot_and_vbs"] = powershell(
            "try{Confirm-SecureBootUEFI}catch{'n/a'}; "
            "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ErrorAction SilentlyContinue | Out-String -Width 200")
        man["av_products"] = powershell(
            "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct "
            "-ErrorAction SilentlyContinue | Select displayName,pathToSignedProductExe | Out-String -Width 200")
    if extra:
        man.update(extra)
    p = os.path.join(root, "manifest.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(man, f, indent=2, ensure_ascii=False, default=str)
    return man


def cmd_survey(args):
    root = out_root(args)
    print("[*] output: %s" % os.path.abspath(root))
    man = write_manifest(root, args)
    gran = man["system_info"]["allocation_granularity"]
    print("[*] allocation granularity = 0x%X (%d KB)" % (gran, gran // 1024))
    pids = enum_pids()
    print("[*] enumerating %d processes ..." % len(pids))
    want = set()
    procs = []
    skipped = 0
    for i, pid in enumerate(pids):
        if i % 25 == 0:
            print("    %d/%d ..." % (i, len(pids)), flush=True)
        try:
            rec = collect_process(pid, want)
        except Exception as e:
            rec = None
            print("    pid %d failed: %r" % (pid, e))
        if rec is None:
            skipped += 1
            continue
        procs.append(rec)
        with open(os.path.join(root, "modules", "pid_%d.json" % pid), "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False, default=str)
    print("[*] %d processes collected, %d inaccessible, %d distinct module files"
          % (len(procs), skipped, len(want)))
    rep = geometry_report(procs)
    with open(os.path.join(root, "geometry_check.txt"), "w", encoding="utf-8") as f:
        f.write(rep)
    print("\n" + rep)
    if args.exports:
        osn = str(man["registry"].get("ProductName", "Windows"))
        osv = "%s.%s" % (man["registry"].get("CurrentBuild", "?"), man["registry"].get("UBR", "?"))
        print("[*] building apiscout-compatible reference DB from %d files ..." % len(want))
        db = build_apiscout_db(want, osn, osv, argcounts=args.argcounts)
        p = os.path.join(root, "exports", "apiscout_db.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2 if args.pretty else None, ensure_ascii=False, default=str)
        print("[*] reference DB: %d DLLs, %d exports -> %s"
              % (db["num_dlls"], db["num_apis"], p))
    if not args.no_zip:
        print("[*] zip: %s" % zip_dir(root))
    return root


def _resolve_targets(rec, which):
    mods = rec["modules"]
    if which == "main":
        img = (rec.get("image") or "").lower()
        sel = [m for m in mods if (m.get("path") or "").lower() == img]
        return sel or mods[:1]
    if which == "nonsystem":
        return [m for m in mods
                if m.get("path") and "\\windows\\" not in m["path"].lower()]
    return mods


def cmd_dump(args):
    root = out_root(args)
    print("[*] output: %s" % os.path.abspath(root))
    man = write_manifest(root, args)
    want = set()
    rec = collect_process(args.pid, want)
    if rec is None:
        print("[!] cannot open pid %d (run elevated?)" % args.pid)
        return root
    with open(os.path.join(root, "modules", "pid_%d.json" % args.pid), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False, default=str)
    print("[*] pid %d (%s) wow64=%s, %d modules"
          % (args.pid, rec.get("image"), rec.get("wow64"), rec["module_count"]))
    h = open_proc(args.pid)
    if not h:
        print("[!] reopen failed")
        return root
    results = []
    try:
        for m in _resolve_targets(rec, args.which):
            info, err = dump_module(h, m, os.path.join(root, "dumps"))
            if err:
                print("    skip %s: %s" % (m.get("path"), err))
                continue
            results.append(info)
            print("    dumped %-52s %d bytes%s"
                  % (info["file"], info["bytes"],
                     "  (%d unreadable pages)" % info["unreadable_pages"] if info["unreadable_pages"] else ""))
    finally:
        k32.CloseHandle(h)
    with open(os.path.join(root, "dumps", "pid_%d_dumps.json" % args.pid), "w", encoding="utf-8") as f:
        json.dump(dict(pid=args.pid, image=rec.get("image"), dumps=results), f, indent=2, default=str)
    rep = geometry_report([rec])
    with open(os.path.join(root, "geometry_check.txt"), "a", encoding="utf-8") as f:
        f.write("\n== pid %d ==\n" % args.pid + rep)
    print("\n" + rep)
    if args.exports:
        osn = str(man["registry"].get("ProductName", "Windows"))
        osv = "%s.%s" % (man["registry"].get("CurrentBuild", "?"), man["registry"].get("UBR", "?"))
        db = build_apiscout_db(want, osn, osv, argcounts=args.argcounts)
        with open(os.path.join(root, "exports", "apiscout_db_pid_%d.json" % args.pid), "w",
                  encoding="utf-8") as f:
            json.dump(db, f, indent=2 if args.pretty else None, ensure_ascii=False, default=str)
        print("[*] reference DB: %d DLLs, %d exports" % (db["num_dlls"], db["num_apis"]))
    if not args.no_zip:
        print("[*] zip: %s" % zip_dir(root))
    return root


def cmd_run(args):
    """Launch a binary, let it settle, then dump + record. Use for benign validation targets."""
    print("[*] launching: %s" % args.exe)
    flags = 0x00000008 if args.detached else 0  # DETACHED_PROCESS
    proc = subprocess.Popen([args.exe] + (args.args or []), creationflags=flags)
    print("[*] pid %d, waiting %ss ..." % (proc.pid, args.wait))
    time.sleep(args.wait)
    args.pid = proc.pid
    try:
        root = cmd_dump(args)
    finally:
        if args.kill:
            try:
                proc.kill()
                print("[*] killed pid %d" % proc.pid)
            except Exception:
                pass
    return root


def cmd_inspect(args):
    """Offline: parse a PE and print what would be recorded. Works on any OS."""
    facts, pe = pe_facts(args.file)
    print(json.dumps({k: v for k, v in facts.items()}, indent=2, default=str))
    if pe is None:
        return
    exps, rng = pe.exports()
    print("sections: %s" % ", ".join("%s@0x%X" % (s["name"], s["vaddr"]) for s in pe.sections))
    print("exports: %d (forwarders: %d)" % (len(exps), sum(1 for e in exps if e["forwarder"])))
    for e in exps[:15]:
        print("   0x%08X  %-6s %s%s" % (e["address"], e["ordinal"], e["name"],
                                        "  -> " + e["forwarder"] if e["forwarder"] else ""))
    if args.argcounts and not pe.pe32plus:
        ac = pe.stdcall_argcounts(exps)
        print("heuristic stdcall argcounts for %d/%d exports" % (len(ac), len(exps)))
        for n, v in list(ac.items())[:15]:
            print("   %-40s %d args (%s)" % (n, v["args"], v["how"]))


def zip_dir(root):
    zp = root.rstrip("\\/") + ".zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                full = os.path.join(dirpath, fn)
                z.write(full, os.path.relpath(full, os.path.dirname(root)))
    return zp


# ============================================================================================
# Self-test (runs anywhere -- validates the PE parser against a synthetic image)
# ============================================================================================

def _build_synthetic_pe(pe32plus=False):
    """Hand-roll a tiny PE with one section and an export directory containing 3 names,
    one forwarder, and an x86 stdcall function ending in `ret 8`."""
    sect_rva, sect_off, sect_size = 0x1000, 0x400, 0x400
    names = [("Alpha", 0x1100), ("Beta", 0x1100), ("Gamma", 0x1180)]  # Alpha/Beta share an RVA
    fwd_name = "Delta"
    body = bytearray(sect_size)

    def put(rva, blob):
        body[rva - sect_rva: rva - sect_rva + len(blob)] = blob

    # code: at 0x1100 a stdcall stub `xor eax,eax; ret 8`; at 0x1180 `ret 0xC`
    put(0x1100, b"\x33\xC0\xC2\x08\x00")
    put(0x1180, b"\x33\xC0\xC2\x0C\x00")
    edir_rva = 0x1200
    strs_rva = 0x1280
    cur = strs_rva
    name_rvas = {}
    for n, _ in names:
        put(cur, n.encode() + b"\0")
        name_rvas[n] = cur
        cur += len(n) + 1
    dllname_rva = cur
    put(cur, b"synth.dll\0")
    cur += 10
    fwd_str_rva = cur          # forwarder string must live INSIDE the export directory range
    put(cur, b"OTHER.Target\0")
    cur += 13
    fwd_end = cur
    funcs_rva, nms_rva, ords_rva = 0x1300, 0x1340, 0x1380
    ordered = sorted(names, key=lambda x: x[0]) + [(fwd_name, fwd_str_rva)]
    put(funcs_rva, b"".join(struct.pack("<I", r) for _, r in ordered))
    put(nms_rva, b"".join(struct.pack("<I", name_rvas[n]) for n, _ in sorted(names, key=lambda x: x[0])))
    put(ords_rva, b"".join(struct.pack("<H", i) for i in range(len(names))))
    edir = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dllname_rva, 1,
                       len(ordered), len(names), funcs_rva, nms_rva, ords_rva)
    put(edir_rva, edir)
    edir_size = fwd_end - edir_rva      # covers the forwarder string
    magic = 0x20B if pe32plus else 0x10B
    opt_size = 240 if pe32plus else 224
    hdr = bytearray(sect_off)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    pe_off = 0x80
    hdr[pe_off:pe_off + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, pe_off + 4,
                     0x8664 if pe32plus else 0x014C, 1, 0x5DEADBEE, 0, 0, opt_size, 0x2102)
    opt = pe_off + 24
    struct.pack_into("<H", hdr, opt, magic)
    struct.pack_into("<I", hdr, opt + 56, 0x2000)                 # SizeOfImage
    if pe32plus:
        struct.pack_into("<Q", hdr, opt + 24, 0x180000000)
        struct.pack_into("<H", hdr, opt + 70, 0x0060)             # HIGH_ENTROPY_VA|DYNAMIC_BASE
        struct.pack_into("<I", hdr, opt + 108, 16)
        dir_off = opt + 112
    else:
        struct.pack_into("<I", hdr, opt + 28, 0x10000000)
        struct.pack_into("<H", hdr, opt + 70, 0x0040)             # DYNAMIC_BASE
        struct.pack_into("<I", hdr, opt + 92, 16)
        dir_off = opt + 96
    struct.pack_into("<II", hdr, dir_off, edir_rva, edir_size)
    sec = opt + opt_size
    hdr[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", hdr, sec + 8, sect_size, sect_rva, sect_size, sect_off)
    struct.pack_into("<I", hdr, sec + 36, 0x60000020)
    return bytes(hdr) + bytes(body)


def cmd_selftest(_args):
    fails = []

    def check(cond, msg):
        print(("  ok   " if cond else "  FAIL ") + msg)
        if not cond:
            fails.append(msg)

    for pe32plus in (False, True):
        label = "PE32+" if pe32plus else "PE32"
        print("[%s]" % label)
        pe = PEFile(_build_synthetic_pe(pe32plus))
        check(pe.bitness == (64 if pe32plus else 32), "bitness = %d" % pe.bitness)
        check(pe.machine_name == ("amd64" if pe32plus else "i386"), "machine = %s" % pe.machine_name)
        check(pe.timestamp == 0x5DEADBEE, "TimeDateStamp = 0x%X" % pe.timestamp)
        check(pe.size_of_image == 0x2000, "SizeOfImage = 0x%X" % pe.size_of_image)
        check("DYNAMIC_BASE" in pe.characteristics_list(),
              "DllCharacteristics = %s" % pe.characteristics_list())
        exps, _rng = pe.exports()
        byname = {e["name"]: e for e in exps}
        check(len(exps) == 4, "4 exports parsed (got %d: %s)" % (len(exps), [e["name"] for e in exps]))
        check({"Alpha", "Beta", "Gamma", "#4"} & set(byname) != set(), "names present: %s" % sorted(byname))
        check(byname.get("Alpha", {}).get("address") == 0x1100, "Alpha RVA")
        check(byname.get("Beta", {}).get("address") == 0x1100, "Beta shares Alpha's RVA (alias case)")
        check(byname.get("Gamma", {}).get("address") == 0x1180, "Gamma RVA")
        fwds = [e for e in exps if e["forwarder"]]
        check(len(fwds) == 1 and fwds[0]["forwarder"] == "OTHER.Target",
              "forwarder parsed: %s" % ([e["forwarder"] for e in fwds],))
        symkey = "%08X%X" % (pe.timestamp, pe.size_of_image)
        check(symkey == "5DEADBEE2000", "symbol-server key = %s" % symkey)
        if not pe32plus:
            ac = pe.stdcall_argcounts(exps)
            check(ac.get("Alpha", {}).get("args") == 2, "heuristic argcount Alpha = %s (ret 8 -> 2)"
                  % ac.get("Alpha", {}).get("args"))
            check(ac.get("Gamma", {}).get("args") == 3, "heuristic argcount Gamma = %s (ret 0xC -> 3)"
                  % ac.get("Gamma", {}).get("args"))
        # apiscout DB shape
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as tf:
            tf.write(_build_synthetic_pe(pe32plus))
            tmp = tf.name
        try:
            _pe_cache.pop(tmp, None)
            db = build_apiscout_db({tmp}, "SynthOS", "0.0.0", argcounts=not pe32plus, progress=False)
            check(db["num_dlls"] == 1, "apiscout DB has 1 dll")
            k = next(iter(db["dlls"]))
            check(k.startswith("%d_" % (64 if pe32plus else 32)), "DB key format: %s" % k)
            e0 = db["dlls"][k]["exports"]
            check(len(e0) == 3 and all("address" in x and "name" in x and "ordinal" in x for x in e0),
                  "exports schema matches apiscout (%d non-forwarder entries)" % len(e0))
            check(len(db["dlls"][k]["forwarders"]) == 1, "forwarders recorded separately")
            check(json.loads(json.dumps(db)) == json.loads(json.dumps(db)), "DB is JSON-serialisable")
        finally:
            os.unlink(tmp)
    print("\n%s  (%d failures)" % ("SELFTEST PASSED" if not fails else "SELFTEST FAILED", len(fails)))
    return 0 if not fails else 1


# ============================================================================================
# CLI
# ============================================================================================

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ASLR / module-geometry capture for relative-IAT-recovery research.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See the module docstring for the recommended capture recipe.")
    ap.add_argument("--out", help="output directory (default aslr_capture_<host>_<bootid>)")
    ap.add_argument("--tag", default="", help="free-text label, e.g. 'win11-vm-A boot2'")
    ap.add_argument("--exports", action="store_true",
                    help="also build an apiscout-compatible reference DB from the on-disk DLLs")
    ap.add_argument("--argcounts", action="store_true",
                    help="add HEURISTIC x86 stdcall arg counts (implies more parsing time)")
    ap.add_argument("--pretty", action="store_true", help="indent the (large) export DB JSON")
    ap.add_argument("--no-zip", action="store_true")
    ap.add_argument("--no-powershell", action="store_true",
                    help="skip Get-ProcessMitigation / AV queries")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("survey", help="OS info + module geometry of every accessible process")
    s.set_defaults(fn=cmd_survey)

    s = sub.add_parser("dump", help="module list + Malpedia-style image dump of one pid")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--which", choices=["main", "nonsystem", "all"], default="main",
                   help="which modules to dump (default: the process's own image)")
    s.set_defaults(fn=cmd_dump)

    s = sub.add_parser("run", help="launch an exe, wait, then dump it (benign validation targets)")
    s.add_argument("--exe", required=True)
    s.add_argument("--args", nargs=argparse.REMAINDER)
    s.add_argument("--wait", type=float, default=3.0)
    s.add_argument("--which", choices=["main", "nonsystem", "all"], default="main")
    s.add_argument("--detached", action="store_true")
    s.add_argument("--kill", action="store_true", help="terminate the target after dumping")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("inspect", help="offline: parse one PE and show what would be recorded")
    s.add_argument("file")
    s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("selftest", help="validate the PE parser and DB writer (any OS)")
    s.set_defaults(fn=cmd_selftest)

    args = ap.parse_args(argv)
    if args.cmd in ("survey", "dump", "run") and not IS_WIN:
        ap.error("'%s' requires Windows. 'selftest' and 'inspect' run anywhere." % args.cmd)
    rc = args.fn(args)
    return rc if isinstance(rc, int) else 0


if __name__ == "__main__":
    sys.exit(main())
