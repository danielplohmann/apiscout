#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import argparse
import collections
import ctypes
import itertools
import json
import logging
import mmap
import operator
import os
import platform
import re
import struct
import sys
from json.encoder import encode_basestring_ascii
from operator import attrgetter, itemgetter

import config
import pefile
from ThreadedCommand import ThreadedCommand

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")


# the bitness of the machine types of a PE file (IMAGE_FILE_MACHINE_*): x86 and the 32bit ARM types (ARM, ARMNT, ARMT)
# have 32bit pointers, AMD64 and ARM64 64bit pointers, as does anything else there is (IA-64, ARM64EC)
MACHINE_BITNESS = {0x14C: 32, 0x1C0: 32, 0x1C2: 32, 0x1C4: 32, 0x8664: 64, 0xAA64: 64}
# DllBaseChecker32.exe is an x86 and DllBaseChecker64.exe an AMD64 program. Neither loads a 32bit ARM DLL, while an
# ARM64 DLL (Windows 11 on ARM has ARM64X ones in System32) can be loaded by the AMD64 one under x64 emulation
ARM32_MACHINES = (0x1C0, 0x1C2, 0x1C4)


def get_bitness(machine):
    return MACHINE_BITNESS.get(machine, 64)


def is_windows():
    return platform.system() == "Windows"


def get_system_info():
    platform_info = platform.uname()
    version_info = sys.getwindowsversion()
    # Python reports the release of Windows Server as e.g. "2022Server"
    release = re.sub(r"(?<=\d)(?=Server)", " ", platform_info.release)
    parts = [platform_info.system, release, version_info.service_pack, f"({platform_info.machine})"]
    return " ".join(part for part in parts if part), platform_info.version


def normalize_dll_path(path):
    """DLL file name with its folder in lower case (system32/kernel32.dll), which identifies a DLL regardless of where a copy of the system is mounted"""
    parts = [part for part in path.strip().strip('"').lower().replace("\\", "/").split("/") if part]
    return "/".join(parts[-2:])


def read_load_addresses(filepath):
    """read lines of "<load address> <path of DLL>", as taken from the module list of a process on the target system"""
    load_addresses = []
    with open(filepath, "rb") as f_in:
        content = f_in.read()
    # module lists are often written by PowerShell, which uses UTF-16 with a byte order mark
    encoding = "utf-16" if content[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    for line in content.decode(encoding, errors="replace").splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or fields[0].startswith("#"):
            continue
        try:
            load_addresses.append((normalize_dll_path(fields[1]), int(fields[0], 16)))
        except ValueError:
            LOG.warning("Skipping line without a load address: %s", line.strip())
    return load_addresses


# courtesy of http://stackoverflow.com/a/16076661
def loword(dword):
    return dword & 0x0000FFFF


def hiword(dword):
    return dword >> 16


def get_product_version(pe):
    try:
        fixed_file_info = pe.VS_FIXEDFILEINFO
        # pefile >= 2018 keeps a list of VS_FIXEDFILEINFO structs, older versions a single one
        if isinstance(fixed_file_info, list):
            fixed_file_info = fixed_file_info[0]
        ms = fixed_file_info.ProductVersionMS
        ls = fixed_file_info.ProductVersionLS
        return f"{hiword(ms)}.{loword(ms)}.{hiword(ls)}.{loword(ls)}"
    except AttributeError:
        return "0.0.0.0"


def check_aslr():
    # first check for a potentially rebased user32.dll
    from ctypes import windll, wintypes

    check_dlls = ["user32.dll", "kernel32.dll", "ntdll.dll"]
    offsets = []
    is_aslr = False
    windll.kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    windll.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    windll.kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    windll.kernel32.GetModuleFileNameW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
    for dll_name in check_dlls:
        h_module_base = windll.kernel32.GetModuleHandleW(dll_name)
        # next get the module's file path
        module_path = ctypes.create_unicode_buffer(255)
        windll.kernel32.GetModuleFileNameW(h_module_base, module_path, 255)
        # then the ImageBase from python.exe file
        pe = pefile.PE(module_path.value)
        pe_header_base_addr = pe.OPTIONAL_HEADER.ImageBase
        offsets.append(pe_header_base_addr - h_module_base)
    for dll_name, offset in zip(check_dlls, offsets, strict=True):
        LOG.debug("Memory vs. File ImageBase offset (%s): 0x%x", dll_name, offset)
        is_aslr |= offset != 0
    return is_aslr


class NotPlainPe(Exception):
    """the file is not laid out like the PE images of Windows, pefile reads it"""


# a section: the RVAs it holds, its file offset minus its RVA, the end of its raw data in the file, and the address and
# size of the raw data as the section table lists them
Section = collections.namedtuple("Section", "start end delta limit address raw_size virtual_size")
# the characters pefile accepts in the name of an export, and the 0 that ends it
EXPORT_NAMES = re.compile(rb"[A-Za-z0-9_?@$()<>\0]*")
# pefile gives up on a resource directory with more entries, and on an export table with more symbols
MAX_DIRECTORY_ENTRIES = 4096
MAX_EXPORTS = 0x2000
# 64bit DLLs that Windows 7 loads below 4 GB (in every process); any other 64bit DLL there is the 32bit copy of a DLL
LOW_64BIT_DLLS = ("ntdll.dll", "kernel32.dll", "user32.dll")


class PlainPe:
    """
    The exports and the product version of a PE image, read from its bytes.

    pefile needs 150 ms or more for a DLL: it decodes every directory (imports, relocations, resources) into objects,
    while the DB takes the export table and one number out of the resources. This reads these two like pefile does,
    but only for images that are laid out like the linker writes them. For anything else it raises NotPlainPe, and the
    DLL is read by pefile, so that the result does not depend on which of them read it. The checks mirror what pefile
    does with a section, an RVA or a directory, and stop where pefile would go another way.
    """

    def __init__(self, data):
        self.data = data
        size = len(data)
        if size < 0x40 or data[:2] != b"MZ":
            raise NotPlainPe("no DOS header")
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew < 0x40 or e_lfanew + 24 > size or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise NotPlainPe("no NT header")
        (self.machine, num_sections, _, symbol_table, _, optional_size) = struct.unpack_from(
            "<HHIIIH", data, e_lfanew + 4
        )
        optional = e_lfanew + 24
        (magic,) = struct.unpack_from("<H", data, optional)
        if magic == 0x10B and optional_size == 224:
            (self.image_base,) = struct.unpack_from("<I", data, optional + 28)
            directories = optional + 96
        elif magic == 0x20B and optional_size == 240:
            (self.image_base,) = struct.unpack_from("<Q", data, optional + 24)
            directories = optional + 112
        else:
            raise NotPlainPe("optional header")
        section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
        (num_directories,) = struct.unpack_from("<I", data, directories - 4)
        sections = optional + optional_size
        if (
            symbol_table
            or num_directories != 16
            or file_alignment < 0x200
            or section_alignment < 0x1000
            or not 0 < num_sections <= 96
            or sections + 40 * num_sections > size
        ):
            raise NotPlainPe("header values")
        self.directories = struct.unpack_from("<32I", data, directories)
        raw_sections = []
        for index in range(num_sections):
            header = data[sections + 40 * index : sections + 40 * index + 40]
            if not any(header):
                raise NotPlainPe("empty section")
            (virtual_size, address, raw_size, raw_pointer, relocs_pointer, _, num_relocs) = struct.unpack_from(
                "<IIIIIIH", header, 8
            )
            if (
                raw_size + raw_pointer > size
                or raw_pointer % file_alignment
                or virtual_size > 0x10000000
                or (relocs_pointer and num_relocs)
            ):
                raise NotPlainPe("section values")
            raw_sections.append((address, virtual_size, raw_size, raw_pointer))
        # pefile sorts the sections by their address, and cuts each at the start of the next one
        raw_sections.sort(key=itemgetter(0))
        self.sections = []
        previous_end = 0
        for index, (address, virtual_size, raw_size, raw_pointer) in enumerate(raw_sections):
            start = address - address % section_alignment
            length = max(raw_size, virtual_size)
            if index + 1 < len(raw_sections):
                next_address = raw_sections[index + 1][0]
                if next_address > address and start + length > next_address:
                    length = next_address - start
            if start > 0x10000000 or start < previous_end:
                raise NotPlainPe("section layout")
            previous_end = start + length
            delta = raw_pointer - raw_pointer % 0x200 - start
            self.sections.append(
                Section(start, start + length, delta, raw_pointer + raw_size, address, raw_size, virtual_size)
            )

    def section(self, rva):
        for section in self.sections:
            if section.start <= rva < section.end:
                return section
        raise NotPlainPe("RVA outside of the sections")

    def read(self, rva, length):
        """the bytes of pefile's get_data: up to the end of the raw data of the section"""
        section = self.section(rva)
        offset = rva + section.delta
        return self.data[offset : min(offset + length, section.limit)]

    def read_exactly(self, rva, length):
        data = self.read(rva, length)
        if len(data) != length:
            raise NotPlainPe("data cut off")
        return data

    def exports(self):
        """(ordinal, address, name) of the exports in the order of pefile, None without an export table"""
        rva, size = self.directories[0:2]
        if not rva:
            return None
        header = self.read_exactly(rva, 40)
        (_, _, _, _, _, base, num_functions, num_names, functions_rva, names_rva, ordinals_rva) = struct.unpack(
            "<IIHHIIIIIII", header
        )
        if num_names > MAX_EXPORTS:
            raise NotPlainPe("many names")
        name_rvas = self.table(names_rva, "I", num_names)
        # pefile reads twice as many ordinals as there are, as far as the file goes
        name_ordinals = self.table(ordinals_rva, "H", num_names, 4 * num_names, False)
        addresses = self.table(functions_rva, "I", num_functions)
        # the names of the exports and the addresses they are for
        names = self.names(name_rvas) if num_names else []
        named_addresses = [addresses[ordinal] for ordinal in name_ordinals]
        forwarders_end = rva + size
        for address in named_addresses:
            if not address:
                # pefile leaves this one out together with its name
                raise NotPlainPe("name without address")
            if rva <= address < forwarders_end:
                # a forwarder: pefile skips it if it can not map it to the file
                self.section(address)
        exports = list(zip([base + ordinal for ordinal in name_ordinals], named_addresses, names, strict=True))
        # then the exports without a name
        ordinals_of_names = set(name_ordinals)
        exports += [
            (base + index, address, None)
            for index, address in enumerate(addresses)
            if address and index not in ordinals_of_names
        ]
        if len(exports) - len(names) > MAX_EXPORTS:
            raise NotPlainPe("many ordinals")
        if not exports and not any(header):
            return None
        return exports

    def names(self, name_rvas):
        """the names that the RVAs point to, if they have the characters pefile accepts"""
        first, last = min(name_rvas), max(name_rvas)
        section = self.section(first)
        if last >= section.end:
            raise NotPlainPe("names in several sections")
        # pefile reads a name up to 512 bytes or the end of the raw data of its section, whichever comes first
        offset = first + section.delta
        text = self.data[offset : min(last + section.delta + 0x200, section.limit)]
        starts = [rva - first for rva in name_rvas]
        ends = list(map(text.find, itertools.repeat(b"\0"), starts))
        if min(ends) < 0 or max(map(operator.sub, ends, starts)) >= 0x200:
            raise NotPlainPe("name without end")
        raw_names = b"\0".join(map(text.__getitem__, map(slice, starts, ends)))
        # pefile gives up on a name of other characters
        if EXPORT_NAMES.fullmatch(raw_names) is None:
            raise NotPlainPe("name with other characters")
        names = raw_names.decode("ascii").split("\0")
        # and on a name that is repeated for the same address
        if len(set(names)) != len(names):
            raise NotPlainPe("repeated names")
        return names

    def table(self, rva, kind, count, read_length=None, counted=True):
        """the entries of an array in the export table, which pefile reads as far as the file goes and its section"""
        width = struct.calcsize(kind)
        if not count:
            if rva >= len(self.data):
                self.section(rva)
            return ()
        section = self.section(rva)
        # and it counts the names and the functions up to the end of the raw data of the section
        if counted and section.address + section.raw_size - rva < 4 * count:
            raise NotPlainPe("table beyond its section")
        data = self.read(rva, read_length or width * count)[: width * count]
        if len(data) != width * count:
            raise NotPlainPe("table cut off")
        return struct.unpack(f"<{count}{kind}", data)

    def directory_entries(self, rva):
        """the number of entries of a resource directory, which pefile reads only if it is readable and not too large"""
        (named, by_id) = struct.unpack_from("<HH", self.read_exactly(rva, 16), 12)
        if named + by_id > MAX_DIRECTORY_ENTRIES:
            raise NotPlainPe("many resources")
        return named + by_id

    def product_version(self):
        """the product version of the first version resource, as get_product_version reads it"""
        root = self.directories[4]
        if not root:
            return "0.0.0.0"
        previous_name = None
        for index in range(self.directory_entries(root)):
            name, offset = struct.unpack("<II", self.read_exactly(root + 16 + 8 * index, 8))
            if name & 0x80000000:
                # pefile stops at a name that begins inside of the one before
                name_rva = root + (name & 0x7FFFFFFF)
                (length,) = struct.unpack("<H", self.read_exactly(name_rva, 2))
                if previous_name and previous_name[0] < name_rva <= previous_name[1]:
                    raise NotPlainPe("overlapping names")
                previous_name = (name_rva, name_rva + length)
            entry_rva = root + (offset & 0x7FFFFFFF)
            if offset & 0x80000000:
                if entry_rva == root:
                    raise NotPlainPe("directory loop")
                self.directory_entries(entry_rva)
                if name & 0xFFFF == 16:
                    return self.version_in_directory(root, entry_rva)
            elif name & 0xFFFF == 16:
                raise NotPlainPe("version without a directory")
            else:
                self.read_exactly(entry_rva, 16)
        return "0.0.0.0"

    def version_in_directory(self, root, type_directory):
        """the product version of the first language of the first version resource"""
        if not self.directory_entries(type_directory):
            raise NotPlainPe("no version")
        _, offset = struct.unpack("<II", self.read_exactly(type_directory + 16, 8))
        language_directory = root + (offset & 0x7FFFFFFF)
        if not offset & 0x80000000 or language_directory in (root, type_directory):
            raise NotPlainPe("version without languages")
        if not self.directory_entries(language_directory):
            raise NotPlainPe("no language")
        _, offset = struct.unpack("<II", self.read_exactly(language_directory + 16, 8))
        if offset & 0x80000000:
            raise NotPlainPe("language with a directory")
        info_rva, info_size = struct.unpack("<II", self.read_exactly(root + (offset & 0x7FFFFFFF), 16)[:8])
        start = info_rva + self.section(info_rva).delta
        info = self.data[start : start + info_size]
        # the version info starts with the key VS_VERSION_INFO, which pefile reads up to the end of the section
        key = self.section(info_rva + 6)
        if (
            len(info) < 6
            or key.address + max(key.raw_size, key.virtual_size) - (info_rva + 6) < 32
            or self.read(info_rva + 6, 32) != "VS_VERSION_INFO\0".encode("utf-16-le")
        ):
            raise NotPlainPe("version info")
        fixed = (6 + 2 * 16 + info_rva + 3 & 0xFFFFFFFC) - (info_rva & 0xFFFFFFFC)
        if len(info) - fixed < 52:
            raise NotPlainPe("version info cut off")
        ms, ls = struct.unpack_from("<II", info, fixed + 16)
        return f"{hiword(ms)}.{loword(ms)}.{hiword(ls)}.{loword(ls)}"


EXPORT_KEYS = {"address", "name", "ordinal"}


def dump_exports(exports, indent):
    """the list of exports as json.dumps(indent=1, sort_keys=True) writes it, None for anything else than ints and a str"""
    if not (
        all(type(export) is dict and export.keys() == EXPORT_KEYS for export in exports)
        and {type(export["address"]) for export in exports} == {int}
        and {type(export["ordinal"]) for export in exports} == {int}
        and {type(export["name"]) for export in exports} == {str}
    ):
        return None
    pad = " " * indent
    item = f'{{\n{pad} "address": %d,\n{pad} "name": %s,\n{pad} "ordinal": %d\n{pad}}}'
    items = (
        item % (export["address"], encode_basestring_ascii(export["name"]), export["ordinal"]) for export in exports
    )
    return f"[\n{pad}" + f",\n{pad}".join(items) + f"\n{pad[1:]}]"


def dump_json(obj, level=0):
    """json.dumps(obj, indent=1, sort_keys=True), but the lists of exports (100000 and more) are written faster"""
    kind = type(obj)
    if kind is str:
        return encode_basestring_ascii(obj)
    if kind is int:
        return int.__repr__(obj)
    if kind is bool or obj is None or kind is float:
        return json.dumps(obj)
    pad = " " * (level + 1)
    if kind is dict and all(type(key) is str for key in obj):
        items = []
        for key in sorted(obj):
            value = obj[key]
            text = dump_exports(value, level + 2) if key == "exports" and type(value) is list and value else None
            if text is None:
                text = dump_json(value, level + 1)
            items.append(f"{pad}{encode_basestring_ascii(key)}: {text}")
        return "{\n" + ",\n".join(items) + "\n" + " " * level + "}" if items else "{}"
    if kind in (list, tuple):
        values = [dump_json(value, level + 1) for value in obj]
        return "[\n" + ",\n".join(pad + value for value in values) + "\n" + " " * level + "]" if values else "[]"
    raise TypeError(kind)


def dumps_api_db(api_db):
    """the text of the DB file: json.dumps(api_db, indent=1, sort_keys=True)"""
    try:
        return dump_json(api_db)
    except TypeError:
        # something that is not written here, the json module knows what to do with it
        return json.dumps(api_db, indent=1, sort_keys=True)


class DatabaseBuilder:
    def __init__(self):
        self._duplicate_paths = {}
        # the machine type of each DLL that was read, by path: the DB does not store it
        self._machines = {}

    def _extractPlainPe(self, filepath):
        """the summary of a DLL by PlainPe, None if it has no exports, an exception if pefile has to read it"""
        with open(filepath, "rb") as f_in:
            data = mmap.mmap(f_in.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            pe = PlainPe(data)
            exports = pe.exports()
            if exports is None:
                return None
            version = pe.product_version()
            self._machines[filepath] = pe.machine
            exports.sort(key=itemgetter(1))
            return {
                "base_address": pe.image_base,
                "bitness": get_bitness(pe.machine),
                "version": version,
                "filepath": filepath,
                "aslr_offset": 0,
                "exports": [
                    {"address": address, "name": "None" if name is None else name, "ordinal": ordinal}
                    for ordinal, address, name in exports
                ],
            }
        finally:
            data.close()

    def _extractPeExports(self, filepath):
        try:
            return self._extractPlainPe(filepath)
        except Exception:
            # a file of another layout, a damaged one, or one that can not be read: pefile decides
            pass
        try:
            # only the export directory and the resources (of the product version) are used
            pe = pefile.PE(filepath, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                ]
            )
            for warning in pe.get_warnings():
                if "export" in warning.lower():
                    LOG.warning("pefile warning for %s: %s", filepath, warning)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                self._machines[filepath] = pe.FILE_HEADER.Machine
                dll_entry = {}
                dll_entry["base_address"] = pe.OPTIONAL_HEADER.ImageBase
                dll_entry["bitness"] = get_bitness(pe.FILE_HEADER.Machine)
                dll_entry["version"] = get_product_version(pe)
                dll_entry["filepath"] = filepath
                dll_entry["aslr_offset"] = 0
                dll_entry["exports"] = []
                for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=attrgetter("address")):
                    export_info = {}
                    export_info["address"] = exp.address
                    if exp.name is None:
                        export_info["name"] = "None"
                    else:
                        export_info["name"] = exp.name.decode("utf-8", errors="replace")
                    export_info["ordinal"] = exp.ordinal
                    dll_entry["exports"].append(export_info)

                return dll_entry
        except Exception as exc:
            LOG.warning("Could not extract exports of %s: %s", filepath, exc)
            return None

    def _buildDllKey(self, dll_info):
        filename = os.path.basename(dll_info["filepath"])
        return "{}_{}_{}_0x{:x}".format(dll_info["bitness"], dll_info["version"], filename, dll_info["base_address"])

    def extractRecursively(self, paths, filter_dlls=False, os_name=None, os_version=None, only_files=None):
        """the API DB of the DLLs in paths; with only_files, a collection of paths, only those files are used (the paths are compared
        as absolute paths in the normal case of the platform: Windows file names are not case sensitive)"""
        api_count = 0
        pe_count = 0
        duplicate_count = 0
        skipped_count = 0
        num_hit_dlls = 0
        api_db = {"dlls": {}}
        # Windows file names are not case sensitive, copies of a DLL can differ in the case of their name
        known_keys = {}
        if paths is None:
            paths = config.DEFAULT_FOLDERS
        # the file names of the filter in lower case, to look a name up instead of comparing it with all of them
        filter_names = {name.casefold() for name in config.DLL_FILTER}
        if only_files is not None:
            only_files = {os.path.normcase(os.path.abspath(path)) for path in only_files}
        for base in paths:
            if not os.path.isdir(base):
                LOG.warning("%s is not a directory, skipping...", base)
                continue
            for root, _, files in os.walk(base):
                for fn in files:
                    if (
                        only_files is not None
                        and os.path.normcase(os.path.abspath(os.path.join(root, fn))) not in only_files
                    ):
                        skipped_count += 1
                        continue
                    if filter_dlls and fn.casefold() not in filter_names:
                        skipped_count += 1
                        continue
                    elif not (
                        fn.lower().endswith(".dll") or fn.lower().endswith(".drv") or fn.lower().endswith(".mui")
                    ):
                        continue
                    pe_count += 1
                    LOG.info("processing: %s %s", root, fn)
                    dll_summary = self._extractPeExports(root + os.sep + fn)
                    if dll_summary is not None:
                        dll_key = self._buildDllKey(dll_summary)
                        dll_key = known_keys.setdefault(dll_key.lower(), dll_key)
                        if dll_key not in api_db["dlls"]:
                            api_db["dlls"][dll_key] = dll_summary
                            num_hit_dlls += 1
                            api_count += len(dll_summary["exports"])
                            LOG.info("APIs: %d", len(dll_summary["exports"]))
                        else:
                            duplicate_count += 1
                            # the same DLL in another folder, which may be the one that is known by its load address
                            self._duplicate_paths.setdefault(dll_key, []).append(dll_summary["filepath"])
        LOG.info("PEs examined: %d (%d duplicates, %d skipped)", pe_count, duplicate_count, skipped_count)
        LOG.info("Successfully evaluated %d DLLs with %d APIs", num_hit_dlls, api_count)
        if os_name and os_version:
            api_db["os_name"], api_db["os_version"] = os_name, os_version
        else:
            api_db["os_name"], api_db["os_version"] = get_system_info()
        api_db["aslr_offsets"] = False
        api_db["num_dlls"] = num_hit_dlls
        api_db["num_apis"] = api_count
        api_db["crawled_paths"] = paths
        api_db["filtered"] = filter_dlls
        return api_db

    def extractAslrOffsets(self, api_db):
        LOG.info("Now check for ASLR...")
        if check_aslr():
            LOG.info(" looks like ASLR is active, let's extract some offsets!")
            num_offsets = {32: 0, 64: 0}
            arm32_dlls = 0
            for dll_key in api_db["dlls"]:
                dll = api_db["dlls"][dll_key]
                if self._machines.get(dll["filepath"]) in ARM32_MACHINES:
                    arm32_dlls += 1
                    continue
                offset = self.getAslrOffsetForDll(dll)
                dll["aslr_offset"] = offset
                if offset:
                    num_offsets[dll["bitness"]] += 1
            if arm32_dlls:
                LOG.warning(
                    "DllBaseChecker can not load 32bit ARM DLLs, the ASLR offset of %d of them is left as 0, "
                    "--load_addresses can take it from a module list.",
                    arm32_dlls,
                )
            LOG.info("Found %d 32bit and %d 64bit ASLR offsets.", num_offsets[32], num_offsets[64])
            api_db["aslr_offsets"] = True
        return api_db

    def applyLoadAddresses(self, api_db, load_addresses):
        """derive ASLR offsets from known load addresses of the DLLs, given as (normalized path, address)"""

        def all_paths(dll_key, dll):
            return [normalize_dll_path(path) for path in [dll["filepath"]] + self._duplicate_paths.get(dll_key, [])]

        has_wow64_dlls = any(
            path.startswith("syswow64/") for dll_key, dll in api_db["dlls"].items() for path in all_paths(dll_key, dll)
        )
        # the module list of a 32bit process names its DLLs by their redirected System32 path
        is_list_of_32bit_process = has_wow64_dlls and all(
            load_address < 0x100000000 and not dll_path.startswith("syswow64/")
            for dll_path, load_address in load_addresses
        )
        if is_list_of_32bit_process:
            LOG.warning(
                "All load addresses are below 4 GB: the list is treated as the one of a 32bit process, "
                "its System32 paths are applied to the SysWOW64 DLLs."
            )
        known_addresses = {}
        for dll_path, load_address in load_addresses:
            if is_list_of_32bit_process and dll_path.startswith("system32/"):
                dll_path = "syswow64/" + dll_path.split("/", 1)[1]
            if known_addresses.get(dll_path, load_address) != load_address:
                LOG.warning("Several load addresses given for %s, using 0x%x.", dll_path, load_address)
            known_addresses[dll_path] = load_address

        def matching_address(dll, dll_path):
            if is_list_of_32bit_process and dll.get("bitness") == 64:
                return None
            if has_wow64_dlls and dll_path.startswith({32: "system32/", 64: "syswow64/"}.get(dll.get("bitness"), "-")):
                # a copy of the DLL for the other bitness
                return None
            load_address = known_addresses.get(dll_path)
            if load_address is not None and load_address >= 0x100000000 and dll.get("bitness") == 32:
                # the address of a 64bit DLL in a folder of the same name
                return None
            return load_address

        # a path that fits a 32bit and a 64bit DLL does not tell which of them was loaded there
        bitness_of_path = {}
        for dll_key, dll in api_db["dlls"].items():
            for dll_path in all_paths(dll_key, dll):
                if matching_address(dll, dll_path) is not None:
                    bitness_of_path.setdefault(dll_path, set()).add(dll.get("bitness"))
        ambiguous_paths = {dll_path for dll_path, bitness in bitness_of_path.items() if len(bitness) > 1}
        for dll_path in sorted(ambiguous_paths):
            LOG.warning("Load address of %s fits DLLs of both bitnesses, it is not applied.", dll_path)
        num_offsets = 0
        applied = []
        used_paths = set(ambiguous_paths)
        unmatched_dlls = {}
        for dll_key, dll in api_db["dlls"].items():
            for dll_path in all_paths(dll_key, dll):
                load_address = None if dll_path in ambiguous_paths else matching_address(dll, dll_path)
                if load_address is not None:
                    dll["aslr_offset"] = dll["base_address"] - load_address
                    num_offsets += 1
                    applied.append((dll, load_address))
                    used_paths.add(dll_path)
                    break
            else:
                folder, _, filename = normalize_dll_path(dll["filepath"]).rpartition("/")
                is_loadable = not (is_list_of_32bit_process and dll.get("bitness") == 64)
                if folder not in ("system32", "syswow64") and is_loadable:
                    unmatched_dlls.setdefault(filename, []).append(dll)
        # DLLs copied to a folder of another name are identified by their file name, as far as this is unique
        unused_addresses = {}
        for dll_path, load_address in known_addresses.items():
            if dll_path not in used_paths:
                unused_addresses.setdefault(dll_path.rsplit("/", 1)[-1], set()).add(load_address)
        for filename, dlls in unmatched_dlls.items():
            if len(unused_addresses.get(filename, ())) != 1:
                continue
            load_address = next(iter(unused_addresses[filename]))
            # an address above 4 GB can only belong to a 64bit DLL
            candidates = [dll for dll in dlls if load_address < 0x100000000 or dll.get("bitness") != 32]
            if len(candidates) == 1:
                candidates[0]["aslr_offset"] = candidates[0]["base_address"] - load_address
                num_offsets += 1
                applied.append((candidates[0], load_address))
        if not has_wow64_dlls:
            self._warnAboutLow64bitDlls(applied)
        log = LOG.warning if load_addresses and not num_offsets else LOG.info
        log("Applied load addresses to %d of %d DLLs.", num_offsets, len(api_db["dlls"]))
        api_db["aslr_offsets"] = num_offsets > 0
        return api_db

    @staticmethod
    def _warnAboutLow64bitDlls(applied):
        """The module list of a 32bit process names the 32bit copies in SysWOW64 by their System32 path. Without a
        SysWOW64 folder in the DB, such a list fits the 64bit DLLs of System32 by name, and every offset of them is
        wrong. An address below 4 GB is no proof, as Windows 7 loads 64bit ntdll, kernel32 and user32 there, so this
        only warns. The same as in apiscout/LoadAddresses.py."""
        low = sorted(
            (normalize_dll_path(dll["filepath"]).rsplit("/", 1)[-1], load_address)
            for dll, load_address in applied
            if dll.get("bitness") == 64 and load_address < 0x100000000
        )
        low = [(name, load_address) for name, load_address in low if name not in LOW_64BIT_DLLS]
        if low:
            LOG.warning(
                "%d 64bit DLLs got a load address below 4 GB (%s): the DB has no SysWOW64 folder, so if the list is "
                "the one of a 32bit process, these offsets are those of the 32bit copies and wrong.",
                len(low),
                ", ".join(f"{name} 0x{address:x}" for name, address in low[:3]) + (", ..." if len(low) > 3 else ""),
            )

    def getAslrOffsetForDll(self, dll_entry):
        this_file = str(os.path.abspath(__file__))
        basechecker = "DllBaseChecker{}.exe".format(dll_entry["bitness"])
        basechecker_path = os.path.abspath(os.sep.join([this_file, "..", "DllBaseChecker", basechecker]))
        cmds = [basechecker_path, dll_entry["filepath"]]
        threaded_basecheck = ThreadedCommand(cmds)
        result = threaded_basecheck.run(10)
        load_address = 0
        aslr_offset = 0
        # a DLL can write to the output as well when it is loaded
        match = re.search(rb"^DLL loaded at: 0x([0-9a-fA-F]+)", result["std_out"] or b"", re.MULTILINE)
        if match:
            load_address = int(match.group(1), 16)
            if load_address:
                aslr_offset = dll_entry["base_address"] - load_address
            else:
                LOG.warning("Could not get a load address for %s, ASLR offset left as 0.", dll_entry["filepath"])
        else:
            LOG.warning(
                "DllBaseChecker failed for %s (%s), ASLR offset left as 0.",
                dll_entry["filepath"],
                result["std_err"] or result["std_out"] or "no output",
            )
        return aslr_offset

    def persistApiDb(self, api_db, filepath=None):
        if filepath is None:
            filtered = "_filtered" if api_db["filtered"] else ""
            filepath = "." + os.sep + ".".join(api_db["os_version"].split(".")[:2]) + filtered + ".json"
        if not filepath.endswith(".json"):
            filepath += ".json"
        # the same bytes on every OS, as the DBs are shared and checked against SHA256SUMS
        with open(filepath, "w", encoding="utf-8", newline="\n") as f_out:
            f_out.write(dumps_api_db(api_db))


def check_python_version(script):
    """stops at once on a Python older than 3.10, instead of with a TypeError (zip(strict=)) after the crawl"""
    # ruff knows requires-python and takes this for dead code, but this runs with any interpreter that starts it
    if sys.version_info < (3, 10):  # noqa: UP036
        sys.exit(
            f"{script} needs Python 3.10 or newer, this is Python {sys.version_info[0]}.{sys.version_info[1]}. "
            "For a system that has none, build the DB from a copy of its DLLs on another system "
            "(--os_name, --os_version, --load_addresses)."
        )


def main():
    check_python_version("DatabaseBuilder.py")
    parser = argparse.ArgumentParser(description="Build a database to be used by apiscout.")
    parser.add_argument(
        "--filter", dest="filter_dlls", action="store_true", help="(optional) filter DLLs by name (see config.py)"
    )
    parser.add_argument(
        "--auto",
        dest="auto",
        action="store_true",
        help="Use default configuration (filtered DLLs from preconfigured paths (see config.py) and extract ASLR offsets.",
    )
    parser.add_argument(
        "--paths",
        metavar="P",
        type=str,
        nargs="+",
        default=None,
        help="the paths to recursively crawl for DLLs (None -> use default, see config.py).",
    )
    parser.add_argument(
        "--outfile",
        dest="output_file",
        type=str,
        default=None,
        help="(optional) filepath where to put the resulting API DB file.",
    )
    parser.add_argument(
        "--ignore_aslr", dest="ignore_aslr", action="store_true", help="Do not perform extraction of ASLR offsets."
    )
    parser.add_argument("--aslr_check", dest="aslr_check", action="store_true", help="Only show ASLR offset.")

    parser.add_argument(
        "--os_name",
        type=str,
        default=None,
        help="Name of the OS the DLLs belong to. Together with --os_version, this allows to build an API DB from a copy of the DLLs on any system (without ASLR offsets, unless --load_addresses is given).",
    )
    parser.add_argument(
        "--os_version", type=str, default=None, help="Version of the OS the DLLs belong to, e.g. 10.0.19045."
    )
    parser.add_argument(
        "--load_addresses",
        type=str,
        default=None,
        help='File with lines of "<hex load address> <DLL path>" (e.g. the module list of a process), used to derive the ASLR offsets instead of loading the DLLs. DLLs are matched by folder and file name (System32\\kernel32.dll), or by file name alone where it is unique.',
    )

    args = parser.parse_args()
    builder = DatabaseBuilder()
    if bool(args.os_name) != bool(args.os_version):
        parser.error("--os_name and --os_version have to be given together.")
    offline = bool(args.os_name and args.os_version)
    if not is_windows() and (not offline or args.aslr_check):
        parser.error(
            "on systems other than Windows, --os_name and --os_version of the system the DLLs were taken from are required, and --aslr_check is not available."
        )
    load_addresses = read_load_addresses(args.load_addresses) if args.load_addresses else None
    if args.auto or args.paths:
        output_folder = os.path.dirname(os.path.abspath(args.output_file)) if args.output_file else os.getcwd()
        if not os.access(output_folder, os.W_OK):
            parser.error(f"can not write to {output_folder}")
    if args.aslr_check:
        print(f"OS has ASLR offsets: {check_aslr()}")
    elif args.auto or args.paths:
        paths = None if args.auto else args.paths
        filter_dlls = True if args.auto else args.filter_dlls
        api_db = builder.extractRecursively(paths, filter_dlls, args.os_name, args.os_version)
        if not api_db["dlls"]:
            parser.error("no DLLs found in {}.".format(", ".join(api_db["crawled_paths"])))
        if load_addresses is not None:
            api_db = builder.applyLoadAddresses(api_db, load_addresses)
        elif not args.ignore_aslr and not offline:
            api_db = builder.extractAslrOffsets(api_db)
        builder.persistApiDb(api_db, args.output_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    sys.exit(main())
