#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout
#
#  apiscout is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import argparse
import ctypes
import json
import logging
import os
import platform
import sys
from operator import attrgetter

import config
import pefile
from ThreadedCommand import ThreadedCommand

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")


def is_windows():
    return platform.system() == "Windows"


def get_system_info():
    platform_info = platform.uname()
    version_info = sys.getwindowsversion()
    os_name = f"{platform_info.system} {platform_info.release} {version_info.service_pack} ({platform_info.machine})"
    return os_name, platform_info.version


def normalize_dll_path(path):
    """DLL file name with its folder in lower case (system32/kernel32.dll), which identifies a DLL regardless of where a copy of the system is mounted"""
    return "/".join(path.strip().lower().replace("\\", "/").split("/")[-2:])


def read_load_addresses(filepath):
    """read lines of "<load address> <path of DLL>", as taken from the module list of a process on the target system"""
    load_addresses = []
    with open(filepath) as f_in:
        for line in f_in:
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
    for dll_name, offset in zip(check_dlls, offsets, strict=False):
        LOG.debug("Memory vs. File ImageBase offset (%s): 0x%x", dll_name, offset)
        is_aslr |= offset != 0
    return is_aslr


class DatabaseBuilder:
    def _extractPeExports(self, filepath):
        try:
            pe = pefile.PE(filepath)
            for warning in pe.get_warnings():
                if "export" in warning.lower():
                    LOG.warning("pefile warning for %s: %s", filepath, warning)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                dll_entry = {}
                dll_entry["base_address"] = pe.OPTIONAL_HEADER.ImageBase
                dll_entry["bitness"] = 32 if pe.FILE_HEADER.Machine == 0x14C else 64
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

    def _isInFilter(self, target_dll, filter_dlls):
        return any(target_dll.casefold() == check_dll.casefold() for check_dll in filter_dlls)

    def extractRecursively(self, paths, filter_dlls=False, os_name=None, os_version=None):
        api_count = 0
        pe_count = 0
        duplicate_count = 0
        skipped_count = 0
        num_hit_dlls = 0
        api_db = {"dlls": {}}
        if paths is None:
            paths = config.DEFAULT_FOLDERS
        for base in paths:
            if not os.path.isdir(base):
                LOG.warning("%s is not a directory, skipping...", base)
                continue
            for root, _, files in os.walk(base):
                for fn in files:
                    if filter_dlls and not self._isInFilter(fn, config.DLL_FILTER):
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
                        if dll_key not in api_db["dlls"]:
                            api_db["dlls"][dll_key] = dll_summary
                            num_hit_dlls += 1
                            api_count += len(dll_summary["exports"])
                            LOG.info("APIs: %d", len(dll_summary["exports"]))
                        else:
                            duplicate_count += 1
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
            for dll_key in api_db["dlls"]:
                dll = api_db["dlls"][dll_key]
                if dll["bitness"] in [32, 64]:
                    offset = self.getAslrOffsetForDll(dll)
                    dll["aslr_offset"] = offset
                    if offset:
                        num_offsets[dll["bitness"]] += 1
            LOG.info("Found %d 32bit and %d 64bit ASLR offsets.", num_offsets[32], num_offsets[64])
            api_db["aslr_offsets"] = True
        return api_db

    def applyLoadAddresses(self, api_db, load_addresses):
        """derive ASLR offsets from known load addresses of the DLLs, given as (normalized path, address)"""
        num_offsets = 0
        known_addresses = dict(load_addresses)
        for dll in api_db["dlls"].values():
            load_address = known_addresses.get(normalize_dll_path(dll["filepath"]))
            if load_address is not None:
                dll["aslr_offset"] = dll["base_address"] - load_address
                num_offsets += 1
        LOG.info("Applied load addresses to %d of %d DLLs.", num_offsets, len(api_db["dlls"]))
        api_db["aslr_offsets"] = num_offsets > 0
        return api_db

    def getAslrOffsetForDll(self, dll_entry):
        this_file = str(os.path.abspath(__file__))
        basechecker = "DllBaseChecker{}.exe".format(dll_entry["bitness"])
        basechecker_path = os.path.abspath(os.sep.join([this_file, "..", "DllBaseChecker", basechecker]))
        cmds = [basechecker_path, dll_entry["filepath"]]
        threaded_basecheck = ThreadedCommand(cmds)
        result = threaded_basecheck.run(10)
        load_address = 0
        aslr_offset = 0
        if result["std_out"] and result["std_out"].startswith(b"DLL loaded at: 0x"):
            load_address = int(result["std_out"][15:], 16)
            if load_address:
                aslr_offset = dll_entry["base_address"] - load_address
            else:
                LOG.warning("Could not get a load address for %s, ASLR offset left as 0.", dll_entry["filepath"])
        return aslr_offset

    def persistApiDb(self, api_db, filepath=None):
        if filepath is None:
            filtered = "_filtered" if api_db["filtered"] else ""
            filepath = "." + os.sep + ".".join(api_db["os_version"].split(".")[:2]) + filtered + ".json"
        if not filepath.endswith(".json"):
            filepath += ".json"
        with open(filepath, "w") as f_out:
            f_out.write(json.dumps(api_db, indent=1, sort_keys=True))


def main():
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
        help='File with lines of "<hex load address> <DLL path>" (e.g. the module list of a process), used to derive the ASLR offsets instead of loading the DLLs.',
    )

    args = parser.parse_args()
    builder = DatabaseBuilder()
    offline = bool(args.os_name and args.os_version)
    if not is_windows() and not offline and not args.aslr_check:
        parser.error(
            "on systems other than Windows, --os_name and --os_version of the system the DLLs were taken from are required."
        )
    if args.aslr_check:
        print(f"OS has ASLR offsets: {check_aslr()}")
    elif args.auto or args.paths:
        paths = None if args.auto else args.paths
        filter_dlls = True if args.auto else args.filter_dlls
        api_db = builder.extractRecursively(paths, filter_dlls, args.os_name, args.os_version)
        if args.load_addresses:
            api_db = builder.applyLoadAddresses(api_db, read_load_addresses(args.load_addresses))
        elif not args.ignore_aslr and not offline:
            api_db = builder.extractAslrOffsets(api_db)
        builder.persistApiDb(api_db, args.output_file)
    else:
        parser.print_help()


if __name__ == "__main__":
    sys.exit(main())
