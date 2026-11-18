########################################################################
# Copyright (c) 2026
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

"""Where the DLLs of an API DB are really loaded in a dump, so that one API DB per Windows build fits the dumps of
every boot (with ASLR, a DB only knows the load addresses of the boot it was built in).

There are two sources, tried in this order for each DLL:
 * module lists: lines of "<hex load address> <DLL path>", as `apiscout scan --modules` reads them and as the module
   list of a minidump gives them. The matching rules are those of DatabaseBuilder.applyLoadAddresses. The DB builder
   is a standalone script that does not import apiscout, so it keeps its own copy of read_load_addresses(),
   normalize_dll_path() and the matching; tests compare both.
 * DLL images in a flat dump: headers of PE files at page-aligned offsets with an export directory. The DLL is
   identified by the name in its export directory and verified by its export address table, as the API DB stores
   neither TimeDateStamp nor SizeOfImage of a DLL, but the RVA and ordinal of each export.
"""

import logging
import re
import struct
from dataclasses import dataclass

from .PeTools import PeTools

LOG = logging.getLogger(__name__)

SOURCE_MODULES = "modules file"
SOURCE_MINIDUMP = "minidump module list"
SOURCE_IMAGES = "DLL images in the dump"

PAGE_SIZE = 0x1000
# share of the exports of a DB entry that an image has to have at the same RVA
MIN_EXPORT_MATCH = 0.9
MAX_EXPORTS = 0x20000
MIN_EXPORTS_BY_EXPORTS_ONLY = 8


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


def match_load_addresses(dlls, load_addresses):
    """the load addresses of the DLLs of an API DB ({key: DLL entry}) found in a list of (normalized path, address),
    as {key: address}"""

    def all_paths(dll):
        return [normalize_dll_path(path) for path in [dll.get("filepath", "")]]

    has_wow64_dlls = any(path.startswith("syswow64/") for dll in dlls.values() for path in all_paths(dll))
    # the module list of a 32bit process names its DLLs by their redirected System32 path
    is_list_of_32bit_process = (
        has_wow64_dlls
        and bool(load_addresses)
        and all(
            load_address < 0x100000000 and not dll_path.startswith("syswow64/")
            for dll_path, load_address in load_addresses
        )
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
    for dll in dlls.values():
        for dll_path in all_paths(dll):
            if matching_address(dll, dll_path) is not None:
                bitness_of_path.setdefault(dll_path, set()).add(dll.get("bitness"))
    ambiguous_paths = {dll_path for dll_path, bitness in bitness_of_path.items() if len(bitness) > 1}
    for dll_path in sorted(ambiguous_paths):
        LOG.warning("Load address of %s fits DLLs of both bitnesses, it is not applied.", dll_path)
    placements = {}
    used_paths = set(ambiguous_paths)
    unmatched_dlls = {}
    for dll_key, dll in dlls.items():
        for dll_path in all_paths(dll):
            load_address = None if dll_path in ambiguous_paths else matching_address(dll, dll_path)
            if load_address is not None:
                placements[dll_key] = load_address
                used_paths.add(dll_path)
                break
        else:
            folder, _, filename = normalize_dll_path(dll.get("filepath", "")).rpartition("/")
            is_loadable = not (is_list_of_32bit_process and dll.get("bitness") == 64)
            if folder not in ("system32", "syswow64") and is_loadable:
                unmatched_dlls.setdefault(filename, []).append((dll_key, dll))
    # DLLs copied to a folder of another name are identified by their file name, as far as this is unique
    unused_addresses = {}
    for dll_path, load_address in known_addresses.items():
        if dll_path not in used_paths:
            unused_addresses.setdefault(dll_path.rsplit("/", 1)[-1], set()).add(load_address)
    for filename, entries in unmatched_dlls.items():
        if len(unused_addresses.get(filename, ())) != 1:
            continue
        load_address = next(iter(unused_addresses[filename]))
        # an address above 4 GB can only belong to a 64bit DLL
        candidates = [entry for entry in entries if load_address < 0x100000000 or entry[1].get("bitness") != 32]
        if len(candidates) == 1:
            placements[candidates[0][0]] = load_address
    return placements


@dataclass(frozen=True)
class DumpImage:
    load_address: int
    name: str
    bitness: int
    # ordinal -> RVA of the export address table
    exports: dict


def find_dll_images(binary, base_address=0):
    """the DLL images in a flat dump: PE headers at page-aligned offsets that have an export directory, with the
    address they are loaded at. A PE file at offset 0 is the image the dump was taken of and is not looked at."""
    images = []
    for offset in range(PAGE_SIZE, len(binary) - 0x40, PAGE_SIZE):
        if binary[offset : offset + 2] == b"MZ":
            image = _readImage(binary, offset, base_address + offset)
            if image:
                images.append(image)
    return images


def _readImage(binary, offset, load_address):
    """the image whose header is at the offset in the dump, None if it is no PE file with an export directory or if
    the dump does not hold its export address table"""
    limit = len(binary) - offset
    pe_offset = struct.unpack_from("<I", binary, offset + 0x3C)[0]
    if not 0 < pe_offset <= PAGE_SIZE or pe_offset + 0x18 + 0x78 > limit:
        return None
    header = offset + pe_offset
    if binary[header : header + 4] != b"PE\x00\x00":
        return None
    machine, _, _, _, _, optional_header_size = struct.unpack_from("<HHIIIH", binary, header + 4)
    bitness = PeTools.BITNESS_MAP.get(machine)
    magic = struct.unpack_from("<H", binary, header + 0x18)[0]
    directory_offset = {0x10B: 0x60, 0x20B: 0x70}.get(magic)
    if not bitness or directory_offset is None or optional_header_size < directory_offset + 8:
        return None
    if (bitness == 32) != (magic == 0x10B):
        return None
    export_rva = struct.unpack_from("<I", binary, header + 0x18 + directory_offset)[0]
    if not export_rva or export_rva + 40 > limit:
        return None
    _, _, _, _, name_rva, ordinal_base, num_functions, _, functions_rva, _, _ = struct.unpack_from(
        "<IIHHIIIIIII", binary, offset + export_rva
    )
    # the export address table has to be in the dump, as it is what the DLL is told apart by
    num_functions = min(num_functions, MAX_EXPORTS)
    if not name_rva or name_rva >= limit or not num_functions or functions_rva + 4 * num_functions > limit:
        return None
    name = bytes(binary[offset + name_rva : offset + name_rva + 256]).split(b"\x00", 1)[0].decode("latin-1")
    rvas = struct.unpack_from(f"<{num_functions}I", binary, offset + functions_rva)
    exports = {ordinal_base + index: rva for index, rva in enumerate(rvas) if rva}
    return DumpImage(load_address, name.lower(), bitness, exports)


def dll_file_name(dll_key, dll):
    """lower case file name of a DLL of an API DB, from its key ("32_10.0.26100.1882_midimap.dll_0x6b700000")"""
    name = re.sub(r"_0x[0-9a-fA-F]+$", "", "_".join(dll_key.split("_")[2:]))
    return (name or re.split(r"[\\/]", dll.get("filepath", ""))[-1]).lower()


def _exportScore(image, dll):
    """share of the exports of a DB entry that the image has at the same ordinal and RVA"""
    exports = dll.get("exports") or []
    if dll.get("bitness") != image.bitness or not exports:
        return 0
    return sum(image.exports.get(export["ordinal"]) == export["address"] for export in exports) / len(exports)


def match_images(dlls, images):
    """the load addresses of the DLLs of an API DB ({key: DLL entry}) found among the images of a dump, as
    {key: address}. An image is the DLL of the DB that has its file name and bitness, and at least 90% of its
    exports at the same RVAs and ordinals. The name in the export directory is not always the file name (the export
    directory of kernel.appcore.dll names appcore.dll): an image with an unknown name is the DLL of the DB that is
    alone in having its exports, if there are at least 8."""
    placements = {}
    by_name = {}
    for dll_key, dll in dlls.items():
        by_name.setdefault(dll_file_name(dll_key, dll), []).append((dll_key, dll))
    for image in sorted(images, key=lambda image: image.load_address):
        candidates = by_name.get(image.name)
        if candidates is None and len(image.exports) >= MIN_EXPORTS_BY_EXPORTS_ONLY:
            candidates = [
                (dll_key, dll)
                for dll_key, dll in dlls.items()
                if len(dll.get("exports") or []) >= MIN_EXPORTS_BY_EXPORTS_ONLY
            ]
        best_score, best_keys = 0, []
        for dll_key, dll in candidates or ():
            score = _exportScore(image, dll)
            if score < MIN_EXPORT_MATCH:
                continue
            if score > best_score:
                best_score, best_keys = score, [dll_key]
            elif score == best_score:
                best_keys.append(dll_key)
        if image.name not in by_name and len(best_keys) != 1:
            continue
        for dll_key in best_keys:
            if dll_key in placements:
                LOG.warning("%s is loaded more than once in the dump, using 0x%x.", image.name, placements[dll_key])
            else:
                placements[dll_key] = image.load_address
    return placements


class DllPlacer:
    """Places the DLLs of API DBs at the load addresses a dump tells: pass it to ApiScout.loadDbFile(). Each source
    is asked in turn for the DLLs the earlier ones did not know, `placed` lists all placements."""

    def __init__(self, ignore_aslr_offsets=False):
        # (source, [(normalized path, address)])
        self.module_lists = []
        # with ASLR offsets, a DB has the load addresses of the boot it was built in, see __call__
        self.ignore_aslr_offsets = ignore_aslr_offsets
        self.images = []
        self.placed = []
        self.summaries = []

    def addModuleList(self, source, load_addresses):
        self.module_lists.append((source, load_addresses))

    def addImages(self, images):
        self.images.extend(images)

    def isEmpty(self):
        return not (self.module_lists or self.images)

    def __call__(self, api_db, db_path=""):
        dlls = api_db.get("dlls", {})
        placements = {}
        counts = {}
        matches = [(source, match_load_addresses(dlls, addresses)) for source, addresses in self.module_lists]
        if self.images:
            # an image in the dump only places a DLL whose load address the DB does not have: a DB built from a copy
            # of the DLLs or from the symbol server only has their file ImageBase. With the ASLR offsets of the boot
            # it was built in, the DB has it, and an image of the DLL in the dump may be a copy that the sample mapped
            # itself (of ntdll, to get around hooks), while the DLL it calls is loaded where the DB says.
            has_load_address = api_db.get("aslr_offsets", False) and not self.ignore_aslr_offsets
            found = match_images(dlls, self.images)
            kept = sorted(key for key in found if has_load_address and dlls[key].get("aslr_offset"))
            if kept:
                LOG.info(
                    "%s: the DB has the load addresses of %d DLLs that are also images in the dump, they stay where the "
                    "DB has them (--ignore-aslr places them at the images): %s",
                    db_path,
                    len(kept),
                    ", ".join(kept),
                )
            matches.append((SOURCE_IMAGES, {key: address for key, address in found.items() if key not in kept}))
        for source, found in matches:
            for dll_key, load_address in found.items():
                if dll_key not in placements:
                    placements[dll_key] = load_address
                    counts[source] = counts.get(source, 0) + 1
                    self.placed.append(
                        {"api_db": db_path, "dll": dll_key, "load_address": load_address, "source": source}
                    )
        self.summaries.append((db_path, api_db.get("os_name", ""), len(dlls), counts))
        return placements
