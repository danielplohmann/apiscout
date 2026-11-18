"""Shared input and pointer recovery for scan and collect."""

import functools
import re

from .LoadAddresses import (
    SOURCE_MINIDUMP,
    find_dll_images,
    normalize_dll_path,
    placed_image_ranges,
    read_from_regions,
)


def infer_base_address(path, explicit=None, minidump=None):
    if explicit is not None:
        return explicit
    if minidump:
        return 0
    match = re.search(r"0x([0-9a-fA-F]{8,16})(?:\.(?i:bin|dmp|dump|raw|mem))?$", path)
    return int(match[1], 16) if match else 0


def configure_placement(placer, binary, base_address, minidump):
    if minidump is None:
        placer.addImages(find_dll_images(binary, base_address))
        return [(base_address, binary)]
    regions = minidump.getRanges()
    modules = minidump.getModules()
    bitness = 32 if minidump.bitness == 32 else None
    if bitness is None and (
        any(start + len(data) > 1 << 32 for start, data in regions)
        or any(module.end_address > 1 << 32 for module in modules)
    ):
        bitness = 64
    placer.addModuleList(
        SOURCE_MINIDUMP,
        [(normalize_dll_path(module.name), module.base_address) for module in modules if module.name],
        bitness=bitness,
    )
    return regions


def recover_pointers(scout, binary, regions, minidump, placer):
    if minidump:
        scout.setBitness(32 if minidump.bitness == 32 else None)
        results = scout.crawlRegions(regions)
        images = [
            (module.base_address, module.end_address)
            for module in minidump.getModules()
            if scout.hasDll(module.name.replace("\\", "/").rsplit("/", 1)[-1])
        ]
    else:
        scout.setBitness(None)
        results = scout.crawl(binary)
        images = placed_image_ranges(placer, functools.partial(read_from_regions, regions))
        # Keep pointers to known DLLs even when their targets are in the same capture.
        start, end = scout.base_address, scout.base_address + len(binary)
        results = {
            name: [
                entry
                for entry in entries
                if not start <= entry[1] < end or any(lo <= entry[1] < hi for lo, hi in images)
            ]
            for name, entries in results.items()
        }
    retained = scout.filter(results, 0, 0, 0, own_image=False, exclude_ranges=images)
    excluded = sum(map(len, results.values())) - sum(map(len, retained.values()))
    return retained, images, excluded
