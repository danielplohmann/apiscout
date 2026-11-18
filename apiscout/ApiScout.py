########################################################################
# Copyright (c) 2018
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# Steffen Enders <steffen<at>enders<dot>nrw>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import bisect
import itertools
import logging
import os
import re
import struct
from itertools import repeat
from operator import itemgetter

try:
    from . import numpy_search
except ImportError:  # pragma: no cover - numpy is a dependency, the plain loops are kept for environments without it
    numpy_search = None

from .ApiVector import ApiVector
from .ImportTableLoader import ImportTableLoader
from .PeTools import PeTools
from .utility import paused_garbage_collection, read_json

LOG = logging.getLogger(__name__)


class ApiScout:
    # share of exports overwriting the address of another DLL above which loading an API DB issues a warning, not
    # counting DLLs that both have the address of their own ASLR offset in the DB (see _loadDbFile)
    COLLISION_WARNING_RATIO = 0.01
    # DLL keys of API DBs end in the address they were loaded at: 32_6.1.7601.17514_kernel32.dll_0x76d10000
    DLL_ADDRESS_SUFFIX = re.compile(r"_0x[0-9a-fA-F]+$")

    # Confidence of a hit, 0 to 100: how likely it is a pointer to an API and not bytes that happen to equal an API
    # address (about 1 in 40,000 DWORDs does, so a megabyte of anything holds dozens). getConfidences() adds up the
    # evidence the scan already has. A hit found in the import table of the image is certain (100), otherwise:
    #   neighbours  0 / 30 / 50 / 60: no / one / two / three or more other APIs of the same width in its cluster, the
    #               hits that are at most CONFIDENCE_NEIGHBOUR_DISTANCE bytes apart (an IAT, a table of resolved APIs,
    #               a table with a stride), see CONFIDENCE_NEIGHBOURS
    #   references  +40: a call or jmp through it was found
    #   agreement   +10: another API DB resolves the location to the same API of the same DLL
    #   alignment   +10 for an offset aligned to the pointer size, tables are. Other hits count at most
    #               CONFIDENCE_UNALIGNED_MAX, they are chance hits nearly without exception.
    # The sum is cut at 100. Weights and thresholds were calibrated on Malpedia memory dumps, see the commit message.
    CONFIDENCE_NEIGHBOUR_DISTANCE = 16
    CONFIDENCE_NEIGHBOURS = (0, 30, 50, 60)
    CONFIDENCE_REFERENCES = 40
    CONFIDENCE_AGREEMENT = 10
    CONFIDENCE_ALIGNED = 10
    CONFIDENCE_UNALIGNED_MAX = 25

    def __init__(self, db_filepath=None):
        # {name of the API map: {address: (DLL, API, bitness)}}. A map is replaced, not edited in place: what a scan
        # searches for is cached by the identity and size of each map, which can not see an entry that was replaced.
        # Put a new map under the name to change one.
        self.api_maps = {}
        self._api_map_sources = {}
        # what loadDbFile() collected besides each map, valid for the map object in _loaded_maps, not for another one
        # that was put under the same name
        self._loaded_maps = {}
        self._other_bitness_maps = {}
        # (signature of the API maps, AddressSearch for them, the maps)
        self._address_search = None
        self._export_entries = {}
        self._dynamic_finder = None
        self.has_64bit = False
        self.base_address = 0
        self._binary_length = 0
        # Used to achieve coherent offset view in IdaScout
        self.load_offset = 0
        self.ignore_aslr_offsets = False
        # 32 restricts the search to 32bit pointers (dumps of 32bit systems), otherwise both sizes are searched
        self.bitness = None
        self._dll_file_names = set()
        self._import_table = None
        if db_filepath:
            self.loadDbFile(db_filepath)
        self._apivector = ApiVector()
        self.loadWinApi1024()

    def loadDbFile(self, db_filepath, place=None, api_db=None):
        """load an API DB. place(api_db) can return {DLL key: load address} to put DLLs at the addresses they are really
        loaded at (see LoadAddresses.DllPlacer), the other DLLs keep the addresses of the DB. A caller that has parsed
        the file already (FingerprintCrawler.readApiDb) passes its content as api_db, which is not read again."""
        with paused_garbage_collection():
            self._loadDbFile(db_filepath, place, api_db)

    def _loadDbFile(self, db_filepath, place, api_db):
        if api_db is None:
            if not os.path.isfile(db_filepath):
                LOG.error("Not a file: %s!", db_filepath)
                raise ValueError
            api_db = read_json(db_filepath)
        placements = place(api_db) if place else {}
        num_apis_loaded = 0
        num_collisions = 0
        num_placed_collisions = 0
        # DLLs at the address that the ASLR offset of the DB gives them. One that a module list of the scan places is
        # not one of them: it is where the dump has it, and an overlap with another DLL is a real one.
        placed_dlls = set()
        api_map = {}
        other_bitness_map = {}
        export_entries = []
        # one dict per DLL is built by C iterators over the lists of its exports, the Python loop runs per DLL
        for dll_entry in api_db["dlls"]:
            LOG.debug("  building address map for: %s", dll_entry)
            dll = api_db["dlls"][dll_entry]
            aslr_offset = 0 if self.ignore_aslr_offsets else dll.get("aslr_offset", 0)
            exports = dll["exports"]
            if not len(exports):
                LOG.debug("loaded %d exports", num_apis_loaded)
                continue
            num_apis_loaded += len(exports)
            dll_name = "_".join(dll_entry.split("_")[2:])
            self._dll_file_names.add(self.DLL_ADDRESS_SUFFIX.sub("", dll_name).lower())
            bitness = dll["bitness"]
            self.has_64bit |= bitness == 64
            load_offset = placements[dll_entry] if dll_entry in placements else dll["base_address"] - aslr_offset
            is_placed = bool(aslr_offset) and dll_entry not in placements
            if is_placed:
                placed_dlls.add(dll_name.lower())
            entries = list(zip(repeat(dll_name), self._getApiNames(exports), repeat(bitness), strict=False))
            addresses = [load_offset + export["address"] for export in exports]
            if not api_map.keys().isdisjoint(addresses):
                # an address in the map already is overwritten by this DLL, repeats inside the DLL are no collisions
                for virtual_address in dict.fromkeys(filter(api_map.__contains__, addresses)):
                    other = api_map[virtual_address]
                    if other[0].lower() != dll_name.lower():
                        if is_placed and other[0].lower() in placed_dlls:
                            num_placed_collisions += 1
                        else:
                            num_collisions += 1
                    if other[2] != bitness:
                        # a 32bit and a 64bit DLL can share an address, both stay resolvable for their pointer size
                        other_bitness_map[virtual_address] = other
            api_map.update(zip(addresses, entries, strict=True))
            # the map keeps one export per address, the names of all of them are needed to find APIs by name
            export_entries.extend(entries)
            LOG.debug("loaded %d exports", num_apis_loaded)
        LOG.debug(
            "loaded %d exports from %d DLLs (%s) with %d potential collisions.",
            num_apis_loaded,
            len(api_db["dlls"]),
            api_db["os_name"],
            num_collisions + num_placed_collisions,
        )
        if num_placed_collisions:
            # The DB builder loads every DLL in a process of its own to get its ASLR offset, and Windows hands out
            # the same free addresses to the DLLs of different processes: up to 23 DLLs of the example DBs share one
            # load address, which no process has them at together. The overlap is how such a DB is made, not damage.
            LOG.info(
                "API DB %s: %d of %d exports have the address of another DLL that has its own ASLR offset in the DB, "
                "a scan resolves them to one of these DLLs unless a module list places the DLLs.",
                db_filepath,
                num_placed_collisions,
                num_apis_loaded,
            )
        if num_apis_loaded and num_collisions > self.COLLISION_WARNING_RATIO * num_apis_loaded:
            hint = ""
            if self.ignore_aslr_offsets and api_db.get("aslr_offsets", False):
                hint = " The ASLR offsets of this DB were ignored, so DLLs sharing a file ImageBase overlap."
            LOG.warning(
                "API DB %s: %d of %d exports collide with exports of other DLLs, APIs at these addresses may be resolved to the wrong DLL.%s",
                db_filepath,
                num_collisions,
                num_apis_loaded,
                hint,
            )
        api_map_name = self._getApiMapName(api_db["os_name"], db_filepath)
        self.api_maps[api_map_name] = api_map
        self._loaded_maps[api_map_name] = api_map
        self._other_bitness_maps[api_map_name] = other_bitness_map
        self._export_entries[api_map_name] = export_entries
        self._dynamic_finder = None

    @staticmethod
    def _getApiNames(exports):
        """the names of exports, one that has none is called None<ordinal>"""
        names = list(map(str, map(itemgetter("name"), exports)))
        if "None" in names:
            names = [
                f"None<{export['ordinal']}>" if name == "None" else name
                for name, export in zip(names, exports, strict=True)
            ]
        return names

    def _getApiMapName(self, os_name, db_filepath):
        """API maps are named by the OS they were built on. Several DBs for the same OS (e.g. one per boot with ASLR) must not replace each other."""
        db_filepath = os.path.abspath(db_filepath)
        api_map_name = os_name
        if self._api_map_sources.get(api_map_name, db_filepath) != db_filepath:
            api_map_name = f"{os_name} ({os.path.basename(db_filepath)})"
            index = 2
            while self._api_map_sources.get(api_map_name, db_filepath) != db_filepath:
                api_map_name = f"{os_name} ({os.path.basename(db_filepath)}, {index})"
                index += 1
        self._api_map_sources[api_map_name] = db_filepath
        return api_map_name

    def loadWinApi1024(self, winapi1024_filepath=None):
        if winapi1024_filepath is None:
            this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
            winapi1024_filepath = this_dir + os.sep + "data" + os.sep + "winapi1024v1.txt"
        self._apivector = ApiVector(winapi1024_filepath)

    def _resolveApiByAddress(self, api_map_name, absolute_addr, bitness=None):
        api_entry = self.api_maps[api_map_name].get(absolute_addr, ("", "", ""))
        if bitness is not None and api_entry[2] != bitness and self._isLoadedMap(api_map_name):
            api_entry = self._other_bitness_maps.get(api_map_name, {}).get(absolute_addr, api_entry)
        return api_entry

    def _isLoadedMap(self, name):
        """whether the map under the name is the one that loadDbFile() built, with its other_bitness_map and entries"""
        return self.api_maps.get(name) is self._loaded_maps.get(name)

    def _getOtherBitnessMaps(self):
        return {name: other for name, other in self._other_bitness_maps.items() if self._isLoadedMap(name)}

    def getNumApisLoaded(self):
        return sum([len(self.api_maps[api_map_name]) for api_map_name in self.api_maps])

    def ignoreAslrOffsets(self, value):
        self.ignore_aslr_offsets = value

    def setBitness(self, bitness):
        """32 searches 32bit pointers only, which is all there is in the memory of a 32bit system, None both sizes"""
        self.bitness = bitness

    def hasDll(self, file_name):
        """whether a DLL of this file name is in one of the loaded API DBs"""
        return file_name.lower() in self._dll_file_names

    def setBaseAddress(self, address):
        self.base_address = address

    def setBinaryLength(self, length):
        """size of the image starting at the base address, used by filter() to recognize references into the own image"""
        self._binary_length = length

    def setLoadOffset(self, offset):
        self.load_offset = offset

    def iterateAllDwords(self, binary):
        unpack_from = struct.Struct("<I").unpack_from
        for offset in range(len(binary) - 3):
            yield offset, unpack_from(binary, offset)[0]

    def iterateAllQwords(self, binary):
        unpack_from = struct.Struct("<Q").unpack_from
        for offset in range(len(binary) - 7):
            yield offset, unpack_from(binary, offset)[0]

    def _findCandidates(self, binary, widths):
        """the DWORDs (width 4) and QWORDs (width 8) of the binary that are addresses of an API map, with their offsets
        in ascending order, as {(API map name, width): [(offset, value)]}. Maps and widths without any hit may be missing."""
        if numpy_search is None:
            return {
                (name, width): [
                    (offset, value)
                    for offset, value in (
                        self.iterateAllDwords(binary) if width == 4 else self.iterateAllQwords(binary)
                    )
                    if value in api_map
                ]
                for name, api_map in self.api_maps.items()
                for width in widths
            }
        # api_maps is public, search for the addresses of the maps as they are now
        signature = tuple((name, id(api_map), len(api_map)) for name, api_map in self.api_maps.items())
        if self._address_search is None or self._address_search[0] != signature:
            search = numpy_search.AddressSearch.fromApiMaps(self.api_maps, self._getOtherBitnessMaps())
            self._address_search = (signature, search, list(self.api_maps.values()))
        return self._address_search[1].find(binary, widths)

    def _parseImportTable(self, binary):
        if self._import_table is None:
            it_loader = ImportTableLoader(binary)
            self._import_table = it_loader.get_import_table()

    def _isImportTableEntry(self, offset):
        if not self._import_table:
            return None
        else:
            return offset in self._import_table

    def _findBaseAddress(self, binary):
        if self.base_address:
            return self.base_address
        # try to extract from PE header
        return PeTools.getBaseAddressFromPeHeader(binary)

    @staticmethod
    def _iterIndirectBranches(binary):
        if numpy_search is not None:
            yield from numpy_search.iter_indirect_branches(binary)
        else:
            for match in re.finditer(b"\xff[\x15\x25](?=.{4})", binary, flags=re.DOTALL):
                offset = match.start()
                yield offset, struct.unpack_from("<I", binary, offset + 2)[0]

    def _getCodeReferences(self, binary, targets, *, base_address=None, load_offset=0):
        """References to pointer offsets by their bitness and offset. Targets and callers share load_offset's origin."""
        references = {32: {}, 64: {}}
        if not targets:
            return references
        if base_address is None:
            base_address = self._findBaseAddress(binary)
        for offset, operand in self._iterIndirectBranches(binary):
            caller = offset + load_offset
            # x86 uses an absolute VA. x64 uses a signed displacement from the end of the instruction.
            absolute_target = operand - base_address + load_offset
            if absolute_target in targets:
                references[32].setdefault(absolute_target, set()).add(caller)
            displacement = operand - (1 << 32) if operand >= 1 << 31 else operand
            relative_target = caller + 6 + displacement
            if relative_target in targets:
                references[64].setdefault(relative_target, set()).add(caller)
        return references

    def evaluateImportTable(self, binary, is_unmapped=True):
        self._binary_length = len(binary)
        results = {"import_table": []}
        mapped_binary = PeTools.mapBinary(binary) if is_unmapped else binary
        # a file can not hold more imports than pointers, crafted tables referencing each other are cut off there
        bitness = PeTools.getBitness(mapped_binary)
        max_thunks = len(binary) // (8 if bitness == 64 else 4)
        import_table_loader = ImportTableLoader(mapped_binary, max_thunks=max_thunks, max_name_bytes=len(binary))
        self._import_table = import_table_loader.get_import_table()
        callers_by_offset = {}
        if PeTools.getMachine(mapped_binary) in PeTools.BITNESS_MAP:
            targets = {offset for offset in self._import_table if offset < len(mapped_binary)}
            callers_by_offset = self._getCodeReferences(mapped_binary, targets)[bitness]
        for offset, import_entry in sorted(self._import_table.items()):
            if not import_entry["name"]:
                # import by an ordinal without known name
                continue
            callers = {caller + self.load_offset for caller in callers_by_offset.get(offset, ())}
            results["import_table"].append(
                (
                    offset + self.load_offset,
                    0xFFFFFFFF,
                    import_entry["dll_name"].lower() + "_0x0",
                    import_entry["name"],
                    bitness,
                    True,
                    1 + len(callers),
                    callers,
                )
            )
        return results

    def crawl(self, binary):
        results = self._crawlPointers(binary)
        targets = {entry[0] for entries in results.values() for entry in entries}
        references = self._getCodeReferences(binary, targets, load_offset=self.load_offset)
        self._attachCodeReferences(results, references)
        return results

    def _crawlPointers(self, binary):
        results = {}
        self._binary_length = len(binary)
        self._import_table = None
        self._parseImportTable(binary)
        widths = (4, 8) if self.has_64bit and self.bitness != 32 else (4,)
        found = self._findCandidates(binary, widths)
        load_offset = self.load_offset
        for api_map_name in self.api_maps:
            recovered_apis = []
            for width in widths:
                bitness = width * 8
                for offset, api_address in found.get((api_map_name, width), ()):
                    dll, api, api_bitness = self._resolveApiByAddress(api_map_name, api_address, bitness)
                    if dll and api and api_bitness == bitness:
                        recovered_apis.append(
                            (
                                offset + load_offset,
                                api_address,
                                dll,
                                api,
                                bitness,
                                self._isImportTableEntry(offset),
                                1,
                                set(),
                            )
                        )
            # hits of both bitnesses are reported in the order of their offsets, as filter() and render() work on neighbouring entries
            if len(widths) > 1:
                recovered_apis.sort(key=lambda entry: (entry[0], entry[4]))
            results[api_map_name] = recovered_apis
        return results

    @staticmethod
    def _attachCodeReferences(results, references):
        for entries in results.values():
            for index, entry in enumerate(entries):
                callers = references[entry[4]].get(entry[0])
                if callers:
                    entries[index] = (*entry[:6], 1 + len(callers), callers.copy())

    def crawlRegions(self, regions):
        """crawl memory regions given as (start address, buffer), like ida_scout.py does with the segments of IDA.
        The offsets of the results are relative to the base address set before, so base address plus offset is the
        address of the hit. Code can refer to pointers in any of the captured regions."""
        load_offset, binary_length = self.load_offset, self._binary_length
        regions = list(regions)
        results = {}
        try:
            for start, binary in regions:
                self.setLoadOffset(start - self.base_address)
                for api_map_name, recovered_apis in self._crawlPointers(binary).items():
                    results.setdefault(api_map_name, []).extend(recovered_apis)
        finally:
            self.load_offset, self._binary_length = load_offset, binary_length
        targets = {entry[0] for entries in results.values() for entry in entries}
        references = {32: {}, 64: {}}
        if targets:
            for start, binary in regions:
                region_references = self._getCodeReferences(
                    binary, targets, base_address=start, load_offset=start - self.base_address
                )
                for bitness, offsets in region_references.items():
                    for offset, callers in offsets.items():
                        references[bitness].setdefault(offset, set()).update(callers)
        self._attachCodeReferences(results, references)
        # the regions are crawled in the order of their addresses, unless they were given in another one
        for recovered_apis in results.values():
            recovered_apis.sort(key=lambda entry: (entry[0], entry[4]))
        return results

    def _getDynamicFinder(self):
        try:
            # numpy is needed to hash the export names and to search the binary, other functions do without it
            from .DynamicApis import ApiNameIndex, DynamicApiFinder
        except ImportError:  # pragma: no cover - numpy is a dependency
            raise RuntimeError("Finding dynamically resolved APIs needs numpy.") from None
        key = tuple((name, id(api_map), len(api_map)) for name, api_map in self.api_maps.items())
        if self._dynamic_finder is None or self._dynamic_finder[0] != key:
            indexes = {
                name: ApiNameIndex(
                    (self._export_entries.get(name) if self._isLoadedMap(name) else None) or api_map.values()
                )
                for name, api_map in self.api_maps.items()
            }
            # the maps are kept, so that the id of a map that was replaced is not given to another one
            self._dynamic_finder = (key, DynamicApiFinder(indexes), list(self.api_maps.values()))
        return self._dynamic_finder[1]

    def findDynamicApis(
        self,
        binary,
        hashes=True,
        strings=True,
        min_string_length=None,
        min_hits=None,
        algorithms=None,
        min_string_run=None,
        keyed=True,
        min_key_apis=None,
    ):
        """APIs that the binary does not refer to by pointer but resolves at run time, per API map as {name: [DynamicApi]}, by offset

        hashes: APIs of which the hash of the name (algorithms, by default all of DynamicApis.HASH_ALGORITHMS) is in the binary, in a
        region of several hashes (min_hits sets the number, see DynamicApis.getMinimumHits). keyed: also the hashes that the program
        combines with a key of its own by XOR or ADD; the key is found in the binary from the hashes of common APIs (at least
        min_key_apis of them, default: DynamicApis.getMinimumKeyApis) and is part of the algorithm of such a hit, e.g. sdbm^0x1e5c48de.
        strings: APIs of which the name, at least min_string_length characters long (default: DynamicApis.DEFAULT_MIN_STRING_LENGTH), is a whole ASCII or UTF-16LE string that is in a
        run of at least min_string_run different names (default: DynamicApis.MIN_STRING_RUN, see DynamicApis.getStringRuns).
        The hashes of an API DB are computed at the first call after loading it."""
        finder = self._getDynamicFinder()
        results = {name: [] for name in self.api_maps}
        found = []
        if hashes:
            found.append(finder.findHashes(binary, algorithms, min_hits, self.load_offset, keyed, min_key_apis))
        if strings:
            found.append(finder.findStrings(binary, min_string_length, self.load_offset, min_string_run))
        for found_in_map in found:
            for name, apis in found_in_map.items():
                results[name].extend(apis)
        for apis in results.values():
            apis.sort(key=lambda api: (api.offset, api.kind, api.algorithm, api.api))
        return results

    def findDynamicApisInRegions(self, regions, exclude_ranges=()):
        """findDynamicApis() over memory regions given as (start address, buffer), like crawlRegions(); APIs found in
        exclude_ranges, (start, end) addresses such as the images of DLLs with their own export names, are dropped"""
        base_address, load_offset = self.base_address, self.load_offset
        results = {name: [] for name in self.api_maps}
        try:
            for start, binary in regions:
                self.setLoadOffset(start - base_address)
                for name, apis in self.findDynamicApis(binary).items():
                    results[name].extend(apis)
        finally:
            self.base_address, self.load_offset = base_address, load_offset
        for name, apis in results.items():
            results[name] = sorted(
                (
                    api
                    for api in apis
                    if not any(start <= base_address + api.offset < end for start, end in exclude_ranges)
                ),
                key=lambda api: (api.offset, api.kind, api.algorithm, api.api),
            )
        return results

    def addDynamicApisToResults(self, results, dynamic_results):
        """a copy of the results of crawl() with the dynamic APIs added as references without address, for the ApiVector

        A hash of a name does not tell which DLL exports the API. The DLLs of the WinApi1024 vector are used where there are some, so
        that the number of APIs does not grow with the number of DLLs that export the same name; otherwise the first DLL."""
        combined = {name: list(apis) for name, apis in results.items()}
        # the same API is found at many offsets
        chosen = {}
        for name, dynamic_apis in dynamic_results.items():
            for api in dynamic_apis:
                dlls = chosen.get((api.api, api.dlls))
                if dlls is None:
                    dlls = chosen[(api.api, api.dlls)] = [
                        dll for dll in api.dlls if self._apivector.isInWinApi1024(dll, api.api)
                    ] or list(api.dlls[:1])
                for dll in dlls:
                    combined.setdefault(name, []).append((api.offset, 0, dll + "_0x0", api.api, 0, None, 1, set()))
        return combined

    def renderDynamicApis(self, dynamic_results, max_dlls=3):
        output = ""
        for api_map_name, apis in dynamic_results.items():
            if not apis:
                output += f"No dynamically resolved APIs for API DB: {api_map_name}\n"
                continue
            output += f"Dynamically resolved APIs for API DB: {api_map_name}\n"
            # the algorithm of a hit with a key is longer
            width = max(9, *(len(api.algorithm) for api in apis))
            output += "{:3}: {:10}; {:6}; {:{width}}; {:10}; {:40}; {:60}\n".format(
                "idx", "offset", "type", "algorithm", "value", "DLL", "API", width=width
            )
            for index, api in enumerate(apis):
                dlls = ", ".join(api.dlls[:max_dlls]) + (
                    f" (+{len(api.dlls) - max_dlls})" if len(api.dlls) > max_dlls else ""
                )
                value = "" if api.value is None else f"0x{api.value:08x}"
                output += f"{index + 1:3}: 0x{self.base_address + api.offset:08x}; {api.kind:6}; {api.algorithm:{width}}; {value:10}; {dlls:40}; {api.api:60}\n"
            num_hashes = sum(api.kind == "hash" for api in apis)
            output += (
                f"APIs: {len({api.api for api in apis})}, by hash: {num_hashes}, by string: {len(apis) - num_hashes}\n"
            )
        return output

    @staticmethod
    def _getFilteredList(distance, list_to_filter):
        # keep all entries that have a neighbour at another offset within the given distance
        list_to_filter = sorted(list_to_filter, key=lambda item: item[0])
        offsets = sorted({item[0] for item in list_to_filter})
        keep = set()
        for offset, next_offset in itertools.pairwise(offsets):
            if next_offset - offset <= distance:
                keep.update((offset, next_offset))
        return [item for item in list_to_filter if item[0] in keep]

    def filter(self, result, from_addr, to_addr, distance, own_image=True, exclude_ranges=()):
        """exclude_ranges: (start, end) addresses of memory whose references are dropped, e.g. the images of DLLs"""
        filtered_result = {}
        ranges = sorted(exclude_ranges)
        range_starts = [start for start, _ in ranges]
        # an address is in a range if the greatest end of the ranges that start at or before it is behind it
        greatest_ends = list(itertools.accumulate((end for _, end in ranges), max))

        def is_excluded(address):
            num_starts = bisect.bisect_right(range_starts, address)
            return num_starts > 0 and greatest_ends[num_starts - 1] > address

        for key in result:
            filtered_list = result[key]
            if ranges:
                filtered_list = [item for item in filtered_list if not is_excluded(self.base_address + item[0])]
            # filter all entries pointing into our own image
            if own_image:
                filtered_list = [
                    item
                    for item in filtered_list
                    if (self.base_address > item[1] or (self.base_address + self._binary_length) <= item[1])
                ]
            if from_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] >= from_addr]
            if to_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] <= to_addr]
            if distance:
                filtered_list = [] if len(filtered_list) < 2 else self._getFilteredList(distance, filtered_list)
            filtered_result[key] = filtered_list
        return filtered_result

    def _getNeighbourCounts(self, entries):
        """for each (offset, bitness) of the hits of one API map: the number of other APIs in its cluster. Hits at least
        one pointer and at most CONFIDENCE_NEIGHBOUR_DISTANCE bytes apart form a cluster, and the same address repeated
        is one API, as in code that happens to repeat the bytes of an address (a table lists different APIs)."""
        counts = {}

        def count_clusters(hits, bitness):
            width = bitness // 8
            cluster = hits[:1]
            for hit in itertools.chain(hits[1:], (None,)):
                if hit is not None and width <= hit[0] - cluster[-1][0] <= self.CONFIDENCE_NEIGHBOUR_DISTANCE:
                    cluster.append(hit)
                    continue
                num_apis = len({address for _, address in cluster})
                for member_offset, _ in cluster:
                    key = (member_offset, bitness)
                    counts[key] = max(counts.get(key, 0), num_apis - 1)
                cluster = [] if hit is None else [hit]

        for bitness in {entry[4] for entry in entries}:
            width = bitness // 8
            hits = sorted({(entry[0], entry[1]) for entry in entries if entry[4] == bitness})
            count_clusters(hits, bitness)
            if any(right[0] - left[0] < width for left, right in itertools.pairwise(hits)):
                # An overlapping candidate can interrupt a table without belonging to it. Also consider
                # each alignment separately so the table can still contribute to its members' scores.
                by_alignment = {}
                for hit in hits:
                    by_alignment.setdefault(hit[0] % width, []).append(hit)
                for alignment_hits in by_alignment.values():
                    count_clusters(alignment_hits, bitness)
        return counts

    def getConfidences(self, results):
        """confidence from 0 to 100 of every hit of the results of crawl() or evaluateImportTable(), see CONFIDENCE_*.
        Returns {api_map_name: {(offset, bitness): confidence}}. Neighbours and agreement are taken from the given
        results, so score the complete results of a scan, before filtering them."""
        # the same API at the same offset in the results of another API DB is an agreement, which there can not be with one DB
        located_apis = {}
        if len(results) > 1:
            for api_map_name, entries in results.items():
                for entry in entries:
                    api_key = (entry[2].lower().rsplit("_0x", 1)[0], entry[3])
                    located_apis.setdefault((entry[0], entry[4], api_key), set()).add(api_map_name)
        neighbour_scores, references_score = self.CONFIDENCE_NEIGHBOURS, self.CONFIDENCE_REFERENCES
        confidences = {}
        for api_map_name, entries in results.items():
            neighbour_counts = self._getNeighbourCounts(entries)
            scores = confidences[api_map_name] = {}
            for entry in entries:
                offset, bitness = entry[0], entry[4]
                if entry[5]:
                    score = 100
                else:
                    score = neighbour_scores[min(neighbour_counts[(offset, bitness)], 3)]
                    if entry[6] > 1:
                        score += references_score
                    if located_apis:
                        api_key = (entry[2].lower().rsplit("_0x", 1)[0], entry[3])
                        if located_apis[(offset, bitness, api_key)] - {api_map_name}:
                            score += self.CONFIDENCE_AGREEMENT
                    if (self.base_address + offset) % (bitness // 8) == 0:
                        score = min(score + self.CONFIDENCE_ALIGNED, 100)
                    else:
                        score = min(score, self.CONFIDENCE_UNALIGNED_MAX)
                scores[(offset, bitness)] = score
        return confidences

    def filterByConfidence(self, results, min_confidence, confidences=None):
        """the hits of the results with a confidence of at least min_confidence, in the shape of the results. Give the
        confidences of getConfidences() for the complete results, otherwise they are computed from these results."""
        if confidences is None:
            confidences = self.getConfidences(results)
        return {
            api_map_name: [
                entry for entry in entries if confidences[api_map_name][(entry[0], entry[4])] >= min_confidence
            ]
            for api_map_name, entries in results.items()
        }

    def getWinApi1024Vectors(self, results):
        return self._apivector.getApiVectors(results)

    def matchVectors(self, vector_a, vector_b):
        return self._apivector.matchVectors(vector_a, vector_b)

    def matchVectorCollection(self, vector, collection_path):
        return self._apivector.matchVectorCollection(vector, collection_path)

    def loadCollection(self, path):
        return self._apivector.loadCollection(path)

    def matchLoadedCollection(self, vector, collection, path):
        return self._apivector.matchLoadedCollection(vector, collection, path)

    def validateCollection(self, lines):
        self._apivector.validateCollection(lines)

    def explainMatch(self, vector_a, vector_b):
        return self._apivector.explainMatch(vector_a, vector_b)

    def getCollectionVector(self, collection_path, family, sample):
        return self._apivector.getCollectionVector(collection_path, family, sample)

    def getPrimaryVector(self, api_vectors):
        if not api_vectors:
            empty_vector = {
                "vector": self._apivector.compress([0] * len(self._apivector.getWinApi1024())),
                "num_unique_apis": 0,
                "in_api_vector": 0,
                "percentage": 0,
            }
            return ("", empty_vector)
        return sorted(
            api_vectors.items(),
            key=lambda entry: (entry[1]["in_api_vector"], entry[1]["percentage"], entry[1]["num_unique_apis"]),
        )[-1]

    def render(self, results):
        lines = []
        base_address = self.base_address
        # the address of a 32bit hit is 8 hex digits wide and set off by 10 spaces, that of a 64bit hit 16 digits wide
        row_32 = "%3d: 0x%08x;         0x%08x; %-3s; %4d; %-40s; %-60s\n"
        row_64 = "%3d: 0x%08x; 0x%016x; %-3s; %4d; %-40s; %-60s\n"
        for api_map_name, result in results.items():
            if not len(result):
                lines.append(f"No results for API map: {api_map_name}\n")
                continue
            lines.append(f"Results for API DB: {api_map_name}\n")
            lines.append(
                "{:3}: {:10}; {:18}; {:3}; {:4};{:40}; {:60}\n".format(
                    "idx", "offset", "VA", "IT?", "#ref", "DLL", "API"
                )
            )
            prev_offset = None
            num_references = 0
            for index, entry in enumerate(result, 1):
                if prev_offset is not None and entry[0] > prev_offset + 16:
                    lines.append("-" * 129 + "\n")
                is_in_import_table = "err" if entry[5] is None else "yes" if entry[5] else "no"
                row_format = row_32 if entry[4] == 32 else row_64
                dll_name = f"{entry[2]} ({entry[4]}bit)"
                lines.append(
                    row_format
                    % (index, base_address + entry[0], entry[1], is_in_import_table, entry[6], dll_name, entry[3])
                )
                num_references += entry[6] - 1
                prev_offset = entry[0]
            num_dlls, num_apis = len({entry[2] for entry in result}), len({entry[3] for entry in result})
            lines.append(f"DLLs: {num_dlls}, APIs: {num_apis}, references: {num_references}\n")
        return "".join(lines)

    def renderVectorResults(self, results):
        api_vectors = self.getWinApi1024Vectors(results)
        output = "WinApi1024 Vector Results:\n"
        for api_map_name, result in sorted(api_vectors.items()):
            output += "{}: {} / {} ({:5.2f}%) APIs covered in WinApi1024 vector.\n".format(
                api_map_name, result["in_api_vector"], result["num_unique_apis"], result["percentage"]
            )
            output += "    Vector:     {}\n".format(result["vector"])
            output += "    Confidence: {}\n".format(self._apivector.getVectorConfidence(result["vector"]))
        return output

    def renderResultsVsCollection(self, results, collection_file):
        # find primary vector
        api_vectors = self.getWinApi1024Vectors(results)
        primary_vector = self.getPrimaryVector(api_vectors)
        output = f'Using resulting Vector from DB "{primary_vector[0]}" for matching...\n'
        collection_result = self.matchVectorCollection(primary_vector[1]["vector"], collection_file)
        output += self.renderVectorCollectionResults(collection_result)
        return output

    def renderVectorCollectionResults(self, results, max_results=5):
        output = "WinApi1024 Vector vs Collection Results:\n"
        output += "    Vector: {}\n".format(results["vector"])
        output += "    Collection: {} ({} families, {} vectors)\n".format(
            results["collection_filepath"], results["families_in_collection"], results["vectors_in_collection"]
        )
        if not results["match_results"]:
            output += "No vectors found in collection, nothing to match against.\n"
            return output
        family_width = max([len(entry[0]) for entry in results["match_results"]])
        sample_width = max([len(entry[1]) for entry in results["match_results"]])
        output += "-" * (family_width + sample_width + 5 + 6) + "\n"
        output += f"Top {max_results} family matches\n"
        num_results = 0
        seen_families = []
        for result in results["match_results"]:
            if num_results >= max_results:
                break
            if result[0] not in seen_families:
                output += "{:{fw}} - {:{sw}} - {:.3f}\n".format(
                    result[0], result[1], result[2], fw=family_width, sw=sample_width
                )
                seen_families.append(result[0])
                num_results += 1
        output += "-" * (family_width + sample_width + 5 + 6) + "\n"
        output += f"Top {max_results} individual matches\n"
        for result in results["match_results"][:max_results]:
            output += "{:{fw}} - {:{sw}} - {:.3f}\n".format(
                result[0], result[1], result[2], fw=family_width, sw=sample_width
            )
        return output

    def renderBestMatchExplanation(self, best_match, top=5):
        """best_match is the explanation of a match with a collection, as produced by cli"""
        output = "Best match: {} - {} - {:.3f}\n".format(
            best_match["family"], best_match["sample"], best_match["score"]
        )
        return output + self.renderMatchExplanation(best_match, top)

    def renderMatchExplanation(self, explanation, top=10):
        output = ""
        sections = (("Shared APIs", "shared"), ("APIs only in vector A", "only_a"), ("APIs only in vector B", "only_b"))
        for title, key in sections:
            entries = explanation[key]
            if not entries:
                output += f"{title}: none\n"
                continue
            output += f"{title}, top {min(top, len(entries))} of {len(entries)} by weight:\n"
            for entry in entries[:top]:
                output += f"  {entry['weight']:6}  {entry['dll']}!{entry['api']}\n"
        return output
