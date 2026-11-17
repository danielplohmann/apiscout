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

import itertools
import json
import logging
import os
import re
import struct

try:
    import numpy as np
except ImportError:  # pragma: no cover - numpy is a dependency, the plain loop is kept for environments without it
    np = None

from .ApiVector import ApiVector
from .ImportTableLoader import ImportTableLoader
from .PeTools import PeTools

LOG = logging.getLogger(__name__)


class ApiScout:
    # number of DWORDs/QWORDs compared at once by the numpy search, bounds its memory use to some 100 MB
    SEARCH_CHUNK_SIZE = 1 << 22
    # share of exports overwriting another DLL's address above which loading an API DB issues a warning
    COLLISION_WARNING_RATIO = 0.01

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
        self.api_maps = {}
        self._api_map_sources = {}
        self._other_bitness_maps = {}
        self._sorted_addresses = {}
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

    def loadDbFile(self, db_filepath, place=None):
        """load an API DB. place(api_db) can return {DLL key: load address} to put DLLs at the addresses they are really
        loaded at (see LoadAddresses.DllPlacer), the other DLLs keep the addresses of the DB."""
        api_db = {}
        if os.path.isfile(db_filepath):
            with open(db_filepath) as f_json:
                api_db = json.loads(f_json.read())
        else:
            LOG.error("Not a file: %s!", db_filepath)
            raise ValueError
        placements = place(api_db) if place else {}
        num_apis_loaded = 0
        num_collisions = 0
        api_map = {}
        other_bitness_map = {}
        for dll_entry in api_db["dlls"]:
            LOG.debug("  building address map for: %s", dll_entry)
            aslr_offset = 0
            if not self.ignore_aslr_offsets:
                aslr_offset = api_db["dlls"][dll_entry].get("aslr_offset", 0)
            for export in api_db["dlls"][dll_entry]["exports"]:
                num_apis_loaded += 1
                api_name = "{}".format(export["name"])
                if api_name == "None":
                    api_name = "None<{}>".format(export["ordinal"])
                dll_name = "_".join(dll_entry.split("_")[2:])
                self._dll_file_names.add(re.sub(r"_0x[0-9a-fA-F]+$", "", dll_name).lower())
                bitness = api_db["dlls"][dll_entry]["bitness"]
                self.has_64bit |= bitness == 64
                base_address = api_db["dlls"][dll_entry]["base_address"]
                if dll_entry in placements:
                    virtual_address = placements[dll_entry] + export["address"]
                else:
                    virtual_address = base_address + export["address"] - aslr_offset
                if virtual_address in api_map:
                    if api_map[virtual_address][0].lower() != dll_name.lower():
                        num_collisions += 1
                    if api_map[virtual_address][2] != bitness:
                        # a 32bit and a 64bit DLL can share an address, both stay resolvable for their pointer size
                        other_bitness_map[virtual_address] = api_map[virtual_address]
                api_map[virtual_address] = (dll_name, api_name, bitness)
            LOG.debug("loaded %d exports", num_apis_loaded)
        LOG.debug(
            "loaded %d exports from %d DLLs (%s) with %d potential collisions.",
            num_apis_loaded,
            len(api_db["dlls"]),
            api_db["os_name"],
            num_collisions,
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
        self._other_bitness_maps[api_map_name] = other_bitness_map

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
        if bitness is not None and api_entry[2] != bitness:
            api_entry = self._other_bitness_maps.get(api_map_name, {}).get(absolute_addr, api_entry)
        return api_entry

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

    def _getSortedAddresses(self, api_map_name):
        assert np is not None
        api_map = self.api_maps[api_map_name]
        cached = self._sorted_addresses.get(api_map_name)
        # api_maps is public, rebuild when a map was replaced or extended since the last scan
        if cached is None or cached[0] is not api_map or len(cached[1]) != len(api_map):
            cached = (api_map, np.array(sorted(api_map), dtype=np.uint64))
            self._sorted_addresses[api_map_name] = cached
        return cached[1]

    def _iterateCandidates(self, binary, api_map_name, width):
        """offsets and values of all DWORDs (width 4) or QWORDs (width 8) that are addresses in the API map, in the order of their offsets"""
        if np is None:
            values = self.iterateAllDwords(binary) if width == 4 else self.iterateAllQwords(binary)
            api_map = self.api_maps[api_map_name]
            yield from ((offset, value) for offset, value in values if value in api_map)
            return
        addresses = self._getSortedAddresses(api_map_name)
        if width == 4:
            addresses = addresses[addresses <= 0xFFFFFFFF].astype(np.uint32)
        if not len(addresses) or len(binary) < width:
            return
        lowest, highest = addresses[0], addresses[-1]
        dtype = np.dtype("<u4") if width == 4 else np.dtype("<u8")
        hits = []
        # one view per alignment, each one reads every width-th value starting at that offset
        for alignment in range(width):
            count = (len(binary) - alignment) // width
            for start in range(0, count, self.SEARCH_CHUNK_SIZE):
                values = np.frombuffer(
                    binary,
                    dtype=dtype,
                    count=min(self.SEARCH_CHUNK_SIZE, count - start),
                    offset=alignment + start * width,
                )
                indices = np.flatnonzero((values >= lowest) & (values <= highest))
                if not len(indices):
                    continue
                in_range = values[indices]
                positions = np.minimum(np.searchsorted(addresses, in_range), len(addresses) - 1)
                indices = indices[addresses[positions] == in_range]
                hits.append(alignment + (start + indices) * width)
        if not hits:
            return
        offsets = np.sort(np.concatenate(hits))
        unpack_from = struct.Struct("<I" if width == 4 else "<Q").unpack_from
        for offset in offsets.tolist():
            yield offset, unpack_from(binary, offset)[0]

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

    def _updateCodeReferences(self, references, binary, base_address, offset, targets=None):
        addr_block = binary[offset + 2 : offset + 2 + 4]
        if len(addr_block) < 4:
            # opcode bytes at the very end of the buffer, there is no operand left to read
            return
        # treat as 32bit code (absolute offsets)
        function_addr = struct.unpack("<I", addr_block)[0] - base_address
        if 0 < function_addr < len(binary) and (targets is None or function_addr in targets):
            if function_addr not in references[32]:
                references[32][function_addr] = set()
            references[32][function_addr].add(offset)
        # treat as 64bit code (this means relative offsets for jmps/calls)
        function_addr = struct.unpack("<i", addr_block)[0]
        # RIP-relative: target is relative to the end of the 6 byte instruction (ff 25|15 ** ** ** **),
        # offset points to the ff opcode byte, i.e. behind a potential REX prefix (48 ff 25 ** ** ** **).
        if binary[offset : offset + 2] == b"\xff\x25" or binary[offset : offset + 2] == b"\xff\x15":
            function_addr += offset + 6
        if 0 < function_addr < len(binary) and (targets is None or function_addr in targets):
            if function_addr not in references[64]:
                references[64][function_addr] = set()
            references[64][function_addr].add(offset)

    def _getCodeReferences(self, binary, targets=None):
        """references by calls and jumps through pointers, optionally only those to the given offsets"""
        references = {32: {}, 64: {}}
        base_address = self._findBaseAddress(binary)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xff\x25", binary):
            self._updateCodeReferences(references, binary, base_address, match.start(), targets)
        # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xff\x15", binary):
            self._updateCodeReferences(references, binary, base_address, match.start(), targets)
        return references

    def evaluateImportTable(self, binary, is_unmapped=True):
        self._binary_length = len(binary)
        results = {"import_table": []}
        mapped_binary = PeTools.mapBinary(binary) if is_unmapped else binary
        # a file can not hold more imports than pointers, crafted tables referencing each other are cut off there
        max_thunks = len(binary) // 8 if PeTools.getBitness(mapped_binary) == 64 else len(binary) // 4
        import_table_loader = ImportTableLoader(mapped_binary, max_thunks=max_thunks, max_name_bytes=len(binary))
        self._import_table = import_table_loader.get_import_table()
        bitness = PeTools.getBitness(mapped_binary)
        references = self._getCodeReferences(mapped_binary, self._import_table.keys())
        for offset, import_entry in sorted(self._import_table.items()):
            if not import_entry["name"]:
                # import by an ordinal without known name
                continue
            ref_count = 1
            if bitness:
                ref_count = 1 + len(references[bitness][offset]) if offset in references[bitness] else 1
            results["import_table"].append(
                (
                    offset + self.load_offset,
                    0xFFFFFFFF,
                    import_entry["dll_name"].lower() + "_0x0",
                    import_entry["name"],
                    bitness,
                    True,
                    ref_count,
                    references[bitness].get(offset, set()),
                )
            )
        return results

    def crawl(self, binary):
        results = {}
        self._binary_length = len(binary)
        self._import_table = None
        self._parseImportTable(binary)
        references = self._getCodeReferences(binary)
        for api_map_name in self.api_maps:
            recovered_apis = []
            for offset, api_address in self._iterateCandidates(binary, api_map_name, 4):
                dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address, 32)
                if dll and api and bitness == 32:
                    ref_count = 1 + len(references[32][offset]) if offset in references[32] else 1
                    recovered_apis.append(
                        (
                            offset + self.load_offset,
                            api_address,
                            dll,
                            api,
                            bitness,
                            self._isImportTableEntry(offset),
                            ref_count,
                            {caller + self.load_offset for caller in references[bitness].get(offset, set())},
                        )
                    )
            if self.has_64bit and self.bitness != 32:
                for offset, api_address in self._iterateCandidates(binary, api_map_name, 8):
                    dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address, 64)
                    if dll and api and bitness == 64:
                        ref_count = 1 + len(references[64][offset]) if offset in references[64] else 1
                        recovered_apis.append(
                            (
                                offset + self.load_offset,
                                api_address,
                                dll,
                                api,
                                bitness,
                                self._isImportTableEntry(offset),
                                ref_count,
                                {caller + self.load_offset for caller in references[bitness].get(offset, set())},
                            )
                        )
            # hits of both bitnesses are reported in the order of their offsets, as filter() and render() work on neighbouring entries
            recovered_apis.sort(key=lambda entry: (entry[0], entry[4]))
            results[api_map_name] = recovered_apis
        return results

    def crawlRegions(self, regions):
        """crawl memory regions given as (start address, buffer), like ida_scout.py does with the segments of IDA.
        The offsets of the results are relative to the base address set before, so base address plus offset is the
        address of the hit. References of code are resolved within each region."""
        base_address, load_offset, binary_length = self.base_address, self.load_offset, self._binary_length
        results = {}
        try:
            for start, binary in regions:
                self.setLoadOffset(start - base_address)
                self.setBaseAddress(start)
                for api_map_name, recovered_apis in self.crawl(binary).items():
                    results.setdefault(api_map_name, []).extend(recovered_apis)
        finally:
            self.base_address, self.load_offset, self._binary_length = base_address, load_offset, binary_length
        # the regions are crawled in the order of their addresses, unless they were given in another one
        for recovered_apis in results.values():
            recovered_apis.sort(key=lambda entry: (entry[0], entry[4]))
        return results

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
        for key in result:
            filtered_list = result[key]
            if exclude_ranges:
                filtered_list = [
                    item
                    for item in filtered_list
                    if not any(start <= self.base_address + item[0] < end for start, end in exclude_ranges)
                ]
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
        for bitness in {entry[4] for entry in entries}:
            width = bitness // 8
            hits = sorted({(entry[0], entry[1]) for entry in entries if entry[4] == bitness})
            cluster = hits[:1]
            for hit in [*hits[1:], None]:
                if hit is not None and width <= hit[0] - cluster[-1][0] <= self.CONFIDENCE_NEIGHBOUR_DISTANCE:
                    cluster.append(hit)
                    continue
                num_apis = len({address for _, address in cluster})
                for member_offset, _ in cluster:
                    counts[(member_offset, bitness)] = num_apis - 1
                cluster = [] if hit is None else [hit]
        return counts

    def getConfidences(self, results):
        """confidence from 0 to 100 of every hit of the results of crawl() or evaluateImportTable(), see CONFIDENCE_*.
        Returns {api_map_name: {(offset, bitness): confidence}}. Neighbours and agreement are taken from the given
        results, so score the complete results of a scan, before filtering them."""
        located_apis = {}
        for api_map_name, entries in results.items():
            for entry in entries:
                api_key = (entry[2].lower().rsplit("_0x", 1)[0], entry[3])
                located_apis.setdefault((entry[0], entry[4], api_key), set()).add(api_map_name)
        confidences = {}
        for api_map_name, entries in results.items():
            neighbour_counts = self._getNeighbourCounts(entries)
            confidences[api_map_name] = {}
            for entry in entries:
                offset, bitness = entry[0], entry[4]
                if entry[5]:
                    score = 100
                else:
                    score = self.CONFIDENCE_NEIGHBOURS[min(neighbour_counts[(offset, bitness)], 3)]
                    if entry[6] > 1:
                        score += self.CONFIDENCE_REFERENCES
                    api_key = (entry[2].lower().rsplit("_0x", 1)[0], entry[3])
                    if located_apis[(offset, bitness, api_key)] - {api_map_name}:
                        score += self.CONFIDENCE_AGREEMENT
                    if (self.base_address + offset) % (bitness // 8) == 0:
                        score = min(score + self.CONFIDENCE_ALIGNED, 100)
                    else:
                        score = min(score, self.CONFIDENCE_UNALIGNED_MAX)
                confidences[api_map_name][(offset, bitness)] = score
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
        return sorted(api_vectors.items(), key=lambda x: (x[1]["in_api_vector"], x[1]["percentage"]))[-1]

    def render(self, results):
        output = ""
        for api_map_name in results:
            if len(results[api_map_name]):
                result = results[api_map_name]
                output += f"Results for API DB: {api_map_name}\n"
                output += "{:3}: {:10}; {:18}; {:3}; {:4};{:40}; {:60}\n".format(
                    "idx", "offset", "VA", "IT?", "#ref", "DLL", "API"
                )
                prev_offset = None
                dlls = set()
                apis = set()
                num_references = 0
                for index, entry in enumerate(result):
                    if prev_offset is not None and entry[0] > prev_offset + 16:
                        output += "-" * 129 + "\n"
                    dll_name = f"{entry[2]} ({entry[4]}bit)"
                    is_in_import_table = "err" if entry[5] is None else "yes" if entry[5] else "no"
                    if entry[4] == 32:
                        output += f"{index + 1:3}: 0x{self.base_address + entry[0]:08x};         0x{entry[1]:08x}; {is_in_import_table:3}; {entry[6]:4}; {dll_name:40}; {entry[3]:60}\n"
                    else:
                        output += f"{index + 1:3}: 0x{self.base_address + entry[0]:08x}; 0x{entry[1]:016x}; {is_in_import_table:3}; {entry[6]:4}; {dll_name:40}; {entry[3]:60}\n"
                    num_references += entry[6] - 1
                    prev_offset = entry[0]
                    dlls.add(entry[2])
                    apis.add(entry[3])
                output += f"DLLs: {len(dlls)}, APIs: {len(apis)}, references: {num_references}\n"
            else:
                output += f"No results for API map: {api_map_name}\n"
        return output

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
