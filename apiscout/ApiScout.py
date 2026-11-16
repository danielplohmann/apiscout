########################################################################
# Copyright (c) 2018
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# Steffen Enders <steffen<at>enders<dot>nrw>
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

import json
import logging
import os
import re
import struct

try:
    import lief
except ImportError:
    print(
        "lief is not installed! We recommend installing lief to improve import table parsing capabilities of ApiScout!"
    )
    lief = None

from .ApiVector import ApiVector
from .ImportTableLoader import ImportTableLoader
from .OrdinalHelper import OrdinalHelper
from .PeTools import PeTools

LOG = logging.getLogger(__name__)


class ApiScout:
    # share of exports overwriting another DLL's address above which loading an API DB issues a warning
    COLLISION_WARNING_RATIO = 0.01

    def __init__(self, db_filepath=None):
        self.api_maps = {}
        self._api_map_sources = {}
        self.has_64bit = False
        self.base_address = 0
        self._binary_length = 0
        # Used to achieve coherent offset view in IdaScout
        self.load_offset = 0
        self.ignore_aslr_offsets = False
        self._import_table = None
        if db_filepath:
            self.loadDbFile(db_filepath)
        self._apivector = ApiVector()
        self.loadWinApi1024()

    def loadDbFile(self, db_filepath):
        api_db = {}
        if os.path.isfile(db_filepath):
            with open(db_filepath) as f_json:
                api_db = json.loads(f_json.read())
        else:
            LOG.error("Not a file: %s!", db_filepath)
            raise ValueError
        num_apis_loaded = 0
        num_collisions = 0
        api_map = {}
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
                bitness = api_db["dlls"][dll_entry]["bitness"]
                self.has_64bit |= bitness == 64
                base_address = api_db["dlls"][dll_entry]["base_address"]
                virtual_address = base_address + export["address"] - aslr_offset
                if virtual_address in api_map and (api_map[virtual_address][0].lower() != dll_name.lower()):
                    num_collisions += 1
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
        self.api_maps[self._getApiMapName(api_db["os_name"], db_filepath)] = api_map

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

    def _resolveApiByAddress(self, api_map_name, absolute_addr):
        api_entry = ("", "", "")
        api_map = self.api_maps[api_map_name]
        check_address = absolute_addr
        if check_address in api_map:
            api_entry = api_map[check_address]
        return api_entry

    def getNumApisLoaded(self):
        return sum([len(self.api_maps[api_map_name]) for api_map_name in self.api_maps])

    def ignoreAslrOffsets(self, value):
        self.ignore_aslr_offsets = value

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

    def _updateCodeReferences(self, references, binary, base_address, offset):
        addr_block = binary[offset + 2 : offset + 2 + 4]
        if len(addr_block) < 4:
            # opcode bytes at the very end of the buffer, there is no operand left to read
            return
        # treat as 32bit code (absolute offsets)
        function_addr = struct.unpack("<I", addr_block)[0] - base_address
        if 0 < function_addr < len(binary):
            if function_addr not in references[32]:
                references[32][function_addr] = set()
            references[32][function_addr].add(offset)
        # treat as 64bit code (this means relative offsets for jmps/calls)
        function_addr = struct.unpack("<i", addr_block)[0]
        # RIP-relative: target is relative to the end of the 6 byte instruction (ff 25|15 ** ** ** **),
        # offset points to the ff opcode byte, i.e. behind a potential REX prefix (48 ff 25 ** ** ** **).
        if binary[offset : offset + 2] == b"\xff\x25" or binary[offset : offset + 2] == b"\xff\x15":
            function_addr += offset + 6
        if 0 < function_addr < len(binary):
            if function_addr not in references[64]:
                references[64][function_addr] = set()
            references[64][function_addr].add(offset)

    def _getCodeReferences(self, binary):
        references = {32: {}, 64: {}}
        base_address = self._findBaseAddress(binary)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xff\x25", binary):
            self._updateCodeReferences(references, binary, base_address, match.start())
        # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xff\x15", binary):
            self._updateCodeReferences(references, binary, base_address, match.start())
        return references

    def _parseWithLief(self, binary):
        """parse a PE with LIEF, returns None if LIEF is not available or can not handle the buffer"""
        if not lief or not PeTools.checkPe(binary):
            return None
        try:
            lief_binary = lief.parse(binary)
        except Exception as exc:
            LOG.warning("LIEF failed to parse the binary (%s), falling back to our own import table parser.", exc)
            return None
        if lief_binary is None or not hasattr(lief_binary, "imports"):
            return None
        return lief_binary

    def evaluateImportTable(self, binary, is_unmapped=True):
        self._binary_length = len(binary)
        results = {"import_table": []}
        lief_binary = self._parseWithLief(binary)
        if lief_binary is not None:
            # the machine type is read from the header directly, as its representation differs across LIEF versions
            bitness = PeTools.getBitness(binary)
            for imported_library in lief_binary.imports:
                dll_name = str(imported_library.name).lower()
                for func in imported_library.entries:
                    api_name = func.name
                    if func.is_ordinal:
                        api_name = OrdinalHelper.resolveOrdinal(dll_name, func.ordinal)
                    if api_name:
                        results["import_table"].append(
                            (
                                func.iat_address + self.load_offset,
                                0xFFFFFFFF,
                                dll_name + "_0x0",
                                str(api_name),
                                bitness,
                                True,
                                1,
                                set(),
                            )
                        )
        else:
            # fallback using the old method and out own import table parser
            mapped_binary = binary
            if is_unmapped:
                LOG.debug("Mapping unmapped binary before processing")
                mapped_binary = PeTools.mapBinary(binary)
            bitness = PeTools.getBitness(mapped_binary)
            self._import_table = ImportTableLoader(mapped_binary).get_import_table()
            references = self._getCodeReferences(mapped_binary)
            for offset, import_entry in sorted(self._import_table.items()):
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
            for offset, api_address in self.iterateAllDwords(binary):
                dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address)
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
                            references[bitness].get(offset, set()),
                        )
                    )
            if self.has_64bit:
                for offset, api_address in self.iterateAllQwords(binary):
                    dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address)
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
                                references[bitness].get(offset, set()),
                            )
                        )
            # hits of both bitnesses are reported in the order of their offsets, as filter() and render() work on neighbouring entries
            recovered_apis.sort(key=lambda entry: (entry[0], entry[4]))
            results[api_map_name] = recovered_apis
        return results

    def _getFilteredList(self, distance, list_to_filter):
        # keep all entries that have a neighbour within the given distance, requires the list to be ordered by offset
        list_to_filter = sorted(list_to_filter, key=lambda item: item[0])
        keep = [False] * len(list_to_filter)
        for index in range(len(list_to_filter) - 1):
            if list_to_filter[index + 1][0] - list_to_filter[index][0] <= distance:
                keep[index] = True
                keep[index + 1] = True
        return [item for index, item in enumerate(list_to_filter) if keep[index]]

    def filter(self, result, from_addr, to_addr, distance, own_image=True):
        filtered_result = {}
        for key in result:
            filtered_list = result[key]
            # filter all entries pointing into our own image
            if own_image:
                filtered_list = [
                    item
                    for item in filtered_list
                    if (self.base_address > item[1] or (self.base_address + self._binary_length) < item[1])
                ]
            if from_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] >= from_addr]
            if to_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] <= to_addr]
            if distance:
                filtered_list = [] if len(filtered_list) < 2 else self._getFilteredList(distance, filtered_list)
            filtered_result[key] = filtered_list
        return filtered_result

    def getWinApi1024Vectors(self, results):
        return self._apivector.getApiVectors(results)

    def matchVectors(self, vector_a, vector_b):
        return self._apivector.matchVectors(vector_a, vector_b)

    def matchVectorCollection(self, vector, collection_path):
        return self._apivector.matchVectorCollection(vector, collection_path)

    def getPrimaryVector(self, api_vectors):
        if not api_vectors:
            empty_vector = {
                "vector": self._apivector.compress([0] * len(self._apivector.getWinApi1024())),
                "num_unique_apis": 0,
                "in_api_vector": 0,
                "percentage": 0,
            }
            return ("", empty_vector)
        return sorted(api_vectors.items(), key=lambda x: x[1]["percentage"])[-1]

    def render(self, results):
        output = ""
        for api_map_name in results:
            if len(results[api_map_name]):
                result = results[api_map_name]
                output += f"Results for API DB: {api_map_name}\n"
                output += "{:3}: {:10}; {:18}; {:3}; {:4};{:40}; {:60}\n".format(
                    "idx", "offset", "VA", "IT?", "#ref", "DLL", "API"
                )
                prev_offset = 0
                dlls = set()
                apis = set()
                num_references = 0
                for index, entry in enumerate(result):
                    if prev_offset and entry[0] > prev_offset + 16:
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
