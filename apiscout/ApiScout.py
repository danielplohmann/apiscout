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

import re
import struct
import os
import json
import operator
import logging

try:
    import lief
except:
    print("lief is not installed! We recommend installing lief to improve import table parsing capabilities of ApiScout!")
    lief = None

from .ImportTableLoader import ImportTableLoader
from .ApiVector import ApiVector
from .PeTools import PeTools

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class ApiScout(object):

    def __init__(self, db_filepath=None):
        self.api_maps = {}
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
            with open(db_filepath, "r") as f_json:
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
                aslr_offset = api_db["dlls"][dll_entry]["aslr_offset"]
            for export in api_db["dlls"][dll_entry]["exports"]:
                num_apis_loaded += 1
                api_name = "%s" % (export["name"])
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
        LOG.debug("loaded %d exports from %d DLLs (%s) with %d potential collisions.", num_apis_loaded, len(api_db["dlls"]), api_db["os_name"], num_collisions)
        self.api_maps[api_db["os_name"]] = api_map

    def loadWinApi1024(self, winapi1024_filepath=None):
        if winapi1024_filepath is None:
            this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
            winapi1024_filepath =  this_dir + os.sep + "data" + os.sep + "winapi1024v1.txt"
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

    def setLoadOffset(self, offset):
        self.load_offset = offset

    def iterateAllDwords(self, binary):
        for offset, _ in enumerate(binary):
            try:
                dword = struct.unpack("I", binary[offset:offset + 4])[0]
                yield offset, dword
            except struct.error:
                break

    def iterateAllQwords(self, binary):
        for offset, _ in enumerate(binary):
            try:
                dword = struct.unpack("Q", binary[offset:offset + 8])[0]
                yield offset, dword
            except struct.error:
                break

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
        # treat as 32bit code (absolute offsets)
        addr_block = binary[offset + 2:offset + 2 + 4]
        function_addr = struct.unpack("I", addr_block)[0] - base_address
        if 0 < function_addr < len(binary):
            if function_addr not in references[32]:
                references[32][function_addr] = set()
            references[32][function_addr].add(offset)
        # treat as 64bit code (this means relative offsets for jmps/calls)
        addr_block = binary[offset + 2:offset + 2 + 4]
        function_addr = struct.unpack("i", addr_block)[0]
        # we need to calculate RIP + offset + 7 (48 ff 25 ** ** ** **)
        if binary[offset:offset + 2] == b"\xFF\x25":
            function_addr += offset + 7
        elif binary[offset:offset + 2] == b"\xFF\x15":
            function_addr += offset + 6
        if 0 < function_addr < len(binary):
            if function_addr not in references[64]:
                references[64][function_addr] = set()
            references[64][function_addr].add(offset)

    def _getCodeReferences(self, binary):
        references = {32: {}, 64: {}}
        base_address = self._findBaseAddress(binary)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xFF\x25", binary):
            self._updateCodeReferences(references, binary, base_address, match.start())
        # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        for match in re.finditer(b"\xFF\x15", binary):
            self._updateCodeReferences(references, binary, base_address, match.start())
        return references

    def evaluateImportTable(self, binary, is_unmapped=True):
        self._binary_length = len(binary)
        results = {"import_table": []}
        if lief:
            lief_binary = lief.parse(bytearray(binary))
            bitness = 32 if lief_binary.header.machine == lief.PE.MACHINE_TYPES.I386 else 64
            for imported_library in lief_binary.imports:
                for func in imported_library.entries:
                    if func.name:
                        results["import_table"].append((func.iat_address + self.load_offset, 0xFFFFFFFF, imported_library.name.lower() + "_0x0", func.name, bitness, True, 1, set()))
        else:
            # fallback using the old method and out own import table parser
            mapped_binary = binary
            if is_unmapped:
                LOG.debug("Mapping unmapped binary before processing")
                mapped_binary = PeTools.mapBinary(binary)
            bitness = PeTools.getBitness(mapped_binary)
            self._import_table = None
            self._parseImportTable(mapped_binary)
            references = self._getCodeReferences(mapped_binary)
            for offset, import_entry in sorted(self._import_table.items()):
                ref_count = 1
                if bitness:
                    ref_count = 1 + len(references[bitness][offset]) if offset in references[bitness] else 1
                results["import_table"].append((offset + self.load_offset, 0xFFFFFFFF, import_entry["dll_name"].lower() + "_0x0", import_entry["name"], bitness, True, ref_count, references[bitness].get(offset, set())))
        return results

    def crawl(self, binary):
        results = {}
        self._binary_length = len(binary)
        self._import_table = None
        self._parseImportTable(binary)
        self._isImportTableEntry(0)
        references = self._getCodeReferences(binary)
        for api_map_name in self.api_maps:
            recovered_apis = []
            for offset, api_address in self.iterateAllDwords(binary):
                dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address)
                if dll and api and bitness == 32:
                    ref_count = 1 + len(references[32][offset]) if offset in references[32] else 1
                    recovered_apis.append((offset + self.load_offset, api_address, dll, api, bitness, self._isImportTableEntry(offset), ref_count, references[bitness].get(offset, set())))
            if self.has_64bit:
                for offset, api_address in self.iterateAllQwords(binary):
                    dll, api, bitness = self._resolveApiByAddress(api_map_name, api_address)
                    if dll and api and bitness == 64:
                        ref_count = 1 + len(references[64][offset]) if offset in references[64] else 1
                        recovered_apis.append((offset + self.load_offset, api_address, dll, api, bitness, self._isImportTableEntry(offset), ref_count, references[bitness].get(offset, set())))
            results[api_map_name] = recovered_apis
        return results

    def _getFilteredList(self, distance, list_to_filter):
        offsets_a = [item[0] for item in list_to_filter]
        offsets_b = offsets_a[1:] + [0]
        api_distances = list(map(operator.sub, offsets_b, offsets_a))
        distance_filtered = []
        for index, api_distance in enumerate(api_distances[:-1]):
            if api_distance <= distance:
                if list_to_filter[index] not in distance_filtered:
                    distance_filtered.append(list_to_filter[index])
                if list_to_filter[index + 1] not in distance_filtered:
                    distance_filtered.append(list_to_filter[index + 1])
        return distance_filtered

    def filter(self, result, from_addr, to_addr, distance, own_image=True):
        filtered_result = {}
        for key in result:
            filtered_list = result[key]
            # filter all entries pointing into our own image
            if own_image:
                filtered_list = [item for item in filtered_list if (self.base_address > item[1] or (self.base_address + self._binary_length) < item[1])]
            if from_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] >= from_addr]
            if to_addr:
                filtered_list = [item for item in filtered_list if self.base_address + item[0] <= to_addr]
            if distance:
                if len(filtered_list) < 2:
                    filtered_list = []
                else:
                    filtered_list = self._getFilteredList(distance, filtered_list)
            filtered_result[key] = filtered_list
        return filtered_result

    def getWinApi1024Vectors(self, results):
        return self._apivector.getApiVectors(results)

    def matchVectors(self, vector_a, vector_b):
        return self._apivector.matchVectors(vector_a, vector_b)

    def matchVectorCollection(self, vector, collection_path):
        return self._apivector.matchVectorCollection(vector, collection_path)

    def getPrimaryVector(self, api_vectors):
        return sorted(api_vectors.items(), key=lambda x: x[1]["percentage"])[-1]

    def render(self, results):
        output = ""
        for api_map_name in results:
            if len(results[api_map_name]):
                result = results[api_map_name]
                output += "Results for API DB: {}\n".format(api_map_name)
                output += "{:3}: {:10}; {:18}; {:3}; {:4};{:40}; {:60}\n".format("idx", "offset", "VA", "IT?", "#ref", "DLL", "API")
                prev_offset = 0
                dlls = set()
                apis = set()
                num_references = 0
                for index, entry in enumerate(result):
                    if prev_offset and entry[0] > prev_offset + 16:
                        output += "-" * 129 + "\n"
                    dll_name = "{} ({}bit)".format(entry[2], entry[4])
                    if entry[5] is None:
                        is_in_import_table = "err"
                    else:
                        is_in_import_table = "yes" if entry[5] else "no"
                    if entry[4] == 32:
                        output += "{:3}: 0x{:08x};         0x{:08x}; {:3}; {:4}; {:40}; {:60}\n".format(index + 1, self.base_address + entry[0], entry[1], is_in_import_table, entry[6], dll_name, entry[3])
                    else:
                        output += "{:3}: 0x{:08x}; 0x{:016x}; {:3}; {:4}; {:40}; {:60}\n".format(index + 1, self.base_address + entry[0], entry[1], is_in_import_table, entry[6], dll_name, entry[3])
                    num_references += entry[6] - 1
                    prev_offset = entry[0]
                    dlls.add(entry[2])
                    apis.add(entry[3])
                output += "DLLs: {}, APIs: {}, references: {}\n".format(len(dlls), len(apis), num_references)
            else:
                output += "No results for API map: {}\n".format(api_map_name)
        return output

    def renderVectorResults(self, results):
        api_vectors = self.getWinApi1024Vectors(results)
        output = "WinApi1024 Vector Results:\n"
        for api_map_name, result in sorted(api_vectors.items()):
            output += "{}: {} / {} ({:5.2f}%) APIs covered in WinApi1024 vector.\n".format(api_map_name, result["in_api_vector"], result["num_unique_apis"], result["percentage"])
            output += "    Vector:     {}\n".format(result["vector"])
            output += "    Confidence: {}\n".format(self._apivector.getVectorConfidence(result["vector"]))
        return output

    def renderResultsVsCollection(self, results, collection_file):
        # find primary vector
        api_vectors = self.getWinApi1024Vectors(results)
        primary_vector = self.getPrimaryVector(api_vectors)
        output = "Using resulting Vector from DB \"{}\" for matching...\n".format(primary_vector[0])
        collection_result = self.matchVectorCollection(primary_vector[1]["vector"], collection_file)
        output += self.renderVectorCollectionResults(collection_result)
        return output

    def renderVectorCollectionResults(self, results, max_results=5):
        output = "WinApi1024 Vector vs Collection Results:\n"
        output += "    Vector: {}\n".format(results["vector"])
        output += "    Collection: {} ({} families, {} vectors)\n".format(results["collection_filepath"], results["families_in_collection"], results["vectors_in_collection"])
        family_width = max([len(entry[0]) for entry in results["match_results"]])
        sample_width = max([len(entry[1]) for entry in results["match_results"]])
        output += "-" * (family_width + sample_width + 5 + 6) + "\n"
        output += "Top {} family matches\n".format(max_results)
        num_results = 0
        seen_families = []
        for result in results["match_results"]:
            if num_results > max_results:
                break
            if result[0] not in seen_families:
                output += "{:{fw}} - {:{sw}} - {:.3f}\n".format(result[0], result[1], result[2], fw=family_width, sw=sample_width)
                seen_families.append(result[0])
                num_results += 1
        output += "-" * (family_width + sample_width + 5 + 6) + "\n"
        output += "Top {} individual matches\n".format(max_results)
        num_results = 0
        for result in results["match_results"]:
            if num_results > max_results:
                break
            output += "{:{fw}} - {:{sw}} - {:.3f}\n".format(result[0], result[1], result[2], fw=family_width, sw=sample_width)
            num_results += 1
        return output
