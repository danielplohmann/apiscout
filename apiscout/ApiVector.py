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

import logging
import math
import os
import re
from itertools import groupby

LOG = logging.getLogger(__name__)

NUMPY_AVAILABLE = False
try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    LOG.warning("numpy/scipy not available, which could otherwise speed up matching.")


class ApiVector:
    def __init__(self, winapi1024_filepath=None, sort_vector=True):
        self._sort_vector = sort_vector
        self._winapi1024 = self._loadWinApi1024(winapi1024_filepath)
        # DLL names are matched in lower case, see _uniquify_api_name()
        self._dllapi_only = [(entry[0].lower(), entry[1]) for entry in self._winapi1024]
        # linear
        self._vector_ranks_only = [entry[3] for entry in self._winapi1024]
        self._n_vector_ranks_only = []
        if NUMPY_AVAILABLE:
            self._n_vector_ranks_only = np.array(self._vector_ranks_only)
        # equal
        # self._vector_ranks_only = [1 for entry in self._winapi1024]
        # sigmoid
        # self._vector_ranks_only = [int(100 * round((1 + math.tanh(3.0 * (rank - 512) / 1024)) / 2, 2)) for rank in self._vector_ranks_only]
        self._base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@}]^+-*/?,._"
        self._bin2base64 = {f"{i:06b}": base64char for i, base64char in enumerate(self._base64chars)}
        self._base642bin = {v: k for k, v in self._bin2base64.items()}

    def _loadWinApi1024(self, winapi1024_filepath):
        winapi1024 = []
        if winapi1024_filepath:
            if os.path.isfile(winapi1024_filepath):
                with open(winapi1024_filepath) as infile:
                    lines = [line for line in infile.readlines() if line.strip()]
                    for line in (
                        sorted(lines, key=lambda line: int(line.split(";")[3].strip()), reverse=True)
                        if self._sort_vector
                        else lines
                    ):
                        functionality = line.split(";")[0]
                        dll, function = line.split(";")[2].strip().split("!")
                        rank = int(line.split(";")[3].strip())
                        winapi1024.append((dll, function, functionality, rank))
                if len(winapi1024) != 1024:
                    LOG.warning(f"WinApi1024 file contained {len(winapi1024)} instead of 1024 api definitions.")
            else:
                LOG.error("Not a file: %s!", winapi1024_filepath)
                raise ValueError
        return winapi1024

    def _loadCollectionData(self, collection_filepath):
        vectors_by_family = {}
        if collection_filepath:
            if os.path.isfile(collection_filepath):
                with open(collection_filepath, encoding="utf-8", errors="surrogateescape") as infile:
                    for line in infile.readlines():
                        fields = line.strip().split(";")
                        if len(fields) < 5:
                            continue
                        family = fields[0]
                        sample_path = fields[1].strip()
                        compressed_api_vector = fields[4].strip()
                        if family not in vectors_by_family:
                            vectors_by_family[family] = {}
                        vectors_by_family[family][sample_path] = compressed_api_vector
            else:
                LOG.error("Not a file: %s!", collection_filepath)
                raise ValueError
        return vectors_by_family

    def getWinApi1024(self):
        return self._winapi1024

    def getApiVectors(self, results):
        unique_results = self._get_uniquified_results(results)
        api_vectors = self._vectorize(results)
        coverage = {}
        for api_map_name in unique_results:
            percentage = (
                100.0 * sum(api_vectors[api_map_name]) / len(unique_results[api_map_name])
                if len(unique_results[api_map_name])
                else 0
            )
            coverage[api_map_name] = {
                "vector": self.compress(api_vectors[api_map_name]),
                "num_unique_apis": len(unique_results[api_map_name]),
                "in_api_vector": sum(api_vectors[api_map_name]),
                "percentage": percentage,
            }
        return coverage

    def getApiVectorFromApiList(self, api_list):
        scout_format = {"user_list": []}
        for index, list_entry in enumerate(api_list):
            scout_list_entry = [
                0,  # unknown offset
                0,  # unknown api_address
                list_entry.split("!")[0] + "_stubbedBitness",
                list_entry.split("!")[1],
                index + 1,  # IAT offset
                1,  # ref count
            ]
            scout_format["user_list"].append(scout_list_entry)
        return self.getApiVectors(scout_format)

    def getListFromApiVector(self, vector):
        if not self._isDecompressed(vector):
            vector = self.decompress(vector)
        api_list = []
        for index, entry in enumerate(self._winapi1024):
            if vector[index]:
                api_list.append(f"{entry[0]}!{entry[1]}")
        return sorted(api_list)

    def getApiVectorFromApiDictionary(self, api_dict):
        scout_format = {"user_list": []}
        index = 0
        for dll_entry in api_dict:
            for api_entry in api_dict[dll_entry]:
                scout_list_entry = [
                    0,  # unknown offset
                    0,  # unknown api_address
                    dll_entry + "_stubbedBitness",
                    api_entry,
                    index + 1,  # IAT offset
                    1,  # ref count
                ]
                scout_format["user_list"].append(scout_list_entry)
                index += 1
        return self.getApiVectors(scout_format)

    def getDictionaryFromApiVector(self, vector):
        if not self._isDecompressed(vector):
            vector = self.decompress(vector)
        api_dict = {}
        for index, entry in enumerate(self._winapi1024):
            if vector[index]:
                if entry[0] not in api_dict:
                    api_dict[entry[0]] = []
                api_dict[entry[0]].append(entry[1])
        return api_dict

    def getVectorConfidence(self, vector):
        if not self._isDecompressed(vector):
            vector = self.decompress(vector)
        scores = []
        for index, entry in enumerate(self._winapi1024):
            if vector[index]:
                scores.append(entry[3])
        score = 0.0
        if sum(vector):
            # confidence is calculated based on APIs less common than top75 and total number of APIs in the vector
            score = (
                100.0
                * math.sqrt(1.0 * sum([1 for value in scores if value > 64]) / sum(vector))
                * (1.0 * min(sum(vector), 20) / 20)
            )
        return score

    def compress(self, api_vector):
        bin_vector_string = "".join([f"{bit:d}" for bit in api_vector]) + "0" * (-len(api_vector) % 6)
        uncompressed_b64 = "".join(self._bin2base64[chunk] for chunk in self._chunks(bin_vector_string, 6))
        compressed_b64 = "".join(self._compress_rep(c, r) for c, r in groupby(uncompressed_b64))
        return compressed_b64

    def decompress(self, compressed_vector):
        as_binary = [int(bit) for bit in self._getBitString(compressed_vector)]
        if NUMPY_AVAILABLE:
            return np.array(as_binary, dtype=int)
        return as_binary

    def n_decompress(self, compressed_vector):
        return np.array([int(bit) for bit in self._getBitString(compressed_vector)], dtype=int)

    def _getBitString(self, compressed_vector):
        """decompressed vector as string of bits, raises ValueError if this is not a valid compressed vector"""
        num_chars = -(-self._getVectorLength() // 6)
        if not isinstance(compressed_vector, str) or not re.fullmatch(r"(\D\d*)*", compressed_vector, re.DOTALL):
            raise ValueError(f"Not a valid ApiVector: {compressed_vector!r:.64}")
        decompressed_b64 = ""
        for char, count in self._decompress_get(compressed_vector):
            if char not in self._base642bin or len(decompressed_b64) + count > num_chars:
                raise ValueError(f"Not a valid ApiVector: {compressed_vector[:64]}")
            decompressed_b64 += char * count
        if len(decompressed_b64) != num_chars:
            raise ValueError(f"Not a valid ApiVector: {compressed_vector[:64]}")
        return "".join(self._base642bin[c] for c in decompressed_b64)[: self._getVectorLength()]

    def _getVectorLength(self):
        return len(self._winapi1024) if self._winapi1024 else 1024

    def _isDecompressed(self, vector):
        return not isinstance(vector, str)

    def matchVectors(self, vector_a, vector_b):
        # ensure binary representation and apply weights
        if not self._isDecompressed(vector_a):
            vector_a = self.decompress(vector_a)
        vector_a = self._apply_weights(vector_a)
        if not self._isDecompressed(vector_b):
            vector_b = self.decompress(vector_b)
        vector_b = self._apply_weights(vector_b)
        # calculate Jaccard index
        if NUMPY_AVAILABLE:
            maxPQ = np.sum(np.maximum(vector_a, vector_b))
            if not maxPQ:
                return 0.0
            return float(1.0 * np.sum(np.minimum(vector_a, vector_b)) / maxPQ)
        intersection_score = 0
        union_score = 0
        jaccard_index = 0
        for offset in range(len(vector_a)):
            intersection_score += vector_a[offset] & vector_b[offset]
            union_score += vector_a[offset] | vector_b[offset]
        if union_score > 0:
            jaccard_index = 1.0 * intersection_score / union_score
        return jaccard_index

    def matchVectorCollection(self, vector, collection_filepath):
        collection_data = self._loadCollectionData(collection_filepath)
        results = {
            "vector": vector,
            "confidence": self.getVectorConfidence(vector),
            "collection_filepath": collection_filepath,
            "families_in_collection": len(collection_data),
            "vectors_in_collection": sum([len(samples) for family, samples in collection_data.items()]),
        }
        vector_collection_results = []
        decompressed_vector = vector
        if not self._isDecompressed(vector):
            decompressed_vector = self.decompress(vector)
        for family, samples in collection_data.items():
            for sample, sample_vector in samples.items():
                try:
                    score = self.matchVectors(decompressed_vector, sample_vector)
                except ValueError:
                    LOG.warning("Skipping invalid ApiVector of %s / %s in collection.", family, sample)
                    continue
                vector_collection_results.append((family, sample, score))
        results["match_results"] = sorted(vector_collection_results, key=lambda tup: tup[2], reverse=True)
        return results

    def _chunks(self, sequence, n):
        for i in range(0, len(sequence), n):
            yield sequence[i : i + n]

    def _compress_rep(self, char, reps):
        size = len(list(reps))
        if size <= 2:
            return char * size
        return f"{char}{size:d}"

    def _decompress_get(self, data):
        for match in re.finditer(r"(?P<char>\D)(?P<count>\d*)", data, re.DOTALL):
            yield match.group("char"), int(match.group("count") or 1)

    def _vectorize(self, results):
        unique_results = self._get_uniquified_results(results)
        vectors = {}
        for api_map_name, unique_apis in unique_results.items():
            vectors[api_map_name] = [1 if entry in unique_apis else 0 for entry in self._dllapi_only]
        return vectors

    def _get_uniquified_results(self, results):
        uniquified = {}
        for api_map_name, map_results in results.items():
            # imports by ordinal that could not be resolved to a name carry no information about the API
            uniquified[api_map_name] = set(
                self._uniquify_api_name("_".join(t[2].split("_")[:-1]), t[3]) for t in map_results if t[3]
            )
        return uniquified

    def _uniquify_api_name(self, dll_name, api_name):
        # DLL file names differ in case across Windows versions (e.g. IPHLPAPI.DLL) and from the WinApi1024 definition (e.g. Wldap32.dll)
        dll_name = dll_name.lower()
        if dll_name.startswith("msvcr"):
            dll_name = "msvcrt.dll"
        api_name = api_name.split("@")[0]
        if api_name.endswith("A") or api_name.endswith("W"):
            api_name = api_name[:-1]
        return dll_name, api_name

    def _apply_weights(self, vector):
        if NUMPY_AVAILABLE:
            return self._n_apply_weights(vector)
        return [f1 * f2 for f1, f2 in zip(vector, self._vector_ranks_only, strict=False)]

    def _n_apply_weights(self, vector):
        return np.multiply(vector, self._n_vector_ranks_only)
