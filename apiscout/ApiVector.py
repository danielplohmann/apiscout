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

import contextlib
import logging
import math
import operator
import os
import re
from operator import and_, itemgetter, or_

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
        self._dllapi_set = set(self._dllapi_only)
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
        self._bit_chars = bytes.maketrans(bytes(range(256)), b"01" + b"x" * 254)
        self._b64_to_bits = str.maketrans({ord(char): bits for char, bits in self._base642bin.items()})

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

    @staticmethod
    def parseCollection(lines, strict=False):
        vectors = {}
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            fields = line.strip().split(";")
            if len(fields) < 5 or (strict and (len(fields) != 5 or not all(fields[:2]))):
                if strict:
                    raise ValueError(f"Invalid collection row {number}.")
                continue
            family, sample = fields[0], fields[1].strip()
            samples = vectors.setdefault(family, {})
            if sample in samples:
                if strict:
                    raise ValueError(f"Duplicate sample {family}/{sample} in the collection.")
                LOG.warning("Duplicate sample %s/%s in the collection. Using its first vector.", family, sample)
                continue
            samples[sample] = fields[4].strip()
        return vectors

    def validateCollection(self, lines):
        collection = self.parseCollection(lines, strict=True)
        if not collection:
            raise ValueError("No vectors.")
        for samples in collection.values():
            for vector in samples.values():
                self._getBitString(vector)

    def _loadCollectionData(self, collection_filepath):
        if not collection_filepath:
            return {}
        if not os.path.isfile(collection_filepath):
            raise ValueError(f"Not a file: {collection_filepath}")
        with open(collection_filepath, encoding="utf-8", errors="surrogateescape") as infile:
            return self.parseCollection(infile)

    def loadCollection(self, path):
        return self._loadCollectionData(path)

    def getWinApi1024(self):
        return self._winapi1024

    def isInWinApi1024(self, dll_name, api_name):
        """whether an API of a DLL (file name, e.g. kernel32.dll) is matched to one of the APIs of the vector"""
        return self._uniquify_api_name(dll_name, api_name) in self._dllapi_set

    def getApiVectors(self, results):
        coverage = {}
        for api_map_name, unique_apis in self._get_uniquified_results(results).items():
            api_vector = self._vectorize(unique_apis)
            in_api_vector = sum(api_vector)
            coverage[api_map_name] = {
                "vector": self.compress(api_vector),
                "num_unique_apis": len(unique_apis),
                "in_api_vector": in_api_vector,
                "percentage": 100.0 * in_api_vector / len(unique_apis) if len(unique_apis) else 0,
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
        bin_vector_string = None
        if isinstance(api_vector, list | tuple):
            # the common case, a list of 0 and 1, is much faster as bytes
            with contextlib.suppress(TypeError, ValueError):
                bin_vector_string = bytes(api_vector).translate(self._bit_chars).decode()
        if bin_vector_string is None or "x" in bin_vector_string:
            bin_vector_string = "".join([f"{bit:d}" for bit in api_vector])
        bin_vector_string += "0" * (-len(api_vector) % 6)
        uncompressed_b64 = "".join([self._bin2base64[chunk] for chunk in self._chunks(bin_vector_string, 6)])
        # runs of three or more characters are written as the character and the length of the run
        return re.sub(r"(.)\1{2,}", lambda run: f"{run[1]}{len(run[0])}", uncompressed_b64, flags=re.DOTALL)

    def decompress(self, compressed_vector):
        bits = self._getBitString(compressed_vector)
        if NUMPY_AVAILABLE:
            return self.n_decompress(compressed_vector, bits)
        return [int(bit) for bit in bits]

    def n_decompress(self, compressed_vector, bits=None):
        if bits is None:
            bits = self._getBitString(compressed_vector)
        return np.frombuffer(bits.encode("ascii"), dtype=np.uint8).astype(int) - ord("0")

    def _getBitString(self, compressed_vector):
        """decompressed vector as string of bits, raises ValueError if this is not a valid compressed vector"""
        num_chars = -(-self._getVectorLength() // 6)
        if not isinstance(compressed_vector, str) or not re.fullmatch(r"(?:\D\d*)*", compressed_vector):
            raise ValueError(f"Not a valid ApiVector: {compressed_vector!r:.64}")

        def expand(run):
            if int(run[2]) > num_chars:
                raise ValueError(f"Not a valid ApiVector: {compressed_vector[:64]}")
            return run[1] * int(run[2])

        decompressed_b64 = re.sub(r"(\D)(\d+)", expand, compressed_vector)
        bits = decompressed_b64.translate(self._b64_to_bits)
        # every character of the alphabet became 6 bits, anything else is still one character
        if len(decompressed_b64) != num_chars or len(bits) != 6 * num_chars:
            raise ValueError(f"Not a valid ApiVector: {compressed_vector[:64]}")
        return bits[: self._getVectorLength()]

    def _getVectorLength(self):
        return len(self._winapi1024) if self._winapi1024 else 1024

    def _isDecompressed(self, vector):
        return not isinstance(vector, str)

    def matchVectors(self, vector_a, vector_b):
        vector_a = self._apply_weights(self._validatedVector(vector_a))
        vector_b = self._apply_weights(self._validatedVector(vector_b))
        # calculate Jaccard index
        if NUMPY_AVAILABLE:
            maxPQ = np.sum(np.maximum(vector_a, vector_b))
            if not maxPQ:
                return 0.0
            return float(1.0 * np.sum(np.minimum(vector_a, vector_b)) / maxPQ)
        intersection_score = sum(map(and_, vector_a, vector_b))
        union_score = sum(map(or_, vector_a, vector_b))
        if union_score > 0:
            return 1.0 * intersection_score / union_score
        return 0

    def explainMatch(self, vector_a, vector_b):
        """why two vectors match: the score of matchVectors, and the APIs found in both vectors or in only one of them,
        each with its weight as used by matchVectors, heaviest first"""
        if not self._winapi1024:
            raise ValueError("The WinApi1024 definitions are needed to explain a match.")
        score = self.matchVectors(vector_a, vector_b)
        bits_a = self._getBits(vector_a)
        bits_b = self._getBits(vector_b)
        shared, only_a, only_b = [], [], []
        for index, (dll, function, _, _) in enumerate(self._winapi1024):
            entry = {"dll": dll, "api": function, "weight": int(self._vector_ranks_only[index])}
            if bits_a[index] and bits_b[index]:
                shared.append(entry)
            elif bits_a[index]:
                only_a.append(entry)
            elif bits_b[index]:
                only_b.append(entry)

        def heaviest_first(entries):
            return sorted(entries, key=lambda entry: (-entry["weight"], entry["dll"].lower(), entry["api"]))

        return {
            "score": score,
            "shared": heaviest_first(shared),
            "only_a": heaviest_first(only_a),
            "only_b": heaviest_first(only_b),
        }

    def _getBits(self, vector):
        if not self._isDecompressed(vector):
            vector = self.decompress(vector)
        bits = [int(bit) for bit in self._validatedVector(vector)]
        if len(bits) != len(self._winapi1024):
            raise ValueError(f"Not a valid ApiVector: expected {len(self._winapi1024)} bits, got {len(bits)}.")
        return bits

    def _validatedVector(self, vector):
        if isinstance(vector, str):
            return self.decompress(vector)
        try:
            if NUMPY_AVAILABLE and isinstance(vector, np.ndarray):
                if (
                    vector.shape == (self._getVectorLength(),)
                    and vector.dtype.kind in "biu"
                    and np.all((vector == 0) | (vector == 1))
                ):
                    return vector
            elif len(vector) == self._getVectorLength():
                bits = tuple(map(operator.index, vector))
                if all(bit in (0, 1) for bit in bits):
                    return bits
        except (TypeError, ValueError):
            pass
        raise ValueError(f"Not a valid ApiVector: expected {self._getVectorLength()} binary values.")

    def getCollectionVector(self, collection_filepath, family, sample):
        """the compressed ApiVector of a sample in a collection"""
        return self._loadCollectionData(collection_filepath)[family][sample]

    def matchVectorCollection(self, vector, collection_filepath):
        return self.matchLoadedCollection(vector, self.loadCollection(collection_filepath), collection_filepath)

    def matchLoadedCollection(self, vector, collection_data, collection_filepath):
        decompressed_vector = self._validatedVector(vector)
        results = {
            "vector": vector,
            "confidence": self.getVectorConfidence(decompressed_vector),
            "collection_filepath": collection_filepath,
            "families_in_collection": len(collection_data),
            "vectors_in_collection": sum([len(samples) for family, samples in collection_data.items()]),
        }
        names = [(family, sample) for family, samples in collection_data.items() for sample in samples]
        sample_vectors = [sample_vector for samples in collection_data.values() for sample_vector in samples.values()]
        scores = self._matchAll(decompressed_vector, sample_vectors)
        vector_collection_results = []
        for (family, sample), sample_vector, score in zip(names, sample_vectors, scores, strict=True):
            if score is None:
                try:
                    score = self.matchVectors(decompressed_vector, sample_vector)
                except ValueError:
                    LOG.warning("Skipping invalid ApiVector of %s / %s in collection.", family, sample)
                    continue
            vector_collection_results.append((family, sample, score))
        results["match_results"] = sorted(vector_collection_results, key=itemgetter(2), reverse=True)
        return results

    def _matchAll(self, vector, compressed_vectors):
        """the scores of matchVectors() of a vector with each of the compressed vectors, None where they are not
        computed here: the vectors that are not plain compressed vectors, or all of them for unusual weights or vectors"""
        scores = [None] * len(compressed_vectors)
        if not NUMPY_AVAILABLE or not compressed_vectors:
            return scores
        length = self._getVectorLength()
        ranks = np.asarray(self._n_vector_ranks_only)
        if ranks.shape != (length,) or ranks.dtype.kind != "i" or ranks.min() < 0 or ranks.sum() >= 2**30:
            return scores
        bits = np.asarray(vector)
        if bits.shape != (length,) or bits.dtype.kind not in "biuf" or not np.isin(bits, (0, 1)).all():
            return scores
        # The weight of the APIs of a vector, and of those it shares with the vector, is the sum over its characters
        # of a table of 64 entries per character. All weights are integers, so are the sums, and the scores are those
        # of matchVectors(). The sums are kept in one number: the shared weight above the 32 bits of the total.
        padding = -length % 6
        bit_values = (np.arange(64)[:, None] >> np.arange(5, -1, -1)) & 1
        weights = np.append(ranks, np.zeros(padding, dtype=ranks.dtype)).reshape(-1, 6)
        shared = weights * np.append(bits, np.zeros(padding, dtype=bits.dtype)).reshape(-1, 6).astype(bool)
        tables = ((shared @ bit_values.T) << 32) + weights @ bit_values.T
        # in chunks, which keep the memory in check for a very large collection
        for start in range(0, len(compressed_vectors), 32768):
            values, found = self._unpackVectors(compressed_vectors[start : start + 32768], len(tables))
            sums = np.zeros(len(values), dtype=np.int64)
            for column, table in zip(np.ascontiguousarray(values.T), tables, strict=True):
                sums += table.take(column)
            both = sums >> 32
            union = int(shared.sum()) + (sums & 0xFFFFFFFF) - both
            found_scores = np.zeros(len(both))
            np.divide(1.0 * both, union, out=found_scores, where=union != 0)
            for index, score in zip(np.flatnonzero(found).tolist(), found_scores.tolist(), strict=True):
                scores[start + index] = score
        return scores

    def _unpackVectors(self, compressed_vectors, num_chars):
        """the characters of the compressed vectors as numbers from 0 to 63, a row for each vector that is a valid
        compressed vector of ASCII characters, and a mask which of the vectors these are. Whether the others are
        valid is for decompress() to decide."""
        # characters of the alphabet are translated to their value, digits to 64 + digit, line ends to 74
        alphabet = bytearray(b"\xff" * 256)
        for char, bits in self._base642bin.items():
            alphabet[ord(char)] = int(bits, 2)
        alphabet[48:58] = range(64, 74)
        alphabet[10] = 74
        # one line per vector, with a line end before the first as well
        raw = ("\n" + "\n".join(compressed_vectors) + "\n").encode("utf-8", "surrogateescape")
        codes = np.frombuffer(raw.translate(bytes(alphabet)), np.uint8)
        others = np.flatnonzero(codes > 63)
        kinds = codes[others]
        line_ends = others[kinds == 74]
        digits = others[kinds < 74]
        # the digits after a character are the number of times it is repeated
        first = np.flatnonzero(np.diff(digits, prepend=-2) != 1)
        starts = digits[first]
        lengths = np.diff(first, append=len(digits))
        counts = np.zeros(len(starts), dtype=np.int32)
        for place in range(4):
            long_enough = lengths > place
            counts[long_enough] = counts[long_enough] * 10 + codes[starts[long_enough] + place] - 64
        # characters that are not of the alphabet, digits that do not follow one, and numbers of more than 4 digits
        misplaced = (codes[starts - 1] > 63) | (lengths > 4)
        counts[misplaced] = 0
        run_lines = np.searchsorted(line_ends, starts) - 1
        # a run of digits and its character are the number of characters long, and these many bytes
        changes = np.bincount(run_lines, counts - 1 - lengths, len(line_ends) - 1)
        found = np.diff(line_ends) - 1 + changes == num_chars
        found[np.searchsorted(line_ends, others[kinds == 255]) - 1] = False
        found[run_lines[misplaced]] = False
        repeats = (codes < 64).astype(np.int32)
        repeats[starts - 1] = np.minimum(counts, num_chars + 1)
        if not found.all():
            repeats[1:] *= np.repeat(found, np.diff(line_ends))
        return np.repeat(codes, repeats).reshape(-1, num_chars), found

    def _chunks(self, sequence, n):
        for i in range(0, len(sequence), n):
            yield sequence[i : i + n]

    def _vectorize(self, unique_apis):
        return list(map(unique_apis.__contains__, self._dllapi_only))

    def _get_uniquified_results(self, results):
        uniquified = {}
        for api_map_name, map_results in results.items():
            # imports by ordinal that could not be resolved to a name carry no information about the API
            uniquified[api_map_name] = set(
                self._uniquify_api_name(t[2].rpartition("_")[0], t[3]) for t in map_results if t[3]
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
