#!/usr/bin/python
########################################################################
# Copyright (c) 2018
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import contextlib
import itertools
import logging
import os
import random
import tempfile
import unittest
from unittest import mock

import apiscout
from apiscout.ApiVector import NUMPY_AVAILABLE, ApiVector

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


class ApiVectorTestSuite(unittest.TestCase):
    """Basic test cases."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.vector = ApiVector()
        cls.vector._winapi1024 = [
            ("kernel32.dll", "CreateActCtx", "execution", 928),
            ("kernel32.dll", "DeactivateActCtx", "execution", 927),
            ("kernel32.dll", "ReleaseActCtx", "execution", 922),
            ("ole32.dll", "CoCreateInstance", "execution", 105),
            ("ole32.dll", "CoCreateInstanceEx", "execution", 547),
            ("ole32.dll", "CoGetClassObject", "execution", 644),
            ("kernel32.dll", "Module32First", "execution", 445),
            ("kernel32.dll", "Module32Next", "execution", 560),
            ("advapi32.dll", "CreateService", "execution", 360),
            ("advapi32.dll", "DeleteService", "execution", 299),
        ]
        cls.vector._dllapi_only = [
            ("kernel32.dll", "CreateActCtx"),
            ("kernel32.dll", "DeactivateActCtx"),
            ("kernel32.dll", "ReleaseActCtx"),
            ("ole32.dll", "CoCreateInstance"),
            ("ole32.dll", "CoCreateInstanceEx"),
            ("ole32.dll", "CoGetClassObject"),
            ("kernel32.dll", "Module32First"),
            ("kernel32.dll", "Module32Next"),
            ("advapi32.dll", "CreateService"),
            ("advapi32.dll", "DeleteService"),
        ]
        cls.vector._vector_ranks_only = [928, 927, 922, 105, 547, 644, 445, 560, 360, 299]

    def testMatchRejectsInvalidUncompressedVectors(self):
        vector = ApiVector(os.path.join(os.path.dirname(apiscout.__file__), "data", "winapi1024v1.txt"))
        valid = [1] + [0] * 1023
        invalid = ([1], [2] + valid[1:], [0.5] + valid[1:])
        for candidate in invalid:
            with self.subTest(candidate=candidate[:2]), self.assertRaisesRegex(ValueError, "binary values"):
                vector.matchVectors(candidate, valid)
            with (
                mock.patch("apiscout.ApiVector.NUMPY_AVAILABLE", False),
                self.assertRaisesRegex(ValueError, "binary values"),
            ):
                vector.matchVectors(candidate, valid)

    def testMatchAcceptsBinaryFloats(self):
        vector = ApiVector(os.path.join(os.path.dirname(apiscout.__file__), "data", "winapi1024v1.txt"))
        ints = [1, 0, 0, 1] * 256
        floats = [float(bit) for bit in ints]
        self.assertEqual(1.0, vector.matchVectors(floats, ints))
        if NUMPY_AVAILABLE:
            import numpy

            self.assertEqual(1.0, vector.matchVectors(numpy.array(floats), ints))
        with mock.patch("apiscout.ApiVector.NUMPY_AVAILABLE", False):
            self.assertEqual(1.0, vector.matchVectors(floats, ints))

    def testListConversions(self):
        # from list to vector
        input_list = [
            "kernel32.dll!DeactivateActCtx",
            "kernel32.dll!Sleep",
            "advapi32.dll!CreateServiceA",
            "ntdll.dll!ZwAllocateVirtualMemory",
        ]
        expected = {"user_list": {"percentage": 50.0, "vector": "QI", "num_unique_apis": 4, "in_api_vector": 2}}
        result_apivector = self.vector.getApiVectorFromApiList(input_list)
        self.assertEqual(result_apivector, expected)
        # from vector to list
        expected = ["advapi32.dll!CreateService", "kernel32.dll!DeactivateActCtx"]
        result_list = self.vector.getListFromApiVector(result_apivector["user_list"]["vector"])
        self.assertEqual(result_list, expected)

    def testDictConversions(self):
        # from dict to vector
        input_dict = {
            "kernel32.dll": ["DeactivateActCtx", "Sleep"],
            "advapi32.dll": ["CreateServiceA"],
            "ntdll.dll": ["ZwAllocateVirtualMemory"],
        }
        expected = {"user_list": {"percentage": 50.0, "vector": "QI", "num_unique_apis": 4, "in_api_vector": 2}}
        result_apivector = self.vector.getApiVectorFromApiDictionary(input_dict)
        self.assertEqual(result_apivector, expected)
        # from vector to dict
        expected = {"advapi32.dll": ["CreateService"], "kernel32.dll": ["DeactivateActCtx"]}
        result_dict = self.vector.getDictionaryFromApiVector(result_apivector["user_list"]["vector"])
        self.assertEqual(result_dict, expected)

    def testDllNameCaseInsensitivity(self):
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        winapi_path = os.sep.join([this_dir, "..", "apiscout", "data", "winapi1024v1.txt"])
        apivector = ApiVector(winapi_path)
        # results as produced by ApiScout.crawl(): (offset, api_address, "<dll>_<base>", api, bitness, ...)
        lower_case = {
            "db": [
                (0, 0, "iphlpapi.dll_0x180000000", "GetAdaptersInfo", 64),
                (8, 0, "sensapi.dll_0x180000000", "IsNetworkAlive", 64),
            ]
        }
        mixed_case = {
            "db": [
                (0, 0, "IPHLPAPI.DLL_0x180000000", "GetAdaptersInfo", 64),
                (8, 0, "SensApi.dll_0x180000000", "IsNetworkAlive", 64),
            ]
        }
        expected = apivector.getApiVectors(lower_case)["db"]
        self.assertEqual(2, expected["in_api_vector"])
        self.assertEqual(expected, apivector.getApiVectors(mixed_case)["db"])
        self.assertEqual(
            ["iphlpapi.dll!GetAdaptersInfo", "sensapi.dll!IsNetworkAlive"],
            apivector.getListFromApiVector(expected["vector"]),
        )
        # WinApi1024 definitions with mixed case DLL names are matched as well, e.g. by lower case import table results
        mixed_definition = {
            "db": [
                (0, 0, "wldap32.dll_0x0", "ldap_init", 32),
                (4, 0, "Wldap32.dll_0x77000000", "ldap_search_s", 32),
                (8, 0, "GDIPLUS.DLL_0x0", "GdiplusStartup", 32),
            ]
        }
        result = apivector.getApiVectors(mixed_definition)["db"]
        self.assertEqual(3, result["in_api_vector"])
        self.assertEqual(
            ["GdiPlus.dll!GdiplusStartup", "Wldap32.dll!ldap_init", "Wldap32.dll!ldap_search_s"],
            apivector.getListFromApiVector(result["vector"]),
        )
        # the same API found via differently cased DLL names is counted once
        both = {"db": lower_case["db"] + mixed_case["db"]}
        self.assertEqual(2, apivector.getApiVectors(both)["db"]["num_unique_apis"])

    def testLoadWinApi1024Definition(self):
        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        LOG.info(f"Using module path {module_path}")
        winapi_path = os.sep.join([module_path, "data", "winapi1024v1.txt"])
        apivector = ApiVector(winapi_path)
        self.assertEqual(len(apivector._winapi1024), 1024)

    def testLoadFingerprintCollectionFile(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        collection_path = os.sep.join([PROJECT_ROOT, "dbs", "collection_example.csv"])
        apivector = ApiVector()
        loaded_vectors = apivector._loadCollectionData(collection_path)
        self.assertTrue("win.urlzone" in loaded_vectors)

    def testConfidence(self):
        # we expect a low confidence, as this value also counts absolute occurrences and our test vector only has a length of 10 entries
        vector = "QI"
        confidence = self.vector.getVectorConfidence(vector)
        self.assertEqual(confidence, 10.0)

    def testVectorCompression(self):
        apivector = ApiVector()
        for exponent in range(3, 13, 1):
            vector_length = 2**exponent
            apivector._winapi1024 = [x for x in range(vector_length)]
            random_vector = [random.randint(0, 1) for i in range(vector_length)]
            compressed = apivector.compress(random_vector)
            decompressed = apivector.decompress(compressed)
            n_decompressed = apivector.n_decompress(compressed)
            self.assertEqual(vector_length, len(decompressed))
            self.assertEqual(vector_length, len(n_decompressed))


class ExplainMatchTestSuite(unittest.TestCase):
    """explainMatch() must agree with matchVectors() and name the APIs behind the score"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        cls.apivector = ApiVector(os.sep.join([module_path, "data", "winapi1024v1.txt"]))
        collection_path = os.sep.join([module_path, "..", "dbs", "collection_example.csv"])
        collection_vectors = [
            sample_vector
            for samples in cls.apivector._loadCollectionData(collection_path).values()
            for sample_vector in samples.values()
        ]
        cls.vectors = [
            "WDBCAgBBAAgCA159",
            "WDBCABBACAgAEAAgA155",
            cls.apivector.compress([0] * 1024),
            cls.apivector.compress([1] * 1024),
            *collection_vectors,
        ]

    def bits(self, indices):
        return self.apivector.compress([1 if index in indices else 0 for index in range(1024)])

    def assertExplanationIsConsistent(self, vector_a, vector_b):
        explanation = self.apivector.explainMatch(vector_a, vector_b)
        score = self.apivector.matchVectors(vector_a, vector_b)
        self.assertEqual(score, explanation["score"])
        ranks = self.apivector._vector_ranks_only
        for key in ("shared", "only_a", "only_b"):
            weights = [entry["weight"] for entry in explanation[key]]
            self.assertEqual(sorted(weights, reverse=True), weights)
        # the weights of the APIs of both vectors make up the score: a sum over the shared ones, a union of all
        shared = sum(entry["weight"] for entry in explanation["shared"])
        union = shared + sum(entry["weight"] for entry in explanation["only_a"] + explanation["only_b"])
        if union:
            self.assertAlmostEqual(shared / union, score, places=12)
        else:
            self.assertEqual(0.0, score)
        for entry in explanation["shared"] + explanation["only_a"] + explanation["only_b"]:
            self.assertIn(entry["weight"], ranks)
        return explanation

    def testScoreEqualsMatchVectors(self):
        for vector_a, vector_b in itertools.combinations(self.vectors, 2):
            self.assertExplanationIsConsistent(vector_a, vector_b)
        for vector in self.vectors:
            self.assertExplanationIsConsistent(vector, vector)

    def testExampleVectors(self):
        explanation = self.assertExplanationIsConsistent("WDBCAgBBAAgCA159", "WDBCABBACAgAEAAgA155")
        self.assertAlmostEqual(0.572, explanation["score"], places=3)
        self.assertTrue(explanation["shared"])
        self.assertTrue(explanation["only_a"])
        self.assertTrue(explanation["only_b"])

    def testSharedAndDifferingApis(self):
        explanation = self.assertExplanationIsConsistent(self.bits({0, 1, 2}), self.bits({1, 2, 3}))
        definitions = self.apivector.getWinApi1024()
        self.assertEqual({1, 2}, self.indices(explanation["shared"], definitions))
        self.assertEqual({0}, self.indices(explanation["only_a"], definitions))
        self.assertEqual({3}, self.indices(explanation["only_b"], definitions))
        # weights are the ones matchVectors applies
        ranks = self.apivector._vector_ranks_only
        for key, index in (("shared", 1), ("shared", 2), ("only_a", 0), ("only_b", 3)):
            found = [entry for entry in explanation[key] if entry["api"] == definitions[index][1]]
            weights = [entry["weight"] for entry in found]
            self.assertEqual([ranks[index]], weights)

    def indices(self, entries, definitions):
        return {
            index for index, definition in enumerate(definitions) for entry in entries if entry["api"] == definition[1]
        }

    def testIdenticalVectors(self):
        vector = self.bits({0, 5, 900})
        explanation = self.assertExplanationIsConsistent(vector, vector)
        self.assertEqual(1.0, explanation["score"])
        self.assertEqual(3, len(explanation["shared"]))
        self.assertEqual([], explanation["only_a"] + explanation["only_b"])

    def testDisjointVectors(self):
        explanation = self.assertExplanationIsConsistent(self.bits({0, 1}), self.bits({2, 3}))
        self.assertEqual(0.0, explanation["score"])
        self.assertEqual([], explanation["shared"])
        self.assertEqual(2, len(explanation["only_a"]))
        self.assertEqual(2, len(explanation["only_b"]))

    def testEmptyVectors(self):
        empty = self.bits(set())
        explanation = self.assertExplanationIsConsistent(empty, empty)
        self.assertEqual(0.0, explanation["score"])
        self.assertEqual({"score": 0.0, "shared": [], "only_a": [], "only_b": []}, explanation)
        explanation = self.assertExplanationIsConsistent(empty, self.vectors[0])
        self.assertEqual(0.0, explanation["score"])
        self.assertEqual([], explanation["shared"])
        self.assertEqual([], explanation["only_a"])

    def testListsAndStringsAgree(self):
        vector_a, vector_b = self.vectors[0], self.vectors[1]
        from_strings = self.apivector.explainMatch(vector_a, vector_b)
        from_lists = self.apivector.explainMatch(
            self.apivector.decompress(vector_a), self.apivector.decompress(vector_b)
        )
        self.assertEqual(from_strings, from_lists)

    def testInvalidVectorsAreRejected(self):
        with self.assertRaises(ValueError):
            self.apivector.explainMatch("!!", self.vectors[0])
        with self.assertRaises(ValueError):
            self.apivector.explainMatch([1, 0, 1], [1, 0, 1])


class CollectionMatchTestSuite(unittest.TestCase):
    """matching a collection must give the scores of matchVectors() for every vector, in the order of sorted()"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        cls.apivector = ApiVector(os.sep.join([module_path, "data", "winapi1024v1.txt"]))

    def testScoresAndOrderOfMatchVectors(self):
        rnd = random.Random(1)
        compress = self.apivector.compress
        vectors = [compress([1 if rnd.random() < density else 0 for _ in range(1024)]) for density in (0, 0.02, 0.3, 1)]
        vectors += [compress([rnd.randint(0, 1)] * 100 + [rnd.randint(0, 1)] * 924) for _ in range(5)]
        arabic_indic_digits = "A\u0661\u0667\u0661"
        lines = []
        for index in range(300):
            # families repeat, as do names (the later vector wins) and vectors (equal scores keep their order)
            lines.append(f"fam{index % 7};sample{index % 250};1;1;{vectors[index % len(vectors)]}\n")
        lines += [
            "x;y;1\n",
            "bad;1;1;1;A172\n",
            "bad;2;1;1;9A171\n",
            "bad;3;1;1;A!170\n",
            f"odd;1;1;1;{arabic_indic_digits}\n",
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f_collection:
            f_collection.writelines(lines)
        try:
            collection = self.apivector._loadCollectionData(f_collection.name)
            for query in (vectors[1], vectors[2], vectors[-1], self.apivector.decompress(vectors[1])):
                expected = []
                for family, samples in collection.items():
                    for sample, sample_vector in samples.items():
                        with contextlib.suppress(ValueError):
                            expected.append((family, sample, self.apivector.matchVectors(query, sample_vector)))
                expected.sort(key=lambda entry: entry[2], reverse=True)
                results = self.apivector.matchVectorCollection(query, f_collection.name)["match_results"]
                self.assertEqual(expected, results)
                self.assertTrue(all(type(score) is float for _, _, score in results))
        finally:
            os.remove(f_collection.name)


if __name__ == "__main__":
    unittest.main()
