#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import json
import logging
import os
import struct
import tempfile
import unittest
from unittest import mock

from apiscout.ApiScout import ApiScout

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


class ApiScoutTestSuite(unittest.TestCase):
    """Basic test cases."""

    def testIterators(self):
        scout = ApiScout()
        result_dwords = [dword for dword in scout.iterateAllDwords(b"\x00\x00\x00\x00\x01\x02")]
        result_qwords = [dword for dword in scout.iterateAllQwords(b"\x00\x00\x00\x00\x01\x02\x00\x00\x00")]
        self.assertEqual([(0, 0), (1, 16777216), (2, 33619968)], result_dwords)
        self.assertEqual([(0, 2203318222848), (1, 8606711808)], result_qwords)

    def testCandidateSearch(self):
        """the numpy search finds the same DWORDs and QWORDs as reading every offset, across chunks and alignments"""
        from apiscout import ApiScout as scout_module
        from apiscout import numpy_search

        scout = ApiScout()
        api_map = {0x1000: ("a.dll", "A", 32), 0x7FFE0000: ("b.dll", "B", 32), 0x7FF812345678: ("c.dll", "C", 64)}
        scout.api_maps["test_map"] = api_map
        binary = bytearray(b"\x01" * 101)
        for offset, value, fmt in (
            (0, 0x1000, "<I"),
            (5, 0x7FFE0000, "<I"),
            (38, 0x7FF812345678, "<Q"),
            (97, 0x1000, "<I"),
        ):
            binary[offset : offset + struct.calcsize(fmt)] = struct.pack(fmt, value)
        binary = bytes(binary)
        expected = {
            width: [(offset, value) for offset, value in iterate(binary) if value in api_map]
            for width, iterate in ((4, scout.iterateAllDwords), (8, scout.iterateAllQwords))
        }
        self.assertEqual([0, 5, 97], [offset for offset, _ in expected[4]])
        self.assertEqual([38], [offset for offset, _ in expected[8]])
        for size in (1, 3, numpy_search.CHUNK_SIZE):
            with mock.patch.multiple(numpy_search, CHUNK_SIZE=size, BLOCK_SIZE=min(size, numpy_search.BLOCK_SIZE)):
                found = scout._findCandidates(binary, (4, 8))
            for width in (4, 8):
                self.assertEqual(expected[width], found["test_map", width])
        # a map changed after a scan is searched with its new addresses
        api_map[0x01010101] = ("d.dll", "D", 32)
        expected_dwords = [(offset, value) for offset, value in scout.iterateAllDwords(binary) if value in api_map]
        self.assertGreater(len(expected_dwords), len(expected[4]))
        self.assertEqual(expected_dwords, scout._findCandidates(binary, (4,))["test_map", 4])
        self.assertEqual([], scout._findCandidates(b"\x00\x10\x00", (4,)).get(("test_map", 4), []))
        with mock.patch.object(scout_module, "numpy_search", None):
            self.assertEqual(expected[8], scout._findCandidates(binary, (8,))["test_map", 8])

    def testCodeReferences(self):
        """calls and jumps through pointers are found by numpy and by the plain loop alike, also at the ends of the buffer"""
        from apiscout import ApiScout as scout_module

        scout = ApiScout()
        scout.setBaseAddress(0x400000)
        binary = bytearray(b"\x90" * 64)
        # call dword ptr [0x400020] at 1, jmp dword ptr [0x400020] at 8, call qword ptr [rip+0x10] at 21 (RIP + 6 is 0x1b)
        # and a jmp whose operand is cut off by the end of the buffer
        binary[1:7] = b"\xff\x15" + struct.pack("<I", 0x400020)
        binary[8:14] = b"\xff\x25" + struct.pack("<I", 0x400020)
        binary[21:27] = b"\xff\x15" + struct.pack("<i", 0x10 - 0x1B)
        binary[58:64] = b"\xff\x25" + struct.pack("<I", 0x400000 + 63)
        binary += b"\xff\x25\x01\x00\x00"
        binary = bytes(binary)
        targets = {0x20, 0x10, 63, 0}
        expected = {32: {0x20: {1, 8}, 63: {58}}, 64: {0x10: {21}}}
        self.assertEqual(expected, scout._getCodeReferences(binary, targets))
        self.assertEqual({32: {}, 64: {}}, scout._getCodeReferences(binary, set()))
        with mock.patch.object(scout_module, "numpy_search", None):
            self.assertEqual(expected, scout._getCodeReferences(binary, targets))

    def testResolveAddressCandidates(self):
        scout = ApiScout()
        scout.api_maps["test_map"] = {0x1000: ("test.dll", "TestApi", 32)}
        result_hit = ("test.dll", "TestApi", 32)
        result_miss = ("", "", "")
        self.assertEqual(result_hit, scout._resolveApiByAddress("test_map", 0x1000))
        self.assertEqual(result_miss, scout._resolveApiByAddress("test_map", 0))

    def testLoadDb(self):
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        db_path = os.path.join(this_dir, "minimal_db.json")
        scout = ApiScout(db_path)
        expected_maps = {
            "Windows 7": {
                8792746496016: ("KernelBase.dll", "WaitForSingleObjectEx", 64),
                2105895504: ("KernelBase.dll", "InterlockedIncrement", 32),
                4119: ("noversion.dll", "SomeAPI", 32),
            }
        }
        self.assertEqual(expected_maps, scout.api_maps)
        with self.assertRaises(ValueError):
            scout.loadDbFile("Error")

    def testLoadDbNamesAndCollisions(self):
        """exports without a name, repeated addresses, DLLs sharing an address and DLLs without exports"""
        db = {
            "os_name": "Test Windows",
            "dlls": {
                "32_1.0_a.dll_0x1000": {
                    "aslr_offset": 0x10,
                    "base_address": 0x1000,
                    "bitness": 32,
                    "exports": [
                        {"address": 0x10, "name": "A1", "ordinal": 1},
                        {"address": 0x20, "name": None, "ordinal": 7},
                        {"address": 0x10, "name": "A2", "ordinal": 2},
                        {"address": 0x30, "name": "None", "ordinal": 8},
                    ],
                },
                "64_1.0_B.dll_0x1000": {
                    "aslr_offset": 0x10,
                    "base_address": 0x1000,
                    "bitness": 64,
                    "exports": [{"address": 0x10, "name": "B", "ordinal": 1}],
                },
                "32_1.0_empty.dll_0x2000": {"base_address": 0x2000, "bitness": 32, "exports": []},
            },
        }
        a_entries = [
            ("a.dll_0x1000", "A1", 32),
            ("a.dll_0x1000", "None<7>", 32),
            ("a.dll_0x1000", "A2", 32),
            ("a.dll_0x1000", "None<8>", 32),
        ]
        b_entry = ("B.dll_0x1000", "B", 64)
        with tempfile.TemporaryDirectory() as directory:
            db_path = os.path.join(directory, "db.json")
            with open(db_path, "w", encoding="utf-8") as f_db:
                json.dump(db, f_db)
            scout = ApiScout()
            # both DLLs are at their own ASLR offset, which is only a note
            with self.assertLogs("apiscout.ApiScout", logging.INFO) as logs:
                scout.loadDbFile(db_path)
            self.assertEqual([], [record for record in logs.records if record.levelno >= logging.WARNING])
            self.assertEqual(
                {0x1000: b_entry, 0x1010: a_entries[1], 0x1020: a_entries[3]}, scout.api_maps["Test Windows"]
            )
            # the order of the addresses is the one of their first export
            self.assertEqual([0x1000, 0x1010, 0x1020], list(scout.api_maps["Test Windows"]))
            self.assertEqual({0x1000: a_entries[2]}, scout._other_bitness_maps["Test Windows"])
            self.assertEqual(a_entries + [b_entry], scout._export_entries["Test Windows"])
            self.assertEqual({"a.dll", "b.dll"}, scout._dll_file_names)
            self.assertTrue(scout.has_64bit)
            scout = ApiScout()
            scout.ignoreAslrOffsets(True)
            with self.assertLogs("apiscout.ApiScout", logging.WARNING):
                scout.loadDbFile(db_path)
            self.assertEqual(
                {0x1010: b_entry, 0x1020: a_entries[1], 0x1030: a_entries[3]}, scout.api_maps["Test Windows"]
            )

    def testCrawlToyData(self):
        test_binary = (
            b"\00" * 0x10 + b"\x34\x12\x00\x00" + b"\00" * 0x10 + b"\x78\x56\x00\x00\x00\x00\x00\x00" + b"\00" * 0x10
        )
        scout = ApiScout()
        scout.api_maps["test_1"] = {0x1234: ("test.dll", "TestApi", 32)}
        scout.api_maps["test_2"] = {0x5678: ("test2.dll", "TestApi2", 64)}
        scout.has_64bit = True
        results = {
            "test_2": [(36, 22136, "test2.dll", "TestApi2", 64, None, 1, set())],
            "test_1": [(16, 4660, "test.dll", "TestApi", 32, None, 1, set())],
        }
        self.assertEqual(results, scout.crawl(test_binary))

    def testCrawlRealData(self):
        test_binary = ""
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        binary_path = os.path.join(this_dir, "example_dump.bin")
        with open(binary_path, "rb") as f_in:
            test_binary = f_in.read()
        db_path = os.path.join(this_dir, "minimal_db.json")
        scout = ApiScout(db_path)
        print(scout.crawl(test_binary))
        results = {
            "Windows 7": [
                (256, 2105895504, "KernelBase.dll", "InterlockedIncrement", 32, None, 2, set([0])),
                (262, 8792746496016, "KernelBase.dll", "WaitForSingleObjectEx", 64, None, 2, set([0])),
            ]
        }
        self.assertEqual(results, scout.crawl(test_binary))

    def testFilter(self):
        scout = ApiScout()
        results = {
            "test_1": [(0x0,), (0x10,), (0x14,), (0x30,), (0x40,), (0x44,), (0x48,)],
            "test_2": [(0x0,), (0x18,), (0x1C,)],
            "test_3": [(0x0,)],
        }
        # no arguments = no filtering
        filtered = scout.filter(results, 0, 0, 0, False)
        self.assertEqual(results, filtered)
        # filtering by range:
        filtered = scout.filter(results, 0x14, 0x34, 0, False)
        expected = {"test_1": [(0x14,), (0x30,)], "test_2": [(0x18,), (0x1C,)], "test_3": []}
        self.assertEqual(expected, filtered)
        # filtering by distance:
        filtered = scout.filter(results, 0, 0, 0x4, False)
        expected = {"test_1": [(0x10,), (0x14,), (0x40,), (0x44,), (0x48,)], "test_2": [(0x18,), (0x1C,)], "test_3": []}
        self.assertEqual(expected, filtered)

    def testFilterExcludeRanges(self):
        """addresses in any of the ranges are dropped, whether the ranges are nested, overlapping, empty or in no order"""
        scout = ApiScout()
        scout.setBaseAddress(0x1000)
        results = {"test": [(offset,) for offset in range(0, 0x80, 4)]}
        ranges = [
            (0x1050, 0x1060),
            (0x1010, 0x1030),
            (0x1018, 0x1020),
            (0x102C, 0x1040),
            (0x1044, 0x1044),
            (0x1070, 0x1070),
        ]
        kept = [0x0, 0x4, 0x8, 0xC, 0x40, 0x44, 0x48, 0x4C, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x78, 0x7C]
        self.assertEqual({"test": [(offset,) for offset in kept]}, scout.filter(results, 0, 0, 0, False, ranges))
        self.assertEqual(results, scout.filter(results, 0, 0, 0, False, []))

    def testRender(self):
        scout = ApiScout()
        results = {
            "test_1": [
                (16, 0x1032, "test32.dll", "TestApi32", 32, None, 1),
                (40, 0x1064, "test64.dll", "TestApi64", 64, None, 1),
            ]
        }
        expected_hits = [
            "Results for API DB: test_1",
            "idx: offset    ; VA                ; IT?; #ref;DLL                                     ; API",
            "  1: 0x00000010;         0x00001032; err;    1; test32.dll (32bit)                      ; TestApi32",
            "---------------------------------------------------------------------------------------------------------------------------------",
            "  2: 0x00000028; 0x0000000000001064; err;    1; test64.dll (64bit)                      ; TestApi64",
            "DLLs: 2, APIs: 2",
        ]
        rendered = scout.render(results)
        print(rendered)
        for hit in expected_hits:
            self.assertTrue(hit in rendered)
        expected_no_result = "No results for API map: test_2\n"
        self.assertEqual(expected_no_result, scout.render({"test_2": []}))

    def testCodeReferences64bit(self):
        # 0x00: call qword ptr [rip + 0x3a] -> 0x40; 0x10: jmp qword ptr [rip + 0x32] -> 0x48
        # 0x20: REX.W prefixed jmp qword ptr [rip + 0x29] -> 0x50
        test_binary = bytearray(b"\x00" * 0x40)
        test_binary[0x00:0x06] = b"\xff\x15" + struct.pack("<i", 0x40 - 0x06)
        test_binary[0x10:0x16] = b"\xff\x25" + struct.pack("<i", 0x48 - 0x16)
        test_binary[0x20:0x27] = b"\x48\xff\x25" + struct.pack("<i", 0x50 - 0x27)
        test_binary += struct.pack("<QQQ", 0x7FFA55931000, 0x7FFA55932000, 0x7FFA55933000) + b"\x00" * 0x10
        scout = ApiScout()
        scout.api_maps["test"] = {
            0x7FFA55931000: ("kernel32.dll_0x180000000", "CreateFileW", 64),
            0x7FFA55932000: ("kernel32.dll_0x180000000", "WriteFile", 64),
            0x7FFA55933000: ("kernel32.dll_0x180000000", "ReadFile", 64),
        }
        scout.has_64bit = True
        expected = {
            "test": [
                (0x40, 0x7FFA55931000, "kernel32.dll_0x180000000", "CreateFileW", 64, None, 2, set([0x00])),
                (0x48, 0x7FFA55932000, "kernel32.dll_0x180000000", "WriteFile", 64, None, 2, set([0x10])),
                (0x50, 0x7FFA55933000, "kernel32.dll_0x180000000", "ReadFile", 64, None, 2, set([0x21])),
            ]
        }
        self.assertEqual(expected, scout.crawl(bytes(test_binary)))

    def testJsonOutputDllName(self):
        from apiscout import cli

        results = {
            "db": [
                (0x10, 0x71AB1000, "ws2_32.dll_0x71ab0000", "connect", 32, None, 1, set([4, 2])),
                (0x18, 0x7FFA55931000, "kernel32.dll_0x180000000", "CreateFileW", 64, None, 1, set()),
                (0x20, 0xFFFFFFFF, "msvcp120_clr0400.dll_0x0", "_Cnd_wait", 64, True, 1, set()),
            ]
        }
        json_results = cli.results_to_records(results)
        self.assertEqual(
            ["ws2_32.dll(32 bit)", "kernel32.dll(64 bit)", "msvcp120_clr0400.dll(64 bit)"],
            [entry["dll"] for entry in json_results],
        )
        self.assertEqual([2, 4], json_results[0]["references"])
        # DLL names from old DBs without base address suffix are kept as they are
        old_db_results = {"db": [(0x10, 0x71AB1000, "ws2_32.dll", "connect", 32, None, 1, set())]}
        self.assertEqual("ws2_32.dll(32 bit)", cli.results_to_records(old_db_results)[0]["dll"])
        self.assertNotIn("confidence", cli.results_to_records(old_db_results)[0])
        self.assertEqual(42, cli.results_to_records(old_db_results, {"db": {(0x10, 32): 42}})[0]["confidence"])

    def testConfidence(self):
        def hit(offset, address=None, api="Api", bitness=32, in_import_table=None, ref_count=1, dll="a.dll_0x1000"):
            return (offset, address or 0x7C000000 + offset, dll, api, bitness, in_import_table, ref_count, set())

        scout = ApiScout()
        scout.setBaseAddress(0x400000)
        results = {
            "db": [
                hit(0x100),  # isolated, aligned
                hit(0x201),  # isolated, unaligned
                hit(0x300, ref_count=2),  # a call goes through it
                hit(0x401, ref_count=2),  # unaligned, but with a call
                hit(0x500),  # IAT of four, with a gap
                hit(0x504),
                hit(0x508),
                hit(0x510),
                hit(0x600, in_import_table=True),
                hit(0x700, bitness=64),  # a QWORD next to a DWORD does not make a neighbour
                hit(0x704),
                hit(0x800, address=0x7C001234),  # the same address repeated is no table
                hit(0x808, address=0x7C001234),
                hit(0x810, address=0x7C001234),
                hit(0x900),  # a pair, 24 bytes apart is too far
                hit(0x918),
                hit(0xA00),  # a pair, 16 bytes apart
                hit(0xA10),
                hit(0xB00, bitness=64),  # 64bit pair
                hit(0xB08, bitness=64),
            ]
        }
        confidences = scout.getConfidences(results)["db"]
        scores = {offset: score for (offset, _), score in confidences.items() if offset not in (0x700, 0x704, 0xB00)}
        self.assertEqual(10, scores[0x100])
        self.assertEqual(0, scores[0x201])
        self.assertEqual(50, scores[0x300])
        self.assertEqual(25, scores[0x401])
        self.assertEqual([70] * 4, [scores[offset] for offset in (0x500, 0x504, 0x508, 0x510)])
        self.assertEqual(100, scores[0x600])
        self.assertEqual(10, confidences[(0x700, 64)])
        self.assertEqual(10, confidences[(0x704, 32)])
        self.assertEqual([10, 10, 10], [scores[offset] for offset in (0x800, 0x808, 0x810)])
        self.assertEqual([10, 10], [scores[0x900], scores[0x918]])
        self.assertEqual([40, 40], [scores[0xA00], scores[0xA10]])
        self.assertEqual(40, confidences[(0xB00, 64)])
        # the sum is cut at 100
        results = {"db": [hit(0x100, ref_count=3), hit(0x104), hit(0x108), hit(0x10C)]}
        self.assertEqual(100, scout.getConfidences(results)["db"][(0x100, 32)])

    def testConfidenceAgreement(self):
        scout = ApiScout()
        entry = (0x100, 0x7C000100, "kernel32.dll_0x7c000000", "Sleep", 32, None, 1, set())
        same = (0x100, 0x7C000100, "KERNEL32.dll_0x7c000000", "Sleep", 32, None, 1, set())
        other = (0x100, 0x7D000100, "user32.dll_0x7d000000", "MessageBoxA", 32, None, 1, set())
        confidences = scout.getConfidences({"a": [entry], "b": [same], "c": [other]})
        self.assertEqual(
            (20, 20, 10), (confidences["a"][(0x100, 32)], confidences["b"][(0x100, 32)], confidences["c"][(0x100, 32)])
        )
        self.assertEqual(10, scout.getConfidences({"a": [entry]})["a"][(0x100, 32)])

    def testFilterByConfidence(self):
        scout = ApiScout()
        iat = [(0x500 + 4 * i, 0x7C000000 + i, "a.dll_0x1000", f"Api{i}", 32, None, 1, set()) for i in range(3)]
        lone = (0x100, 0x7C001000, "a.dll_0x1000", "Lone", 32, None, 1, set())
        results = {"db": [lone, *iat], "empty": []}
        self.assertEqual(results, scout.filterByConfidence(results, 0))
        self.assertEqual({"db": iat, "empty": []}, scout.filterByConfidence(results, 11))
        self.assertEqual({"db": [], "empty": []}, scout.filterByConfidence(results, 100))
        # scores of the complete results keep the neighbours of hits that were filtered since
        confidences = scout.getConfidences(results)
        self.assertEqual({"db": iat[:1]}, {"db": scout.filterByConfidence({"db": iat[:1]}, 50, confidences)["db"]})
        self.assertEqual({"db": []}, {"db": scout.filterByConfidence({"db": iat[:1]}, 50)["db"]})

    def testConfidenceOfRealScan(self):
        """an IAT of three APIs found in a scan scores high, the hit far away from it does not"""
        scout = ApiScout()
        scout.setBaseAddress(0x1000)
        scout.api_maps["db"] = {0x7C000000 + i * 0x100: ("a.dll", f"Api{i}", 32) for i in range(4)}
        binary = bytearray(0x200)
        for offset, index in ((0x40, 0), (0x44, 1), (0x48, 2), (0x180, 3)):
            binary[offset : offset + 4] = struct.pack("<I", 0x7C000000 + index * 0x100)
        results = scout.crawl(bytes(binary))
        confidences = scout.getConfidences(results)["db"]
        self.assertEqual({(0x40, 32): 60, (0x44, 32): 60, (0x48, 32): 60, (0x180, 32): 10}, confidences)

    def testCompleteCoverage(self):
        scout = ApiScout()
        scout.setBaseAddress(0x1000)
        self.assertEqual(scout.base_address, 0x1000)


if __name__ == "__main__":
    unittest.main()
