#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
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
import struct
import os
import unittest

from apiscout.ApiScout import ApiScout

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


class ApiScoutTestSuite(unittest.TestCase):
    """Basic test cases."""

    def testIterators(self):
        scout = ApiScout()
        result_dwords = [dword for dword in scout.iterateAllDwords("\x00\x00\x00\x00\x01\x02")]
        result_qwords = [dword for dword in scout.iterateAllQwords("\x00\x00\x00\x00\x01\x02\x00\x00\x00")]
        self.assertEqual([(0, 0), (1, 16777216), (2, 33619968)], result_dwords)
        self.assertEqual([(0, 2203318222848), (1, 8606711808)], result_qwords)

    def testResolveAddressCandidates(self):
        scout = ApiScout()
        scout.api_maps["test_map"] = {0x1000: ("test.dll", "TestApi", 32)}
        result_hit = ('test.dll', 'TestApi', 32)
        result_miss = ('', '', '')
        self.assertEqual(result_hit, scout._resolveApiByAddress("test_map", 0x1000))
        self.assertEqual(result_miss, scout._resolveApiByAddress("test_map", 0))

    def testLoadDb(self):
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        db_path = os.path.join(this_dir, "minimal_db.json")
        scout = ApiScout(db_path)
        expected_maps = {u'Windows 7': {8792746496016: (u'KernelBase.dll', u'WaitForSingleObjectEx', 64), 2105895504: (u'KernelBase.dll', u'InterlockedIncrement', 32), 4119: (u'noversion.dll', u'SomeAPI', 32)}}
        self.assertEqual(expected_maps, scout.api_maps)
        with self.assertRaises(ValueError):
            scout.loadDbFile("Error")

    def testCrawlToyData(self):
        test_binary = "\00" * 0x10 + struct.pack("I", 0x1234) + "\00" * 0x10 + struct.pack("Q", 0x5678) + "\00" * 0x10
        scout = ApiScout()
        scout.api_maps["test_1"] = {0x1234: ("test.dll", "TestApi", 32)}
        scout.api_maps["test_2"] = {0x5678: ("test2.dll", "TestApi2", 64)}
        scout.has_64bit = True
        results = {'test_2': [(36, 22136, 'test2.dll', 'TestApi2', 64, None, 1)], 'test_1': [(16, 4660, 'test.dll', 'TestApi', 32, None, 1)]}
        self.assertEqual(results, scout.crawl(test_binary))

    def testCrawlRealData(self):
        test_binary = ""
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        binary_path = os.path.join(this_dir, "example_dump.bin")
        with open(binary_path, "rb") as f_in:
            test_binary = f_in.read()
        db_path = os.path.join(this_dir, "minimal_db.json")
        scout = ApiScout(db_path)
        print scout.crawl(test_binary)
        results = {u'Windows 7': [(256, 2105895504, u'KernelBase.dll', u'InterlockedIncrement', 32, None, 1), (264, 8792746496016, u'KernelBase.dll', u'WaitForSingleObjectEx', 64, None, 1)]}
        self.assertEqual(results, scout.crawl(test_binary))

    def testFilter(self):
        scout = ApiScout()
        results = {'test_1': [(0x0,), (0x10,), (0x14,), (0x30,), (0x40,), (0x44,), (0x48,)],
                   'test_2': [(0x0,), (0x18,), (0x1c,)],
                   'test_3': [(0x0,)],
                  }
        # no arguments = no filtering
        filtered = scout.filter(results, 0, 0, 0)
        self.assertEqual(results, filtered)
        # filtering by range:
        filtered = scout.filter(results, 0x14, 0x34, 0)
        expected = {'test_1': [(0x14,), (0x30,)], 'test_2': [(0x18,), (0x1c,)], 'test_3': []}
        self.assertEqual(expected, filtered)
        # filtering by distance:
        filtered = scout.filter(results, 0, 0, 0x4)
        expected = {'test_1': [(0x10,), (0x14,), (0x40,), (0x44,), (0x48,)], 'test_2': [(0x18,), (0x1c,)], 'test_3': []}
        self.assertEqual(expected, filtered)

    def testRender(self):
        scout = ApiScout()
        results = {'test_1': [(16, 0x1032, 'test32.dll', 'TestApi32', 32, None, 1), (40, 0x1064, 'test64.dll', 'TestApi64', 64, None, 1)]}
        expected_hits = ['Results for API DB: test_1',
                         'idx: offset    ; VA                ; IT?; #ref;DLL                                     ; API',
                         '  1: 0x00000010;         0x00001032; err;    1; test32.dll (32bit)                      ; TestApi32',
                         '---------------------------------------------------------------------------------------------------------------------------------',
                         '  2: 0x00000028; 0x0000000000001064; err;    1; test64.dll (64bit)                      ; TestApi64',
                         'DLLs: 2, APIs: 2']
        rendered = scout.render(results)
        print rendered
        for hit in expected_hits:
            self.assertTrue(hit in rendered)
        expected_no_result = "No results for API map: test_2\n"
        self.assertEqual(expected_no_result, scout.render({"test_2": []}))

    def testCompleteCoverage(self):
        scout = ApiScout()
        scout.setBaseAddress(0x1000)
        self.assertEqual(scout.base_address, 0x1000)


if __name__ == '__main__':
    unittest.main()
