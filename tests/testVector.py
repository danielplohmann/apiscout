#!/usr/bin/python
########################################################################
# Copyright (c) 2018
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
import random

from apiscout.ApiVector import ApiVector
import apiscout

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


class ApiVectorTestSuite(unittest.TestCase):
    """Basic test cases."""
    
    @classmethod
    def setUpClass(cls):
        super(ApiVectorTestSuite, cls).setUpClass()
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
            ("advapi32.dll", "DeleteService", "execution", 299)
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

    def testListConversions(self):
        # from list to vector
        input_list = ["kernel32.dll!DeactivateActCtx", "kernel32.dll!Sleep", "advapi32.dll!CreateServiceA", "ntdll.dll!ZwAllocateVirtualMemory"]
        expected = {'user_list': {'percentage': 50.0, 'vector': 'QI', 'num_unique_apis': 4, 'in_api_vector': 2}}
        result_apivector = self.vector.getApiVectorFromApiList(input_list)
        self.assertEquals(result_apivector, expected)
        # from vector to list
        expected = ['advapi32.dll!CreateService', 'kernel32.dll!DeactivateActCtx']
        result_list = self.vector.getListFromApiVector(result_apivector["user_list"]["vector"])
        self.assertEquals(result_list, expected)
        
    def testDictConversions(self):
        # from dict to vector
        input_dict = {
            "kernel32.dll": ["DeactivateActCtx", "Sleep"],
            "advapi32.dll": ["CreateServiceA"],
            "ntdll.dll": ["ZwAllocateVirtualMemory"]
        }
        expected = {'user_list': {"percentage": 50.0, "vector": "QI", "num_unique_apis": 4, "in_api_vector": 2}}
        result_apivector = self.vector.getApiVectorFromApiDictionary(input_dict)
        self.assertEquals(result_apivector, expected)
        # from vector to dict
        expected =  {
            "advapi32.dll": ["CreateService"], 
            "kernel32.dll": ["DeactivateActCtx"]
        }
        result_dict = self.vector.getDictionaryFromApiVector(result_apivector["user_list"]["vector"])
        self.assertEquals(result_dict, expected)
        
    def testLoadWinApi1024Definition(self):
        module_path = os.path.dirname(os.path.realpath(apiscout.__file__))
        LOG.info("Using module path %s" % module_path)
        winapi_path = os.sep.join([module_path, "data", "winapi1024v1.txt"])
        apivector = ApiVector(winapi_path)
        self.assertEquals(len(apivector._winapi1024), 1024)
        
    def testLoadFingerprintCollectionFile(self):
        THIS_FILE_PATH = str(os.path.abspath(__file__))
        PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
        collection_path = os.sep.join([PROJECT_ROOT , "dbs", "collection_example.csv"])
        apivector = ApiVector()
        loaded_vectors = apivector._loadCollectionData(collection_path)
        self.assertTrue("win.urlzone" in loaded_vectors)
        
    def testConfidence(self):
        # we expect a low confidence, as this value also counts absolute occurrences and our test vector only has a length of 10 entries
        vector = "QI"
        confidence = self.vector.getVectorConfidence(vector)
        self.assertEquals(confidence, 10.0)

    def testVectorCompression(self):
        apivector = ApiVector()
        for exponent in range(3, 13, 1):
            vector_length = 2**exponent
            apivector._winapi1024 = [x for x in range(vector_length)]
            random_vector = [random.randint(0,1) for i in range(vector_length)]
            compressed = apivector.compress(random_vector)
            decompressed = apivector.decompress(compressed)
            n_decompressed = apivector.n_decompress(compressed)
            self.assertEqual(vector_length, len(decompressed))
            self.assertEqual(vector_length, len(n_decompressed))




if __name__ == '__main__':
    unittest.main()
