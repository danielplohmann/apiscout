#!/usr/bin/python
########################################################################
# Copyright (c) 2019
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

from apiscout.ImportTableLoader import ImportTableLoader

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class ImportTableLoaderTestSuite(unittest.TestCase):
    """Basic test cases."""
    simple_peheader = b"MZ" + b"\x00" * 0x3a + b"\x60\x00\x00\x00" + b"\x00" * 0x20 + b"PE\x00\x00"
    simple_x86 = simple_peheader + b"\x4c\x01" + b"\x00" * 0x12 + "\x0b\x01"
    simple_x64 = simple_peheader + b"\x64\x86" + b"\x00" * 0x12 + "\x0b\x02"

    def testPeParsing(self):
        loader_fail = ImportTableLoader(ImportTableLoaderTestSuite.simple_peheader)
        loader86 = ImportTableLoader(ImportTableLoaderTestSuite.simple_x86)
        loader64 = ImportTableLoader(ImportTableLoaderTestSuite.simple_x64)
        self.assertEqual(loader_fail._is_pe, False)
        self.assertEqual(loader_fail._is_64bit, False)
        self.assertEqual(loader86._is_pe, True)
        self.assertEqual(loader86._is_64bit, False)
        self.assertEqual(loader64._is_pe, True)
        self.assertEqual(loader64._is_64bit, True)

    def testImportParsing(self):
        return

if __name__ == '__main__':
    unittest.main()
