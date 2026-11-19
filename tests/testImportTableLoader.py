#!/usr/bin/python
########################################################################
# Copyright (c) 2019
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import logging
import struct
import unittest

from apiscout.ImportTableLoader import ImportDescriptor, ImportTableLoader
from apiscout.PeTools import PeTools

LOG = logging.getLogger(__name__)


class ImportTableLoaderTestSuite(unittest.TestCase):
    """Basic test cases."""

    simple_peheader = b"MZ" + b"\x00" * 0x3A + b"\x60\x00\x00\x00" + b"\x00" * 0x20 + b"PE\x00\x00"
    simple_x86 = simple_peheader + struct.pack("<HHIIIHHH", 0x14C, 0, 0, 0, 0, 0xE0, 0, 0x10B)
    simple_x64 = simple_peheader + struct.pack("<HHIIIHHH", 0x8664, 0, 0, 0, 0, 0xF0, 0, 0x20B)

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

    def testOrdinalImports32bit(self):
        # name table at 0x20: import by ordinal (ws2_32.dll #16), import by name (hint/name at 0x60)
        buf = bytearray(b"\x00" * 0x80)
        buf[0x20:0x28] = struct.pack("<II", 0x80000010, 0x60)
        buf[0x60:0x6A] = struct.pack("<H", 0x2A) + b"connect\x00"
        descriptor = ImportDescriptor(0x40, 0x20, "ws2_32.dll", False)
        descriptor.parse(bytes(buf))
        expected = {
            0x40: {"ordinal": 16, "name": "recv", "dll_name": "ws2_32.dll"},
            0x44: {"ordinal": 0x2A, "name": "connect", "dll_name": "ws2_32.dll"},
        }
        self.assertEqual(expected, descriptor.imports)

    def testOrdinalImports64bit(self):
        # as above but with QWORD thunks, where the ordinal flag is bit 63
        buf = bytearray(b"\x00" * 0x80)
        buf[0x20:0x30] = struct.pack("<QQ", 0x8000000000000010, 0x60)
        buf[0x60:0x6A] = struct.pack("<H", 0x2A) + b"connect\x00"
        descriptor = ImportDescriptor(0x40, 0x20, "ws2_32.dll", True)
        descriptor.parse(bytes(buf))
        expected = {
            0x40: {"ordinal": 16, "name": "recv", "dll_name": "ws2_32.dll"},
            0x48: {"ordinal": 0x2A, "name": "connect", "dll_name": "ws2_32.dll"},
        }
        self.assertEqual(expected, descriptor.imports)

    def testBaseAddressFromPeHeader(self):
        # PE32: ImageBase is a DWORD at 0x34, PE32+: a QWORD at 0x30 behind the PE signature
        header_x86 = bytearray(ImportTableLoaderTestSuite.simple_x86 + b"\x00" * 0x40)
        header_x86[0x60 + 0x34 : 0x60 + 0x38] = struct.pack("<I", 0x400000)
        self.assertEqual(0x400000, PeTools.getBaseAddressFromPeHeader(bytes(header_x86)))
        for image_base in [0x140000000, 0x180000000, 0x7FF612340000, 0x400000]:
            header_x64 = bytearray(ImportTableLoaderTestSuite.simple_x64 + b"\x00" * 0x40)
            header_x64[0x60 + 0x30 : 0x60 + 0x38] = struct.pack("<Q", image_base)
            self.assertEqual(image_base, PeTools.getBaseAddressFromPeHeader(bytes(header_x64)))
        self.assertEqual(0, PeTools.getBaseAddressFromPeHeader(b"\x00" * 0x20))


if __name__ == "__main__":
    unittest.main()
