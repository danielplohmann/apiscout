import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import unittest

import numpy as np

from apiscout import DynamicApis
from apiscout.ApiScout import ApiScout
from apiscout.DynamicApis import ApiNameIndex, DynamicApi, _ConstantSet, _findStrings, getMinimumHits, getRegions

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REAL_DB_PATH = os.path.join(THIS_DIR, "..", "dbs", "win7_prof-n_sp1_example.json")

# Mandiant FLARE, shellcode_hashes: the definitions are the functions ror13AddHash32, crc32 and add1505Shl5Hash32 in
# https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py and these are the hashes of its database
# https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/sc_hashes.db (table symbol_hashes of the types ror13AddHash32,
# crc32 and add1505Shl5Hash32, source library kernel32.dll)
FLARE_HASHES = {
    # name: (ror13, crc32, djb2)
    b"LoadLibraryA": (0xEC0E4E8E, 0x3FC1BD8D, 0x5FBFF0FB),
    b"GetProcAddress": (0x7C0DFCAA, 0xC97C1FFF, 0xCF31BB1F),
    b"VirtualAlloc": (0x91AFCA54, 0x09CE0D4A, 0x382C0F97),
}

# Metasploit block_api, the hashes that the PEB walking stub api_call compares: the table of hashes in
# https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py (the module name is
# hashed in upper case as UTF-16LE with its terminator, the function name with its terminator, the sum of both is the hash); the
# function hash() of that script does not reproduce its own table, these definitions do
METASPLOIT_HASHES = [
    (0x006B8029, "ws2_32.dll", "WSAStartup"),
    (0xE0DF0FEA, "ws2_32.dll", "WSASocketA"),
    (0x6737DBC2, "ws2_32.dll", "bind"),
    (0xFF38E9B7, "ws2_32.dll", "listen"),
    (0xE13BEC74, "ws2_32.dll", "accept"),
    (0x614D6E75, "ws2_32.dll", "closesocket"),
    (0x6174A599, "ws2_32.dll", "connect"),
    (0x5FC8D902, "ws2_32.dll", "recv"),
    (0x5F38EBC2, "ws2_32.dll", "send"),
    (0x5BAE572D, "kernel32.dll", "WriteFile"),
    (0x4FDAF6DA, "kernel32.dll", "CreateFileA"),
    (0x13DD2ED7, "kernel32.dll", "DeleteFileA"),
    (0xE449F330, "kernel32.dll", "GetTempPathA"),
    (0x528796C6, "kernel32.dll", "CloseHandle"),
    (0x863FCC79, "kernel32.dll", "CreateProcessA"),
    (0xE553A458, "kernel32.dll", "VirtualAlloc"),
    (0x300F2F0B, "kernel32.dll", "VirtualFree"),
    (0x0726774C, "kernel32.dll", "LoadLibraryA"),
    (0x7802F749, "kernel32.dll", "GetProcAddress"),
    (0x601D8708, "kernel32.dll", "WaitForSingleObject"),
    (0x876F8B31, "kernel32.dll", "WinExec"),
    (0x9DBD95A6, "kernel32.dll", "GetVersion"),
    (0xEA320EFE, "kernel32.dll", "SetUnhandledExceptionFilter"),
    (0x56A2B5F0, "kernel32.dll", "ExitProcess"),
    (0x0A2A1DE0, "kernel32.dll", "ExitThread"),
    (0x6F721347, "ntdll.dll", "RtlExitUserThread"),
    (0x23E38427, "advapi32.dll", "RevertToSelf"),
]

# FNV-1a: pseudo code in section 2 and test vectors in Appendix C of https://www.ietf.org/archive/id/draft-eastlake-fnv-17.txt
# (draft-eastlake-fnv, Fowler, Noll, Vo, Eastlake, Hansen); the 32bit values
FNV1A_VECTORS = {b"": 0x811C9DC5, b"a": 0xE40C292C, b"foobar": 0xBF9CF968}

# djb2: the function hash() of http://www.cse.yorku.ca/~oz/hash.html (5381, then hash * 33 + c); the hashes of FLARE above are
# the values of this algorithm, and the empty string has the initial value 5381

# CRC-32 (zlib, CRC-32/ISO-HDLC): the check value of the CRC catalogue (https://reveng.sourceforge.io/crc-catalogue/17plus.htm,
# CRC-32/ISO-HDLC, not reachable from the environment this was written in) is the CRC-32 of the ASCII string 123456789
CRC32_CHECK = (b"123456789", 0xCBF43926)

DLL_BASE = 0x7C800000


def write_db(directory, dlls, name="db.json", os_name="Test OS"):
    """dlls: {"kernel32.dll": [export names]}, written as API DB; exports that are None are exports by ordinal only"""
    db = {"aslr_offsets": False, "os_name": os_name, "os_version": "1", "dlls": {}}
    base = DLL_BASE
    for dll, names in dlls.items():
        db["dlls"][f"32_1.0_{dll}_0x{base:x}"] = {
            "aslr_offset": 0,
            "base_address": base,
            "bitness": 32,
            "exports": [
                {"address": 0x1000 + 0x10 * index, "name": api_name, "ordinal": index + 1}
                for index, api_name in enumerate(names)
            ],
            "filepath": "/test/" + dll,
            "version": "1.0",
        }
        base += 0x100000
    path = os.path.join(directory, name)
    with open(path, "w") as f_db:
        json.dump(db, f_db)
    return path


TEST_DLLS = {
    "kernel32.dll": [
        "LoadLibraryA",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualProtect",
        "ExitProcess",
        "WinExec",
        "CreateFileA",
        "Sleep",
        None,
    ],
    "KernelBase.dll": ["GetProcAddress", "VirtualAlloc", "VirtualProtect", "DllMain"],
    "ws2_32.dll": ["WSAStartup", "WSASocketA", "connect", "send"],
}


def reference_hash(algorithm, name, module=None):
    name = name.encode()
    if algorithm == "block_api":
        return DynamicApis.hashBlockApi(module, name)
    return {
        "ror13": DynamicApis.hashRor13,
        "crc32": DynamicApis.hashCrc32,
        "djb2": DynamicApis.hashDjb2,
        "fnv1a": DynamicApis.hashFnv1a,
    }[algorithm](name)


def reference_search(binary, values):
    """offsets and values of all DWORDs that are one of the values, read at every offset"""
    return [
        (offset, value)
        for offset in range(len(binary) - 3)
        if (value := struct.unpack_from("<I", binary, offset)[0]) in values
    ]


def reference_strings(binary, names, unit_size, min_length):
    """whole strings of a set of names by reading units (bytes or words) of every alignment one by one"""
    found = []
    for alignment in range(unit_size):
        units = [
            int.from_bytes(binary[at : at + unit_size], "little")
            for at in range(alignment, len(binary) - unit_size + 1, unit_size)
        ]
        printable = [0x20 <= unit <= 0x7E for unit in units]
        index = 0
        while index < len(units):
            if not printable[index] or (index and printable[index - 1]):
                index += 1
                continue
            end = index
            while end < len(units) and printable[end]:
                end += 1
            name = "".join(map(chr, units[index:end]))
            if end < len(units) and units[end] == 0 and len(name) >= min_length and name in names:
                found.append((alignment + index * unit_size, name))
            index = end
    return sorted(found)


class HashValuesTestSuite(unittest.TestCase):
    def testRor13(self):
        for name, (expected, _, _) in FLARE_HASHES.items():
            self.assertEqual(expected, DynamicApis.hashRor13(name), name)
        self.assertEqual(0, DynamicApis.hashRor13(b""))
        # rotate right by 13, then add: one character is its own value, two are rotated once
        self.assertEqual(0x41, DynamicApis.hashRor13(b"A"))
        self.assertEqual((0x41 << 19) + 0x42, DynamicApis.hashRor13(b"AB"))

    def testBlockApi(self):
        for expected, module, name in METASPLOIT_HASHES:
            self.assertEqual(expected, DynamicApis.hashBlockApi(module, name.encode()), f"{module}!{name}")
        # the module name is hashed in upper case
        self.assertEqual(
            DynamicApis.hashBlockApi("kernel32.dll", b"LoadLibraryA"),
            DynamicApis.hashBlockApi("KERNEL32.DLL", b"LoadLibraryA"),
        )

    def testCrc32(self):
        self.assertEqual(CRC32_CHECK[1], DynamicApis.hashCrc32(CRC32_CHECK[0]))
        for name, (_, expected, _) in FLARE_HASHES.items():
            self.assertEqual(expected, DynamicApis.hashCrc32(name), name)

    def testDjb2(self):
        self.assertEqual(5381, DynamicApis.hashDjb2(b""))
        self.assertEqual(5381 * 33 + ord("a"), DynamicApis.hashDjb2(b"a"))
        for name, (_, _, expected) in FLARE_HASHES.items():
            self.assertEqual(expected, DynamicApis.hashDjb2(name), name)

    def testFnv1a(self):
        for text, expected in FNV1A_VECTORS.items():
            self.assertEqual(expected, DynamicApis.hashFnv1a(text), text)

    def testVectorizedHashesAreTheReferenceHashes(self):
        rng = random.Random(7)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@?$"
        names = {"a", "LoadLibraryA", "?x@@YAXXZ", "N" * 300} | {
            "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 120))) for _ in range(500)
        }
        dlls = {
            "kernel32.dll": sorted(names)[::2] + ["LoadLibraryA"],
            "WS2_32.DLL": sorted(names)[1::2] + ["LoadLibraryA"],
            "a.dll": ["LoadLibraryA"],
        }
        exports = [(f"{dll}_0x{index:x}", name, 32) for index, (dll, apis) in enumerate(dlls.items()) for name in apis]
        # a name that no hash can be computed of: ordinal only, not ASCII
        exports += [
            ("kernel32.dll_0x1", "None<5>", 32),
            ("kernel32.dll_0x1", "Straße", 32),
            ("kernel32.dll_0x1", "", 32),
        ]
        index = ApiNameIndex(exports)
        self.assertEqual(sorted(names), index.names)
        for algorithm in DynamicApis.HASH_ALGORITHMS:
            table = index.getTable(algorithm)
            self.assertEqual(sorted(table.hashes.tolist()), table.hashes.tolist())
            for row in range(len(table.hashes)):
                name, row_dlls = index.resolve(algorithm, row)
                self.assertEqual(
                    reference_hash(algorithm, name, row_dlls[0]), int(table.hashes[row]), f"{algorithm} {name}"
                )
            if algorithm == "block_api":
                # one hash for each module that exports the name
                self.assertEqual(sum(map(len, index.dlls)), len(table.hashes))
            else:
                self.assertEqual(len(index.names), len(table.hashes))
        # the DLL names lost their load addresses, once for each name
        self.assertEqual(("a.dll", "kernel32.dll", "WS2_32.DLL"), index.dlls[index.names.index("LoadLibraryA")])

    def testHashSetsInTheDllsOfADb(self):
        """real export names, with the names of all DLLs"""
        if not os.path.isfile(REAL_DB_PATH):
            self.skipTest("API DB not found")
        scout = ApiScout(REAL_DB_PATH)
        index = scout._getDynamicFinder().indexes["Microsoft Windows 7 Professional N"]
        self.assertGreater(len(index.names), 20000)
        for algorithm in DynamicApis.HASH_ALGORITHMS:
            table = index.getTable(algorithm)
            for row in np.random.default_rng(1).integers(0, len(table.hashes), 300).tolist():
                name, dlls = index.resolve(algorithm, row)
                self.assertEqual(reference_hash(algorithm, name, dlls[0]), int(table.hashes[row]))
        # the hashes of the well known APIs are among them
        names = ("LoadLibraryA", "GetProcAddress", "VirtualAlloc")
        for algorithm, position in (("ror13", 0), ("crc32", 1), ("djb2", 2)):
            hashes = set(index.getTable(algorithm).hashes.tolist())
            for name in names:
                self.assertIn(FLARE_HASHES[name.encode()][position], hashes)
        self.assertIn(0x0726774C, set(index.getTable("block_api").hashes.tolist()))


class SearchTestSuite(unittest.TestCase):
    def testConstantSearchFindsEveryOffset(self):
        rng = random.Random(3)
        values = {0x0726774C, 0xDEADBEEF, 0x00000001, 0xFFFFFFFF}
        for _ in range(40):
            binary = bytearray(rng.randbytes(rng.randint(0, 200)))
            for value in values:
                if len(binary) > 8:
                    position = rng.randint(0, len(binary) - 4)
                    binary[position : position + 4] = struct.pack("<I", value)
            binary = bytes(binary)
            expected = reference_search(binary, values)
            constants = _ConstantSet(np.array(sorted(values), dtype=np.uint32))
            for chunk_size in (1, 2, 3, 7, 1 << 22):
                offsets, found = constants.find(binary, chunk_size)
                self.assertEqual(expected, list(zip(offsets.tolist(), found.tolist(), strict=True)), chunk_size)
        # shorter than a DWORD
        self.assertEqual(0, len(_ConstantSet(np.zeros(0, dtype=np.uint32)).find(b"abcdefgh")[0]))
        for binary in (b"", b"\x4c", b"\x4c\x77\x26"):
            self.assertEqual(0, len(constants.find(binary)[0]))

    def testConstantsThatAreFillerAreDropped(self):
        constants = _ConstantSet(np.array([0x41414141, 0x0726774C], dtype=np.uint32))
        binary = b"A" * 5000 + struct.pack("<I", 0x0726774C) + b"B" * 100
        self.assertEqual(
            [(5000, 0x0726774C)], list(zip(*(a.tolist() for a in constants.find(binary, 64)), strict=True))
        )

    def testStringSearchIsWholeStringsAtAnyOffset(self):
        rng = random.Random(5)
        names = {"abc", "VirtualAlloc", "ab", "x_1"}
        for _ in range(60):
            parts = []
            for _ in range(rng.randint(0, 12)):
                text = rng.choice(["abc", "VirtualAlloc", "abcd", "ab", "x_1", "zabc", "VirtualAlloc2", "q"])
                encoded = text.encode() if rng.random() < 0.5 else text.encode("utf-16-le")
                parts.append(rng.choice([b"", b"\x00", b"\xff", b" ", b"\x00\x00", b"\x01\x02"]) + encoded)
                parts.append(rng.choice([b"\x00", b"\x00\x00", b"", b"\x00\x00\x00"]))
            binary = b"".join(parts)
            for unit_size in (1, 2):
                for min_length in (2, 3, 6):
                    expected = reference_strings(binary, names, unit_size, min_length)
                    for chunk_size in (1, 2, 5, 1 << 22):
                        self.assertEqual(
                            expected,
                            _findStrings(binary, names, unit_size, min_length, 12, chunk_size),
                            (binary, unit_size, min_length, chunk_size),
                        )

    def testStringRuns(self):
        strings = [(0, "a"), (10, "b"), (20, "c"), (200, "d"), (210, "e"), (400, "f"), (410, "f"), (420, "f")]
        # 8 character names with terminator: the next one may start up to 64 bytes behind the end of the previous
        self.assertEqual(strings[:3], DynamicApis.getStringRuns(strings, 1, 3, 64))
        self.assertEqual(strings[:5], DynamicApis.getStringRuns(strings, 1, 2, 64))
        self.assertEqual(strings, DynamicApis.getStringRuns(strings, 1, 1, 64))
        # the same name again and again is no run of different names
        self.assertEqual([], DynamicApis.getStringRuns(strings[5:], 1, 2, 64))
        self.assertEqual([], DynamicApis.getStringRuns([], 1))
        # the gap is counted from the end of the previous string with its terminator: 1 + 1 characters, gap 8
        self.assertEqual(3, len(DynamicApis.getStringRuns([(0, "a"), (10, "b"), (20, "c")], 1, 3, 8)))
        self.assertEqual([], DynamicApis.getStringRuns([(0, "a"), (11, "b"), (22, "c")], 1, 3, 8))
        # UTF-16: 2 bytes for each character
        self.assertEqual(3, len(DynamicApis.getStringRuns([(0, "a"), (14, "b"), (28, "c")], 2, 3, 10)))
        self.assertEqual([], DynamicApis.getStringRuns([(0, "a"), (15, "b"), (30, "c")], 2, 3, 10))

    def testRegions(self):
        hits = [(0, 1), (10, 2), (20, 3), (500, 4), (510, 5), (700, 6), (703, 7), (2000, 8), (2004, 8), (2008, 8)]
        # a chain needs min_hits distinct values; the hits 700 and 703 overlap, the second one is skipped
        self.assertEqual([(0, 1), (10, 2), (20, 3)], getRegions(hits, 3))
        self.assertEqual([(0, 1), (10, 2), (20, 3), (500, 4), (510, 5)], getRegions(hits, 2))
        self.assertEqual([], getRegions(hits, 4))
        # one value repeated is no region
        self.assertEqual([], getRegions([(0, 1), (4, 1), (8, 1)], 2))
        self.assertEqual([], getRegions([], 1))
        self.assertEqual([(0, 1), (128, 2)], getRegions([(0, 1), (128, 2), (257, 3)], 2))

    def testMinimumHits(self):
        # 100,000 hashes make some 24 hits of chance per MB
        self.assertAlmostEqual(24.41, DynamicApis.getExpectedChanceHits(100000, 1 << 20), places=2)
        self.assertEqual(3, getMinimumHits(100000, 1 << 20))
        self.assertEqual(3, getMinimumHits(35000, 62 << 20))
        # more hashes or larger dumps raise the number of hits needed
        self.assertGreater(getMinimumHits(2_000_000, 1 << 30), 3)
        self.assertGreaterEqual(getMinimumHits(100000, 1 << 30), getMinimumHits(100000, 1 << 20))
        self.assertEqual(2, getMinimumHits(100000, 1 << 20, floor=2, budget=1))


class DynamicApisTestSuite(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_path = write_db(self.directory.name, TEST_DLLS)
        self.scout = ApiScout(self.db_path)
        self.scout.setBaseAddress(0x400000)
        self.map_name = "Test OS"

    def buildDump(self):
        """filler that holds, at odd offsets as well: a Metasploit style call sequence, a table of ROR13 hashes, some hashes that are
        too few or too far apart, and strings"""
        rng = random.Random(11)
        dump = bytearray(rng.randbytes(0x6000))
        expected = []

        def put(offset, data):
            dump[offset : offset + len(data)] = data

        # push <hash>; call ebp, with 5 APIs of the modules kernel32 and ws2_32
        offset = 0x1001
        for module, name in (
            ("kernel32.dll", "LoadLibraryA"),
            ("ws2_32.dll", "WSAStartup"),
            ("ws2_32.dll", "WSASocketA"),
            ("ws2_32.dll", "connect"),
            ("kernel32.dll", "VirtualAlloc"),
        ):
            value = DynamicApis.hashBlockApi(module, name.encode())
            put(offset, b"\x68" + struct.pack("<I", value) + b"\xff\xd5")
            expected.append(DynamicApi(offset + 1, "hash", "block_api", value, name, (module,)))
            offset += 7
        # a table of ROR13 hashes, names that two DLLs export; the third value is a repeated one
        offset = 0x3002
        for name, dlls in (
            ("GetProcAddress", ("kernel32.dll", "KernelBase.dll")),
            ("VirtualProtect", ("kernel32.dll", "KernelBase.dll")),
            ("ExitProcess", ("kernel32.dll",)),
        ):
            value = DynamicApis.hashRor13(name.encode())
            put(offset, struct.pack("<I", value))
            expected.append(DynamicApi(offset, "hash", "ror13", value, name, dlls))
            offset += 4
        # two CRC32 hashes only
        put(0x3800, struct.pack("<I", DynamicApis.hashCrc32(b"WinExec")))
        put(0x3810, struct.pack("<I", DynamicApis.hashCrc32(b"VirtualAlloc")))
        # three djb2 hashes, but the chain is cut by distances beyond a region
        for position, name in ((0x3900, b"WinExec"), (0x3910, b"VirtualAlloc"), (0x3A00, b"connect")):
            put(position, struct.pack("<I", DynamicApis.hashDjb2(name)))
        # three FNV-1a hashes of which two are the same
        for position, name in ((0x3B00, b"WinExec"), (0x3B08, b"WinExec"), (0x3B10, b"connect")):
            put(position, struct.pack("<I", DynamicApis.hashFnv1a(name)))
        # strings in runs: ASCII names one behind the other (Sleep is too short), and UTF-16LE ones at an odd offset
        offset = 0x4001
        put(0x4000, b"\x00")
        for name, dlls in (
            ("VirtualAlloc", ("kernel32.dll", "KernelBase.dll")),
            ("Sleep", None),
            ("WSAStartup", ("ws2_32.dll",)),
            ("connect", ("ws2_32.dll",)),
        ):
            put(offset, name.encode() + b"\x00")
            if dlls:
                expected.append(DynamicApi(offset, "string", "ascii", None, name, dlls))
            offset += len(name) + 1
        offset = 0x4101
        put(0x4100, b"\xff")
        for name, dlls in (
            ("WinExec", ("kernel32.dll",)),
            ("GetProcAddress", ("kernel32.dll", "KernelBase.dll")),
            ("VirtualProtect", ("kernel32.dll", "KernelBase.dll")),
        ):
            put(offset, name.encode("utf-16-le") + b"\x00\x00")
            expected.append(DynamicApi(offset, "string", "utf16le", None, name, dlls))
            offset += 2 * len(name) + 2
        # not whole, not terminated and isolated: a name inside a longer one, without terminator, and two names that are no run
        put(0x4200, b"\x00xVirtualAlloc\x00")
        put(0x4300, b"\x00VirtualProtect\x01")
        put(0x4500, b"\x00connect\x00")
        put(0x4600, b"\x00" + "WinExec".encode("utf-16-le") + b"\x00\x00")
        # the end of the dump
        put(len(dump) - 8, b"\x00connect")
        return bytes(dump), expected

    def testFindsHashesAndStrings(self):
        dump, expected = self.buildDump()
        result = self.scout.findDynamicApis(dump)
        self.assertEqual([self.map_name], list(result))
        self.assertEqual(sorted(expected), result[self.map_name])

    def testHashesAndStringsAreOptional(self):
        dump, expected = self.buildDump()
        hashes = self.scout.findDynamicApis(dump, strings=False)[self.map_name]
        strings = self.scout.findDynamicApis(dump, hashes=False)[self.map_name]
        self.assertEqual(sorted(e for e in expected if e.kind == "hash"), hashes)
        self.assertEqual(sorted(e for e in expected if e.kind == "string"), strings)
        self.assertEqual([], self.scout.findDynamicApis(dump, hashes=False, strings=False)[self.map_name])
        only = self.scout.findDynamicApis(dump, strings=False, algorithms=("ror13",))[self.map_name]
        self.assertEqual({"ror13"}, {hit.algorithm for hit in only})
        self.assertEqual(3, len(only))

    def testMinimumNumberOfHitsAndStringLength(self):
        dump, expected = self.buildDump()
        crc = [hit for hit in self.scout.findDynamicApis(dump, min_hits=2)[self.map_name] if hit.algorithm == "crc32"]
        self.assertEqual(["VirtualAlloc", "WinExec"], sorted(hit.api for hit in crc))
        self.assertEqual(
            [], [hit for hit in self.scout.findDynamicApis(dump, min_hits=6)[self.map_name] if hit.kind == "hash"]
        )
        strings = self.scout.findDynamicApis(dump, hashes=False, min_string_length=5)[self.map_name]
        self.assertIn("Sleep", [hit.api for hit in strings])
        # names of 8 and more characters: no run of 3 is left in either encoding
        strings = self.scout.findDynamicApis(dump, hashes=False, min_string_length=8)[self.map_name]
        self.assertEqual([], strings)
        # isolated names count where a run of 1 is enough
        strings = self.scout.findDynamicApis(dump, hashes=False, min_string_run=1)[self.map_name]
        self.assertEqual({0x4501, 0x4601}, {hit.offset for hit in strings} & {0x4501, 0x4601})

    def testLoadOffsetAndTheEndOfTheDump(self):
        dump, expected = self.buildDump()
        self.scout.setLoadOffset(0x100)
        hits = self.scout.findDynamicApis(dump)[self.map_name]
        self.assertEqual([hit.offset + 0x100 for hit in sorted(expected)], [hit.offset for hit in hits])
        for dump in (b"", b"\x00", b"abc", b"\x00connect\x00"[:-1]):
            self.assertEqual({self.map_name: []}, self.scout.findDynamicApis(dump))

    def testEverythingElseWorksWithoutNumpy(self):
        """the plugins may run in a Python that has no numpy, only finding dynamic APIs needs it"""
        code = (
            "import sys; sys.modules['numpy'] = None; sys.path.insert(0, sys.argv[1]);"
            "from apiscout.ApiScout import ApiScout; scout = ApiScout(sys.argv[2]); scout.crawl(b'\\0' * 64);"
            "\ntry: scout.findDynamicApis(b'')\nexcept RuntimeError as exc: print(exc)"
        )
        completed = subprocess.run(
            [sys.executable, "-c", code, os.path.join(THIS_DIR, ".."), self.db_path], capture_output=True, text=True
        )
        self.assertEqual("Finding dynamically resolved APIs needs numpy.", completed.stdout.strip(), completed.stderr)

    def testEmptyAndOrdinalOnlyDbs(self):
        scout = ApiScout()
        self.assertEqual({}, scout.findDynamicApis(b"\x00" * 100))
        path = write_db(self.directory.name, {"x.dll": [None, None]}, "ordinals.json")
        scout.loadDbFile(path)
        self.assertEqual({"Test OS": []}, scout.findDynamicApis(b"\x00" * 100))

    def testDbsAreSearchedAtOnce(self):
        """each API DB has its own results, the hashes of both are searched together"""
        dump, expected = self.buildDump()
        path = write_db(
            self.directory.name,
            {"kernel32.dll": ["GetProcAddress", "VirtualProtect", "ExitProcess"]},
            "other.json",
            "Other OS",
        )
        self.scout.loadDbFile(path)
        result = self.scout.findDynamicApis(dump, strings=False, algorithms=("ror13",))
        self.assertEqual(["Test OS", "Other OS"], list(result))
        self.assertEqual(3, len(result["Test OS"]))
        self.assertEqual(
            [
                ("GetProcAddress", ("kernel32.dll",)),
                ("VirtualProtect", ("kernel32.dll",)),
                ("ExitProcess", ("kernel32.dll",)),
            ],
            [(hit.api, hit.dlls) for hit in result["Other OS"]],
        )
        # loading a DB again replaces the one that was searched before
        write_db(self.directory.name, {"kernel32.dll": ["ExitProcess"]}, "db.json")
        self.scout.loadDbFile(self.db_path)
        self.assertEqual([], self.scout.findDynamicApis(dump, strings=False)["Test OS"])

    def testRender(self):
        dump, _ = self.buildDump()
        text = self.scout.renderDynamicApis(self.scout.findDynamicApis(dump))
        lines = text.splitlines()
        self.assertEqual("Dynamically resolved APIs for API DB: Test OS", lines[0])
        self.assertIn("0x00401002; hash  ; block_api; 0x", lines[2])
        self.assertIn("kernel32.dll, KernelBase.dll", text)
        self.assertEqual("APIs: 9, by hash: 8, by string: 6", lines[-1])
        self.assertEqual(
            "No dynamically resolved APIs for API DB: Test OS\n", self.scout.renderDynamicApis({"Test OS": []})
        )
        # many DLLs are abbreviated
        many = {"Test OS": [DynamicApi(0, "string", "ascii", None, "Api", tuple(f"{c}.dll" for c in "abcde"))]}
        self.assertIn("a.dll, b.dll, c.dll (+2)", self.scout.renderDynamicApis(many))

    def testApiVector(self):
        dump, _ = self.buildDump()
        pointers = {self.map_name: []}
        dynamic = self.scout.findDynamicApis(dump)
        # the vector of the results of the scan does not change by itself
        self.assertEqual(
            {
                self.map_name: {
                    "vector": self.scout.getPrimaryVector({})[1]["vector"],
                    "num_unique_apis": 0,
                    "in_api_vector": 0,
                    "percentage": 0,
                }
            },
            self.scout.getWinApi1024Vectors(pointers),
        )
        combined = self.scout.addDynamicApisToResults(pointers, dynamic)
        self.assertEqual({self.map_name: []}, pointers)
        vectors = self.scout.getWinApi1024Vectors(combined)
        vector = vectors[self.map_name]
        api_vector = self.scout._apivector
        # LoadLibraryA, GetProcAddress, VirtualAlloc, ExitProcess and WinExec are in WinApi1024, WSAStartup, VirtualProtect... are not
        self.assertEqual(
            [
                "kernel32.dll!ExitProcess",
                "kernel32.dll!GetProcAddress",
                "kernel32.dll!LoadLibrary",
                "kernel32.dll!VirtualAlloc",
                "kernel32.dll!WinExec",
                "ws2_32.dll!connect",
            ],
            [
                api
                for api in api_vector.getListFromApiVector(vector["vector"])
                if api.split("!")[1]
                in ("ExitProcess", "GetProcAddress", "LoadLibrary", "VirtualAlloc", "WinExec", "connect")
            ],
        )
        self.assertEqual(vector["in_api_vector"], len(api_vector.getListFromApiVector(vector["vector"])))
        # a name that several DLLs export is one API of the vector, not one for each DLL
        rows = [row for row in combined[self.map_name] if row[3] == "GetProcAddress"]
        self.assertEqual({"kernel32.dll_0x0"}, {row[2] for row in rows})
        rows = [row for row in combined[self.map_name] if row[3] == "VirtualProtect"]
        self.assertEqual(1, len({row[2] for row in rows}))

    def testChanceHitsInRandomData(self):
        """random data holds hits by chance at the rate that the number of hashes predicts, and no region of them"""
        if not os.path.isfile(REAL_DB_PATH):
            self.skipTest("API DB not found")
        scout = ApiScout(REAL_DB_PATH)
        finder = scout._getDynamicFinder()
        index = next(iter(finder.indexes.values()))
        size = 24 << 20
        binary = np.random.default_rng(2024).integers(0, 256, size, dtype=np.uint8).tobytes()
        offsets, values = finder._getConstants(DynamicApis.HASH_ALGORITHMS).find(binary)
        expected = sum(
            DynamicApis.getExpectedChanceHits(index.getNumHashes(algorithm), size)
            for algorithm in DynamicApis.HASH_ALGORITHMS
        )
        # some 1,000 hits: the measured number is a Poisson variable with a deviation of 3%
        self.assertGreater(expected, 1000)
        self.assertAlmostEqual(1.0, len(offsets) / expected, delta=0.15)
        self.assertEqual(
            {}, {name: hits for name, hits in scout.findDynamicApis(binary, strings=False).items() if hits}
        )
        self.assertEqual({}, {name: hits for name, hits in scout.findDynamicApis(binary, hashes=False).items() if hits})
        # the model of the regions: with a gap of 4096 bytes there are about size * p * p * 4096 pairs of hits of one algorithm by chance
        # (p: share of the 32bit values that are a hash), some 25 in all; the regions in the default are 32 times smaller
        pairs = expected_pairs = 0
        for algorithm in DynamicApis.HASH_ALGORITHMS:
            table = index.getTable(algorithm)
            member = np.isin(values, table.hashes)
            hits = list(zip(offsets[member].tolist(), values[member].tolist(), strict=True))
            pairs += len(getRegions(hits, 2, gap=4096)) / 2
            probability = index.getNumHashes(algorithm) / 2**32
            expected_pairs += size * probability * probability * 4096
        self.assertGreater(expected_pairs, 20)
        self.assertAlmostEqual(1.0, pairs / expected_pairs, delta=0.5)
        self.assertEqual(3, getMinimumHits(index.getNumHashes("block_api"), size))


class DynamicCliTestSuite(unittest.TestCase):
    def testDefaultOutputIsUnchanged(self):
        from tests.testCli import DB_PATH, DUMP_PATH, run

        code, output, _ = run("scan", DUMP_PATH, "--db", DB_PATH, "--base-addr", "0x1000")
        self.assertEqual(0, code)
        # the output of the commit before --dynamic
        self.assertEqual(
            "Results for API DB: Windows 7\n"
            "idx: offset    ; VA                ; IT?; #ref;DLL                                     ; API                                                         \n"
            "  1: 0x00001100;         0x7d856a50; err;    1; KernelBase.dll (32bit)                  ; InterlockedIncrement                                        \n"
            "  2: 0x00001106; 0x000007ff38881010; err;    2; KernelBase.dll (64bit)                  ; WaitForSingleObjectEx                                       \n"
            "DLLs: 1, APIs: 2, references: 1\n"
            "\n"
            "WinApi1024 Vector Results:\n"
            "Windows 7: 0 / 2 ( 0.00%) APIs covered in WinApi1024 vector.\n"
            "    Vector:     A171\n"
            "    Confidence: 0.0\n"
            "\n",
            output,
        )
        code, output, _ = run("scan", DUMP_PATH, "--db", DB_PATH, "--base-addr", "0x1000", "--json")
        self.assertEqual(
            {
                "base_address": 4096,
                "api_dbs": [DB_PATH],
                "placed_dlls": [],
                "apis": [
                    {
                        "offset": 256,
                        "apiAddress": 2105895504,
                        "dll": "KernelBase.dll(32 bit)",
                        "api": "InterlockedIncrement",
                        "references": [],
                        "confidence": 10,
                    },
                    {
                        "offset": 262,
                        "apiAddress": 8792746496016,
                        "dll": "KernelBase.dll(64 bit)",
                        "api": "WaitForSingleObjectEx",
                        "references": [0],
                        "confidence": 25,
                    },
                ],
                "apivector": "A171",
                "apis_in_vector": 0,
            },
            json.loads(output),
        )

    def testDynamic(self):
        from tests.testCli import run

        with tempfile.TemporaryDirectory() as directory:
            db_path = write_db(directory, TEST_DLLS)
            rng = random.Random(1)
            dump = bytearray(rng.randbytes(0x400))
            offset = 0x101
            for name in ("LoadLibraryA", "GetProcAddress", "VirtualAlloc", "ExitProcess"):
                dump[offset : offset + 5] = b"\x68" + struct.pack("<I", DynamicApis.hashCrc32(name.encode()))
                offset += 6
            # a run of three names, and an isolated name
            run_of_names = b"\x00connect\x00WSAStartup\x00WSASocketA\x00"
            dump[0x300 : 0x300 + len(run_of_names)] = run_of_names
            dump[0x200:0x210] = b"\x00VirtualProtect\x00"
            dump_path = os.path.join(directory, "dump_0x00400000")
            with open(dump_path, "wb") as f_dump:
                f_dump.write(dump)
            code, plain, _ = run("scan", dump_path, "--db", db_path)
            self.assertEqual(0, code)
            self.assertNotIn("Dynamically", plain)
            self.assertNotIn("dynamic_apis", json.loads(run("scan", dump_path, "--db", db_path, "--json")[1]))
            code, output, errors = run("scan", dump_path, "--db", db_path, "--dynamic")
            self.assertEqual(0, code)
            self.assertEqual(
                ["Scanned 1024 bytes at base address 0x400000 with 17 APIs of 1 DBs."], errors.splitlines()
            )
            # the section follows the listing, the vector comes after it
            self.assertLess(
                plain.index("No results for API map"), output.index("Dynamically resolved APIs for API DB: Test OS")
            )
            self.assertLess(output.index("Dynamically resolved APIs"), output.index("WinApi1024 Vector Results"))
            self.assertIn("0x00400301; string; ascii", output)
            self.assertNotIn("VirtualProtect", output)
            self.assertIn("by hash: 4, by string: 3", output)
            document = json.loads(run("scan", dump_path, "--db", db_path, "--dynamic", "--json")[1])
            hashes = [api for api in document["dynamic_apis"] if api["type"] == "hash"]
            self.assertEqual(
                ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "ExitProcess"], [api["api"] for api in hashes]
            )
            self.assertEqual(
                {
                    "offset": 0x102,
                    "type": "hash",
                    "algorithm": "crc32",
                    "value": DynamicApis.hashCrc32(b"LoadLibraryA"),
                    "api": "LoadLibraryA",
                    "dlls": ["kernel32.dll"],
                    "api_db": "Test OS",
                },
                hashes[0],
            )
            self.assertEqual(
                {
                    "offset": 0x314,
                    "type": "string",
                    "algorithm": "ascii",
                    "value": None,
                    "api": "WSASocketA",
                    "dlls": ["ws2_32.dll"],
                    "api_db": "Test OS",
                },
                document["dynamic_apis"][-1],
            )
            # the APIs are in the vector, which is not the case without --dynamic
            plain_document = json.loads(run("scan", dump_path, "--db", db_path, "--json")[1])
            self.assertEqual(0, plain_document["apis_in_vector"])
            # 4 by hash, and connect, WSAStartup and WSASocket by name
            self.assertEqual(7, document["apis_in_vector"])
            self.assertNotEqual(plain_document["apivector"], document["apivector"])
            code, _, errors = run("scan", dump_path, "--dynamic", "--import-table")
            self.assertEqual(1, code)
            self.assertIn("can not be combined with --import-table", errors)
        self.assertIn("--dynamic", run("scan", "--help")[1])


if __name__ == "__main__":
    unittest.main()

    def testDynamicInMinidump(self):
        """ranges are searched at their addresses, the export names in the images of the DLLs are left out"""
        from tests.testCli import run
        from tests.testMinidump import build_minidump

        with tempfile.TemporaryDirectory() as directory:
            db_path = write_db(directory, TEST_DLLS)
            names = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]
            hashes = b"".join(struct.pack("<I", reference_hash("ror13", name)) for name in names)
            sample = bytes(0x100) + hashes + bytes(0x1000 - 0x100 - len(hashes))
            image = b"\x00" + b"".join(name.encode() + b"\x00" for name in names)
            image += bytes(0x1000 - len(image))
            dump_path = os.path.join(directory, "crash.dmp")
            with open(dump_path, "wb") as f_dump:
                f_dump.write(
                    build_minidump(
                        [(0x400000, sample), (DLL_BASE, image)],
                        [("C:\\Windows\\System32\\kernel32.dll", DLL_BASE, 0x1000)],
                    )
                )
            code, output, errors = run("scan", dump_path, "--db", db_path, "--dynamic", "--json")
            self.assertEqual(0, code, errors)
            found = [(api["offset"], api["type"], api["api"]) for api in json.loads(output)["dynamic_apis"]]
            self.assertEqual([(0x400100 + 4 * index, "hash", name) for index, name in enumerate(names)], found)
