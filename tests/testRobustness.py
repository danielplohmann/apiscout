import json
import os
import struct
import sys
import tempfile
import unittest

import apiscout.ApiScout as ApiScoutModule
from apiscout.ApiQR import ApiQR
from apiscout.ApiScout import ApiScout
from apiscout.ApiVector import ApiVector
from apiscout.ImportTableLoader import ImportTableLoader
from apiscout.OrdinalHelper import OrdinalHelper
from apiscout.PeTools import PeTools
from apiscout.utility import get_string

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
WINAPI1024_PATH = os.path.join(THIS_DIR, "..", "apiscout", "data", "winapi1024v1.txt")
sys.path.insert(0, os.path.join(THIS_DIR, "..", "apiscout", "db_builder"))


def build_pe32():
    """unmapped PE32 with one section at RVA 0x1000 that imports kernel32!CreateFileW, ws2_32!#16 and ws2_32!send"""
    section = bytearray(0x200)
    # kernel32.dll uses an import name table, ws2_32.dll has none (as produced by some linkers and packers)
    struct.pack_into("<IIIII", section, 0x00, 0x1080, 0, 0, 0x1100, 0x10A0)
    struct.pack_into("<IIIII", section, 0x14, 0, 0, 0, 0x1110, 0x10C0)
    struct.pack_into("<II", section, 0x80, 0x1120, 0)
    struct.pack_into("<II", section, 0xA0, 0x1120, 0)
    struct.pack_into("<III", section, 0xC0, 0x80000010, 0x1130, 0)
    section[0x100:0x10D] = b"KERNEL32.dll\x00"
    section[0x110:0x11B] = b"WS2_32.dll\x00"
    section[0x122:0x12E] = b"CreateFileW\x00"
    section[0x132:0x137] = b"send\x00"
    header = bytearray(0x200)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional_header = 0x58
    struct.pack_into("<H", header, optional_header, 0x10B)
    struct.pack_into("<III", header, optional_header + 28, 0x400000, 0x1000, 0x200)
    struct.pack_into("<HH", header, optional_header + 40, 6, 0)
    struct.pack_into("<HH", header, optional_header + 48, 6, 0)
    struct.pack_into("<II", header, optional_header + 56, 0x2000, 0x200)
    struct.pack_into("<H", header, optional_header + 68, 3)
    struct.pack_into("<I", header, optional_header + 92, 16)
    struct.pack_into("<II", header, optional_header + 104, 0x1000, 0x3C)
    section_header = optional_header + 0xE0
    header[section_header : section_header + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", header, section_header + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", header, section_header + 36, 0x40000040)
    return bytes(header + section)


EXPECTED_IMPORTS = {
    (0x10A0, "kernel32.dll_0x0", "CreateFileW"),
    (0x10C0, "ws2_32.dll_0x0", "recv"),
    (0x10C4, "ws2_32.dll_0x0", "send"),
}


class CrawlTestSuite(unittest.TestCase):
    def _getScout(self):
        scout = ApiScout()
        scout.api_maps["test"] = {
            0x71AB1000: ("ws2_32.dll_0x71ab0000", "connect", 32),
            0x7FF000001000: ("kernel32.dll_0x7ff000000000", "Sleep", 64),
        }
        scout.has_64bit = True
        return scout

    def testOpcodeAtEndOfBuffer(self):
        scout = self._getScout()
        for tail in (b"\xff\x15", b"\xff\x25\x00", b"\xff\x15\x00\x00\x00"):
            self.assertEqual({"test": []}, scout.crawl(b"\x00" * 16 + tail))

    def testResultsAreOrderedByOffset(self):
        scout = self._getScout()
        binary = struct.pack("<Q", 0x7FF000001000) + struct.pack("<I", 0x71AB1000) + struct.pack("<Q", 0x7FF000001000)
        results = scout.crawl(binary)["test"]
        self.assertEqual([(0, 64), (8, 32), (12, 64)], [(entry[0], entry[4]) for entry in results])
        self.assertEqual(3, len(scout.filter({"test": results}, 0, 0, 8)["test"]))

    def testFilterDoesNotDependOnInputOrder(self):
        scout = ApiScout()
        entries = [(0x40,), (0x0,), (0x100,), (0x4,)]
        self.assertEqual([(0x0,), (0x4,)], scout.filter({"test": entries}, 0, 0, 0x8, False)["test"])

    def testPrimaryVectorWithoutApiDb(self):
        scout = ApiScout()
        name, vector = scout.getPrimaryVector(scout.getWinApi1024Vectors(scout.crawl(b"\x00" * 32)))
        self.assertEqual("", name)
        self.assertEqual("A171", vector["vector"])

    def testApiMapsOfSameOsDoNotReplaceEachOther(self):
        db = {
            "os_name": "Windows 10",
            "dlls": {
                "64_1.0_a.dll_0x180000000": {
                    "base_address": 0x180000000,
                    "bitness": 64,
                    "exports": [{"address": 0x1000, "name": "A", "ordinal": 1}],
                }
            },
        }
        paths = []
        for index in range(2):
            with tempfile.NamedTemporaryFile("w", suffix=f"_boot{index}.json", delete=False) as f_db:
                json.dump(db, f_db)
                paths.append(f_db.name)
        try:
            scout = ApiScout()
            for path in paths + paths[:1]:
                scout.loadDbFile(path)
            self.assertEqual(2, len(scout.api_maps))
            self.assertIn("Windows 10", scout.api_maps)
        finally:
            for path in paths:
                os.remove(path)

    def testCollectionRendering(self):
        scout = ApiScout()
        results = {
            "vector": "A171",
            "collection_filepath": "none",
            "families_in_collection": 0,
            "vectors_in_collection": 0,
            "match_results": [],
        }
        self.assertIn("nothing to match", scout.renderVectorCollectionResults(results))
        results["match_results"] = [(f"family{index}", "sample", 0.5) for index in range(10)]
        rendered = scout.renderVectorCollectionResults(results, max_results=3)
        self.assertEqual(6, rendered.count("- sample -"))


class ImportTableTestSuite(unittest.TestCase):
    def _getImports(self, results):
        return set((entry[0], entry[2], entry[3]) for entry in results["import_table"])

    def testEvaluateImportTable(self):
        self.assertEqual(EXPECTED_IMPORTS, self._getImports(ApiScout().evaluateImportTable(build_pe32())))

    def testEvaluateImportTableWithoutLief(self):
        lief = ApiScoutModule.lief
        ApiScoutModule.lief = None
        try:
            self.assertEqual(EXPECTED_IMPORTS, self._getImports(ApiScout().evaluateImportTable(build_pe32())))
        finally:
            ApiScoutModule.lief = lief

    def testEvaluateImportTableOfNonPe(self):
        self.assertEqual({"import_table": []}, ApiScout().evaluateImportTable(b"no pe file" * 20))

    def testMissingImportNameTable(self):
        imports = ImportTableLoader(PeTools.mapBinary(build_pe32())).get_import_table()
        self.assertEqual(
            {0x10A0: "CreateFileW", 0x10C0: "recv", 0x10C4: "send"},
            {offset: entry["name"] for offset, entry in imports.items()},
        )

    def testOrdinals(self):
        self.assertEqual("recv", OrdinalHelper.resolveOrdinal("WS2_32.dll", 16))
        self.assertEqual("SysAllocString", OrdinalHelper.resolveOrdinal("oleaut32.dll", 2))
        self.assertEqual("", OrdinalHelper.resolveOrdinal("unknown.dll", 2))

    def testGetString(self):
        self.assertEqual("abc", get_string(b"abc", 0))
        self.assertEqual("b", get_string(b"ab\x00c", 1))
        self.assertRaises(IndexError, get_string, b"abc", 3)


class PeToolsTestSuite(unittest.TestCase):
    def testMapBinary(self):
        pe = build_pe32()
        mapped = PeTools.mapBinary(pe)
        self.assertEqual(0x1200, len(mapped))
        self.assertEqual(pe[:0x200], mapped[:0x200])
        self.assertEqual(pe[0x200:], mapped[0x1000:])

    def testMapTruncatedBinary(self):
        mapped = PeTools.mapBinary(build_pe32()[:0x280])
        self.assertEqual(0x1200, len(mapped))
        self.assertEqual(b"\x00" * 0x180, mapped[0x1080:])

    def testMapBinaryWithOptionalHeaderOfOtherSize(self):
        pe = bytearray(build_pe32())
        # move the section table by 0x10 bytes, as given by SizeOfOptionalHeader
        section_header = 0x58 + 0xE0
        pe[section_header + 0x10 : section_header + 0x38] = pe[section_header : section_header + 0x28]
        struct.pack_into("<H", pe, 0x54, 0xF0)
        self.assertEqual(bytes(pe[0x200:]), PeTools.mapBinary(bytes(pe))[0x1000:])

    def testMapCorruptBinary(self):
        pe = bytearray(build_pe32())
        struct.pack_into("<I", pe, 0x58 + 0xE0 + 8, 0xFFFFFFF0)
        self.assertEqual(b"", PeTools.mapBinary(bytes(pe)))
        self.assertEqual(b"", PeTools.mapBinary(b"no pe file" * 20))


class VectorTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.apivector = ApiVector(WINAPI1024_PATH)
        cls.bits = [1, 0, 0, 1] * 256
        cls.compressed = cls.apivector.compress(cls.bits)

    def testRoundtrip(self):
        self.assertEqual(self.bits, [int(bit) for bit in self.apivector.decompress(self.compressed)])
        self.assertEqual(1024, len(ApiVector().decompress(self.compressed)))

    def testMatchingAcceptsAllVectorRepresentations(self):
        for vector in (self.compressed, self.bits, tuple(self.bits), self.apivector.decompress(self.compressed)):
            self.assertEqual(1.0, self.apivector.matchVectors(vector, self.compressed))
            self.assertEqual(
                self.apivector.getVectorConfidence(self.compressed), self.apivector.getVectorConfidence(vector)
            )
            self.assertEqual(
                self.apivector.getListFromApiVector(self.compressed), self.apivector.getListFromApiVector(vector)
            )

    def testMatchingEmptyVectors(self):
        self.assertEqual(0.0, self.apivector.matchVectors("A171", "A171"))

    def testUnresolvedOrdinalsAreIgnored(self):
        results = {
            "import_table": [
                (0, 0, "oleaut32.dll_0x0", "", 32, True, 1, set()),
                (4, 0, "kernel32.dll_0x0", "CreateFileW", 32, True, 1, set()),
            ]
        }
        self.assertEqual(1, self.apivector.getApiVectors(results)["import_table"]["num_unique_apis"])

    def testCollectionWithBlankLines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f_collection:
            f_collection.write(f"\nfamily;sample;1;1;{self.compressed}\n\nincomplete;line\n")
        try:
            results = self.apivector.matchVectorCollection(self.compressed, f_collection.name)
            self.assertEqual([("family", "sample", 1.0)], results["match_results"])
        finally:
            os.remove(f_collection.name)


class ApiQrTestSuite(unittest.TestCase):
    def _getApiQr(self):
        apiqr = ApiQR(WINAPI1024_PATH)
        apiqr.setVector(ApiVector(WINAPI1024_PATH).compress([1, 0, 0, 1] * 256))
        return apiqr

    def testPng(self):
        image = self._getApiQr().getPng("", scale_factor=1)
        self.assertEqual((64, 64), image.size)
        self.assertEqual("RGB", image.mode)
        # full colours of the semantic groups must not be distorted
        self.assertIn((41, 128, 185), set(image.getpixel((x, y)) for x in range(64) for y in range(64)))

    def testHtml(self):
        apiqr = self._getApiQr()
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f_html:
            pass
        try:
            apiqr.exportHtml(f_html.name, full=True)
            with open(f_html.name) as f_in:
                html = f_in.read()
            self.assertEqual(1024, html.count('class="apicell"'))
            self.assertIn(ApiVector(WINAPI1024_PATH).compress([1, 0, 0, 1] * 256), html)
        finally:
            os.remove(f_html.name)

    def testArithmetic(self):
        apiqr = self._getApiQr()
        self.assertEqual([2, 0, 0, 2], [int(value) for value in (apiqr + apiqr).vector[:4]])
        self.assertEqual([3, 0, 0, 3], [int(value) for value in (apiqr * 3).vector[:4]])
        self.assertEqual([0.5, 0, 0, 0.5], [float(value) for value in (apiqr / 2).vector[:4]])


class DatabaseBuilderTestSuite(unittest.TestCase):
    def testLoadAddresses(self):
        import DatabaseBuilder

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f_addresses:
            f_addresses.write(
                "# modules\n0x7ffb11110000 C:\\Windows\\System32\\kernel32.dll\n75990000 C:\\Windows\\SysWOW64\\kernel32.dll\n\n"
            )
        try:
            load_addresses = DatabaseBuilder.read_load_addresses(f_addresses.name)
        finally:
            os.remove(f_addresses.name)
        self.assertEqual(
            [("system32/kernel32.dll", 0x7FFB11110000), ("syswow64/kernel32.dll", 0x75990000)], load_addresses
        )
        api_db = {
            "dlls": {
                "64_kernel32.dll": {
                    "filepath": "/mnt/win/Windows/System32/kernel32.dll",
                    "base_address": 0x180000000,
                    "aslr_offset": 0,
                },
                "32_kernel32.dll": {
                    "filepath": "/mnt/win/Windows/SysWOW64/kernel32.dll",
                    "base_address": 0x68900000,
                    "aslr_offset": 0,
                },
                "64_ntdll.dll": {
                    "filepath": "/mnt/win/Windows/System32/ntdll.dll",
                    "base_address": 0x180000000,
                    "aslr_offset": 0,
                },
            }
        }
        api_db = DatabaseBuilder.DatabaseBuilder().applyLoadAddresses(api_db, load_addresses)
        self.assertTrue(api_db["aslr_offsets"])
        self.assertEqual(0x180000000 - 0x7FFB11110000, api_db["dlls"]["64_kernel32.dll"]["aslr_offset"])
        self.assertEqual(0x68900000 - 0x75990000, api_db["dlls"]["32_kernel32.dll"]["aslr_offset"])
        self.assertEqual(0, api_db["dlls"]["64_ntdll.dll"]["aslr_offset"])


if __name__ == "__main__":
    unittest.main()
