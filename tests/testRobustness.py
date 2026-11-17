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
from apiscout.ImportTableLoader import ImportDescriptor, ImportTableLoader
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
        self.assertEqual(0x1200, len(PeTools.mapBinary(bytes(pe))))
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


class HostileInputTestSuite(unittest.TestCase):
    def testTruncatedPeHeader(self):
        binary = bytearray(0x50)
        binary[0:2] = b"MZ"
        struct.pack_into("<I", binary, 0x3C, 0x40)
        binary[0x40:0x46] = b"PE\x00\x00\x4c\x01"
        self.assertEqual({}, ImportTableLoader(bytes(binary)).get_import_table())
        self.assertEqual({}, ApiScout().crawl(bytes(binary)))

    def testImportDescriptorsSharingOneThunkList(self):
        pe = bytearray(build_pe32()) + bytearray(0x8000)
        struct.pack_into("<IIII", pe, 0x58 + 0xE0 + 8, 0x8200, 0x1000, 0x8200, 0x200)
        num_thunks = 0x400
        for index in range(num_thunks):
            struct.pack_into("<I", pe, 0x200 + 0x4000 + 4 * index, 0x1120)
        num_descriptors = 0x300
        for index in range(num_descriptors):
            struct.pack_into("<IIIII", pe, 0x200 + 0x200 + 20 * index, 0x5000, 0, 0, 0x1100, 0x5000)
        struct.pack_into("<II", pe, 0x58 + 104, 0x1200, 20 * num_descriptors)
        mapped = PeTools.mapBinary(bytes(pe))
        loader = ImportTableLoader(mapped)
        parsed = []
        original_parse = ImportDescriptor.parse

        def counting_parse(self, buf, max_imports=None):
            original_parse(self, buf, max_imports)
            parsed.append(len(self.imports))

        ImportDescriptor.parse = counting_parse
        try:
            loader.get_import_table()
        finally:
            ImportDescriptor.parse = original_parse
        self.assertLessEqual(sum(parsed), len(mapped) // 4)

    def testInvalidCompressedVectors(self):
        apivector = ApiVector(WINAPI1024_PATH)
        for vector in ("A300000000", "AAAA", "A170!", "", "9A171", "A172"):
            self.assertRaises(ValueError, apivector.decompress, vector)
            self.assertRaises(ValueError, apivector.matchVectors, "A171", vector)
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f_collection:
            f_collection.write("bad;sample;1;1;A300000000\ngood;sample;1;1;A171\n")
        try:
            results = apivector.matchVectorCollection("A171", f_collection.name)
            self.assertEqual([("good", "sample", 0.0)], results["match_results"])
        finally:
            os.remove(f_collection.name)

    def testSameAddressInBothBitnesses(self):
        db = {
            "os_name": "test",
            "dlls": {
                "32_1.0_a.dll_0x400000": {
                    "base_address": 0x400000,
                    "bitness": 32,
                    "exports": [{"address": 0x1000, "name": "A32", "ordinal": 1}],
                },
                "64_1.0_a.dll_0x400000": {
                    "base_address": 0x400000,
                    "bitness": 64,
                    "exports": [{"address": 0x1000, "name": "A64", "ordinal": 1}],
                },
            },
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_db:
            json.dump(db, f_db)
        try:
            scout = ApiScout(f_db.name)
        finally:
            os.remove(f_db.name)
        results = scout.crawl(
            b"\x00" * 16 + struct.pack("<I", 0x401000) + b"\x00" * 16 + struct.pack("<Q", 0x401000) + b"\x00" * 8
        )["test"]
        self.assertEqual(
            [(16, "A32", 32), (16, "A64", 64), (36, "A32", 32), (36, "A64", 64)],
            [(entry[0], entry[3], entry[4]) for entry in results],
        )

    def testOwnImageFilterBounds(self):
        scout = ApiScout()
        scout.setBaseAddress(0x400000)
        scout.setBinaryLength(0x1000)
        entries = [(0, 0x3FFFFF), (4, 0x400000), (8, 0x400FFF), (12, 0x401000)]
        self.assertEqual([(0, 0x3FFFFF), (12, 0x401000)], scout.filter({"test": entries}, 0, 0, 0)["test"])

    def testPrimaryVectorPrefersMoreApis(self):
        vectors = {
            "good": {"vector": "", "num_unique_apis": 100, "in_api_vector": 60, "percentage": 60.0},
            "spurious": {"vector": "", "num_unique_apis": 2, "in_api_vector": 2, "percentage": 100.0},
        }
        self.assertEqual("good", ApiScout().getPrimaryVector(vectors)[0])

    def testOversizedImageIsCutToItsFileData(self):
        pe = bytearray(build_pe32())
        struct.pack_into("<I", pe, 0x58 + 0xE0 + 8, 0x20000000)
        self.assertEqual(0x1200, len(PeTools.mapBinary(bytes(pe))))
        struct.pack_into("<I", pe, 0x58 + 0xE0 + 12, 0x20000000)
        self.assertEqual(b"", PeTools.mapBinary(bytes(pe)))

    def testUpdatingFingerprintsKeepsOtherEntries(self):
        from apiscout.FingerprintCrawler import FingerprintCrawler

        crawler = FingerprintCrawler([], WINAPI1024_PATH, "/nonexistent")
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f_list:
            f_list.write("famA;a_dump;1;1;A171\nfamB;b_dump;1;1;A171\nbroken;line\n\n")
        try:
            crawler.loadIgnoreList(f_list.name)
            merged = crawler.mergeWithIgnoreList([("famB", "b_dump", 2, 2, "A171"), ("famC", "c_dump", 3, 3, "A171")])
            crawler.persistFingerprintsToFile(merged, f_list.name)
            with open(f_list.name) as f_in:
                lines = f_in.read().splitlines()
        finally:
            os.remove(f_list.name)
        self.assertEqual(["famA;a_dump;1;1;A171", "famB;b_dump;2;2;A171", "famC;c_dump;3;3;A171"], lines)


class SecondAuditTestSuite(unittest.TestCase):
    def testOrdinalTables(self):
        # wsock32.dll numbers some APIs differently than ws2_32.dll, oleaut32.dll differs between 32 and 64bit
        self.assertEqual("inet_addr", OrdinalHelper.resolveOrdinal("wsock32.dll", 10))
        self.assertEqual("htons", OrdinalHelper.resolveOrdinal("ws2_32.dll", 9, 64))
        self.assertEqual("DllCanUnloadNow", OrdinalHelper.resolveOrdinal("oleaut32.dll", 144))
        self.assertEqual("BSTR_UserFree64", OrdinalHelper.resolveOrdinal("oleaut32.dll", 144, 64))
        self.assertEqual("", OrdinalHelper.resolveOrdinal("ws2_32.dll", 24))

    def testImportTableReferences(self):
        pe = bytearray(build_pe32())
        # call dword ptr [0x4010A0] in the headers' slack space references the IAT slot of CreateFileW
        pe[0x180:0x186] = b"\xff\x15" + struct.pack("<I", 0x4010A0)
        for lief in (ApiScoutModule.lief, None):
            original = ApiScoutModule.lief
            ApiScoutModule.lief = lief
            try:
                entries = {entry[3]: entry for entry in ApiScout().evaluateImportTable(bytes(pe))["import_table"]}
            finally:
                ApiScoutModule.lief = original
            self.assertEqual((2, {0x180}), entries["CreateFileW"][6:8])
            self.assertEqual((1, set()), entries["send"][6:8])

    def testImportTableOfMappedImage(self):
        mapped = PeTools.mapBinary(build_pe32())
        imports = set(
            (entry[0], entry[2], entry[3]) for entry in ApiScout().evaluateImportTable(mapped, False)["import_table"]
        )
        self.assertEqual(EXPECTED_IMPORTS, imports)

    def testApiQrHtmlAfterArithmetic(self):
        apiqr = ApiQR(WINAPI1024_PATH)
        apiqr.setVector(ApiVector(WINAPI1024_PATH).compress([1, 0, 0, 1] * 256))
        with tempfile.TemporaryDirectory() as directory:
            for index, combined in enumerate((apiqr + apiqr, apiqr / 2)):
                path = os.path.join(directory, f"{index}.html")
                combined.exportHtml(path, full=True)
                self.assertGreater(os.path.getsize(path), 0)

    def testRenderSeparatesBlockAtOffsetZero(self):
        scout = ApiScout()
        entries = [(offset, 0x1000, "a.dll_0x0", "Api", 32, False, 1, set()) for offset in (0, 0x100)]
        self.assertEqual(1, scout.render({"test": entries}).count("-" * 129))

    def testFingerprintPersistence(self):
        from apiscout.FingerprintCrawler import FingerprintCrawler

        crawler = FingerprintCrawler([], WINAPI1024_PATH, "/root")
        self.assertEqual(("fam", "a_b_dump"), crawler._getFamilyAndPath("/root/fam/a;b_dump"))
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "real.csv")
            link = os.path.join(directory, "link.csv")
            with open(target, "w") as f_target:
                f_target.write("old\n")
            os.symlink(target, link)
            crawler.persistFingerprintsToFile([("fam", "sample", 1, 1, "A171")], link)
            self.assertTrue(os.path.islink(link))
            with open(target) as f_target:
                self.assertEqual("fam;sample;1;1;A171\n", f_target.read())
            self.assertEqual(["link.csv", "real.csv"], sorted(os.listdir(directory)))

    def testLoadAddressFiles(self):
        import DatabaseBuilder

        content = (
            '0x7ffb11110000 "C:\\Windows\\System32\\kernel32.dll"\r\n75990000 C:\\Windows\\SysWOW64\\kernel32.dll\r\n'
        )
        expected = [("system32/kernel32.dll", 0x7FFB11110000), ("syswow64/kernel32.dll", 0x75990000)]
        with tempfile.TemporaryDirectory() as directory:
            for encoding in ("utf-8", "utf-8-sig", "utf-16"):
                path = os.path.join(directory, encoding)
                with open(path, "w", encoding=encoding, newline="") as f_addresses:
                    f_addresses.write(content)
                self.assertEqual(expected, DatabaseBuilder.read_load_addresses(path))
        self.assertEqual(
            "system32/kernel32.dll", DatabaseBuilder.normalize_dll_path("/mnt/Windows/System32//kernel32.dll")
        )
        builder = DatabaseBuilder.DatabaseBuilder()
        # the copy in WinSxS was found first, the copy in System32 is the one the load address is known for
        builder._duplicate_paths["key"] = ["/mnt/Windows/System32/kernel32.dll"]
        api_db = {
            "dlls": {
                "key": {
                    "filepath": "/mnt/Windows/WinSxS/amd64_x/kernel32.dll",
                    "base_address": 0x180000000,
                    "aslr_offset": 0,
                }
            }
        }
        builder.applyLoadAddresses(api_db, expected)
        self.assertEqual(0x180000000 - 0x7FFB11110000, api_db["dlls"]["key"]["aslr_offset"])


class ThirdAuditTestSuite(unittest.TestCase):
    def testLongStringsAreCutOff(self):
        self.assertEqual(512, len(get_string(b"A" * 100000, 0)))
        self.assertEqual("name", get_string(b"name\x00" + b"A" * 100, 0))

    def testFingerprintKeysDoNotCollide(self):
        from apiscout.FingerprintCrawler import FingerprintCrawler

        crawler = FingerprintCrawler([], WINAPI1024_PATH, "/x")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "list.csv")
            with open(path, "w") as f_list:
                f_list.write("a_b;c_dump;0;0;A171\na;b_c_dump;1;1;A171\n")
            os.chmod(path, 0o644)
            crawler.loadIgnoreList(path)
            self.assertEqual(("a_b", "c_dump", "0", "0", "A171"), crawler.getFingerprint("/x/a_b/c_dump"))
            self.assertEqual(2, len(crawler.mergeWithIgnoreList([])))
            crawler.persistFingerprintsToFile(crawler.mergeWithIgnoreList([]), path)
            self.assertEqual(0o644, os.stat(path).st_mode & 0o777)

    def testEntriesAtOneOffsetAreNoNeighbours(self):
        entries = [(64, 0x401356, "a.dll", "A", 32), (64, 0x401356, "a.dll", "A", 64), (0x200, 1, "b.dll", "B", 32)]
        self.assertEqual([], ApiScout._getFilteredList(32, entries))
        self.assertEqual(
            3,
            len(ApiScout._getFilteredList(32, entries + [(72, 2, "c.dll", "C", 32), (0x204, 3, "d.dll", "D", 32)])) - 2,
        )

    def testOrdinalsThatChangedInNewerWindowsVersions(self):
        self.assertEqual("", OrdinalHelper.resolveOrdinal("ws2_32.dll", 168))
        self.assertEqual("recv", OrdinalHelper.resolveOrdinal("ws2_32.dll", 16, 64))

    def testUnnamedOrdinalImportsAreLeftOutByBothParsers(self):
        pe = bytearray(build_pe32())
        struct.pack_into("<I", pe, 0x200 + 0xC0, 0x80000BB8)
        for lief in (ApiScoutModule.lief, None):
            original = ApiScoutModule.lief
            ApiScoutModule.lief = lief
            try:
                names = sorted(entry[3] for entry in ApiScout().evaluateImportTable(bytes(pe))["import_table"])
            finally:
                ApiScoutModule.lief = original
            self.assertEqual(["CreateFileW", "send"], names)

    def testImageWithLargeUninitializedSection(self):
        pe = bytearray(build_pe32())
        struct.pack_into("<I", pe, 0x58 + 0xE0 + 8, 0x800000)
        mapped = PeTools.mapBinary(bytes(pe))
        self.assertEqual(0x1200, len(mapped))
        self.assertEqual(3, len(ImportTableLoader(mapped).get_import_table()))


class FourthAuditTestSuite(unittest.TestCase):
    def testImportBudgetFollowsTheFileSize(self):
        pe = bytearray(build_pe32()) + bytearray(0x800)
        struct.pack_into("<IIII", pe, 0x58 + 0xE0 + 8, 0xA00, 0x1000, 0xA00, 0x200)
        # many descriptors sharing one long thunk list, as a crafted file would have
        for index in range(0x40):
            struct.pack_into("<I", pe, 0x200 + 0x200 + 4 * index, 0x1120)
        num_descriptors = 0x28
        for index in range(num_descriptors):
            struct.pack_into("<IIIII", pe, 0x200 + 0x300 + 20 * index, 0x1200, 0, 0, 0x1100, 0x1200 + 0x10000 * index)
        struct.pack_into("<II", pe, 0x58 + 104, 0x1300, 20 * num_descriptors)
        entries = ApiScout().evaluateImportTable(bytes(pe))["import_table"]
        self.assertLessEqual(len(entries), len(pe) // 4)
        self.assertLess(len(entries), 0x40 * num_descriptors)

    def testPeHeaderBehind64k(self):
        pe = bytearray(build_pe32())
        moved = bytearray(0x20000) + pe[0x40:0x200]
        moved[0:0x40] = pe[0:0x40]
        struct.pack_into("<I", moved, 0x3C, 0x20000)
        self.assertTrue(PeTools.checkPe(bytes(moved)))
        self.assertEqual(0x20000, PeTools.getPeOffset(bytes(moved)))
        self.assertEqual(0, PeTools.getPeOffset(b"MZ" + b"\xff" * 0x100))

    def testFileNamesThatAreNoValidUtf8(self):
        from apiscout.FingerprintCrawler import FingerprintCrawler

        crawler = FingerprintCrawler([], WINAPI1024_PATH, "/x")
        name = b"bad\xff_dump".decode("utf-8", errors="surrogateescape")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "list.csv")
            crawler.persistFingerprintsToFile([("fam", name, 1, 1, "A171")], path)
            crawler.loadIgnoreList(path)
            self.assertIn(("fam", name), crawler._ignore_files)

    def testLoadAddressesOfA32BitProcess(self):
        import DatabaseBuilder

        api_db = {
            "dlls": {
                "64": {
                    "filepath": "C:\\Windows\\System32\\kernel32.dll",
                    "base_address": 0x180000000,
                    "aslr_offset": 0,
                },
                "32": {"filepath": "C:\\Windows\\SysWOW64\\kernel32.dll", "base_address": 0x6B800000, "aslr_offset": 0},
            }
        }
        api_db["dlls"]["64"]["bitness"] = 64
        api_db["dlls"]["32"]["bitness"] = 32
        builder = DatabaseBuilder.DatabaseBuilder()
        # the list of a 32bit process names the SysWOW64 DLL by its System32 path
        builder.applyLoadAddresses(api_db, [("system32/kernel32.dll", 0x75990000)])
        self.assertEqual(0x6B800000 - 0x75990000, api_db["dlls"]["32"]["aslr_offset"])
        self.assertEqual(0, api_db["dlls"]["64"]["aslr_offset"])
        # a 64bit process can have its System32 DLLs below 4 GB as well (Windows 7)
        api_db["dlls"]["32"]["aslr_offset"] = 0
        builder.applyLoadAddresses(
            api_db, [("system32/kernel32.dll", 0x77A10000), ("system32/ntdll.dll", 0x7FFB11110000)]
        )
        self.assertEqual(0x180000000 - 0x77A10000, api_db["dlls"]["64"]["aslr_offset"])
        self.assertEqual(0, api_db["dlls"]["32"]["aslr_offset"])

    def testLiefIsNotUsedForCraftedImportTables(self):
        pe = bytearray(build_pe32()) + bytearray(0x800)
        struct.pack_into("<IIII", pe, 0x58 + 0xE0 + 8, 0xA00, 0x1000, 0xA00, 0x200)
        for index in range(0x40):
            struct.pack_into("<I", pe, 0x200 + 0x200 + 4 * index, 0x1120)
        # the first descriptor has an unreadable thunk, the others share one long thunk list
        struct.pack_into("<IIIII", pe, 0x200 + 0x300, 0x1180, 0, 0, 0x1100, 0x1180)
        struct.pack_into("<II", pe, 0x200 + 0x180, 0x7FFFFF00, 0)
        num_descriptors = 0x28
        for index in range(1, num_descriptors):
            struct.pack_into("<IIIII", pe, 0x200 + 0x300 + 20 * index, 0x1200, 0, 0, 0x1100, 0x1200 + 0x10000 * index)
        struct.pack_into("<II", pe, 0x58 + 104, 0x1300, 20 * num_descriptors)
        self.assertTrue(ImportTableLoader.fileExceedsThunkBudget(bytes(pe), len(pe) // 4))
        self.assertFalse(ImportTableLoader.fileExceedsThunkBudget(build_pe32(), len(build_pe32()) // 4))
        self.assertLessEqual(len(ApiScout().evaluateImportTable(bytes(pe))["import_table"]), len(pe) // 4)


class FifthAuditTestSuite(unittest.TestCase):
    def _buildSharedThunkPe(self, first_address_table):
        pe = bytearray(build_pe32()) + bytearray(0x800)
        struct.pack_into("<IIII", pe, 0x58 + 0xE0 + 8, 0xA00, 0x1000, 0xA00, 0x200)
        for index in range(0x40):
            struct.pack_into("<I", pe, 0x200 + 0x200 + 4 * index, 0x1120)
        num_descriptors = 0x28
        for index in range(num_descriptors):
            address_table = 0x1200 if index else first_address_table
            struct.pack_into("<IIIII", pe, 0x200 + 0x300 + 20 * index, 0x1200, 0, 0, 0x1100, address_table)
        struct.pack_into("<II", pe, 0x58 + 104, 0x1300, 20 * num_descriptors)
        return pe

    def testImportBudgetIsCountedInTheFile(self):
        # a descriptor without address table ends the table for the Windows loader, but not for every parser
        pe = self._buildSharedThunkPe(0)
        self.assertTrue(ImportTableLoader.fileExceedsThunkBudget(bytes(pe), len(pe) // 4))
        self.assertEqual([], ApiScout().evaluateImportTable(bytes(pe))["import_table"])
        # a section far away makes the image unmappable, its file is still readable for other parsers
        pe = self._buildSharedThunkPe(0x1200)
        struct.pack_into("<H", pe, 0x46, 2)
        struct.pack_into("<IIII", pe, 0x58 + 0xE0 + 0x28 + 8, 0x200, 0x20000000, 0x200, 0x200)
        self.assertEqual(b"", PeTools.mapBinary(bytes(pe)))
        self.assertTrue(ImportTableLoader.fileExceedsThunkBudget(bytes(pe), len(pe) // 4))
        self.assertEqual([], ApiScout().evaluateImportTable(bytes(pe))["import_table"])

    def testLoadAddressesOfRenamedFoldersAndNamesInOtherCase(self):
        import DatabaseBuilder

        builder = DatabaseBuilder.DatabaseBuilder()
        api_db = {
            "dlls": {
                "flat": {"filepath": "/copy/kernel32.dll", "base_address": 0x180000000, "aslr_offset": 0},
                "other": {"filepath": "/copy/ntdll.dll", "base_address": 0x180000000, "aslr_offset": 0},
            }
        }
        addresses = [
            ("system32/kernel32.dll", 0x7FFA10000000),
            ("system32/ntdll.dll", 0x7FFA20000000),
            ("syswow64/ntdll.dll", 0x77000000),
        ]
        builder.applyLoadAddresses(api_db, addresses)
        self.assertEqual(0x180000000 - 0x7FFA10000000, api_db["dlls"]["flat"]["aslr_offset"])
        # two addresses are known for this file name
        self.assertEqual(0, api_db["dlls"]["other"]["aslr_offset"])
        with tempfile.TemporaryDirectory() as directory:
            for folder, name in (("a", "KERNEL32.DLL"), ("b", "kernel32.dll")):
                os.mkdir(os.path.join(directory, folder))
                with open(os.path.join(directory, folder, name), "wb"):
                    pass
            builder._extractPeExports = lambda path: {
                "base_address": 0x180000000,
                "bitness": 64,
                "version": "1.0",
                "filepath": path,
                "aslr_offset": 0,
                "exports": [],
            }
            api_db = builder.extractRecursively([directory], os_name="W", os_version="1")
        self.assertEqual(1, len(api_db["dlls"]))
        self.assertEqual(1, len(next(iter(builder._duplicate_paths.values()))))


if __name__ == "__main__":
    unittest.main()
