import atexit
import contextlib
import io
import json
import os
import random
import struct
import tempfile
import unittest

from apiscout import cli
from apiscout.ApiScout import ApiScout
from apiscout.Minidump import Minidump, MinidumpError

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
TEMP_DIR = tempfile.TemporaryDirectory()
DB_PATH = os.path.join(TEMP_DIR.name, "minidump_db.json")
SAMPLES_DIR = os.environ.get("APISCOUT_SAMPLES", "")

# the DB of the tests: KernelBase.dll (32bit, loaded at 0x10000000 as the module list says) exports InterlockedIncrement
# at RVA 0x6A50, KernelBase.dll (64bit) WaitForSingleObjectEx at RVA 0x1010 of 0x7FF800000000
API32 = 0x10006A50
API64 = 0x7FF800001010

DB = {
    "aslr_offsets": False,
    "dlls": {
        "32_10.0.19045.1_KernelBase.dll_0x10000000": {
            "aslr_offset": 0,
            "base_address": 268435456,
            "bitness": 32,
            "exports": [{"address": 27216, "name": "InterlockedIncrement", "ordinal": 383}],
            "filepath": "C:\\Windows\\SysWOW64\\KernelBase.dll",
            "version": "10.0.19045.1",
        },
        "64_10.0.19045.1_KernelBase.dll_0x7ff800000000": {
            "aslr_offset": 0,
            "base_address": 140703128616960,
            "bitness": 64,
            "exports": [{"address": 4112, "name": "WaitForSingleObjectEx", "ordinal": 598}],
            "filepath": "C:\\Windows\\System32\\KernelBase.dll",
            "version": "10.0.19045.1",
        },
    },
    "os_name": "Windows 10",
    "os_version": "10.0.19045",
}


with open(DB_PATH, "w") as f_db:
    json.dump(DB, f_db)
atexit.register(TEMP_DIR.cleanup)

STREAM_MODULE_LIST, STREAM_MEMORY_LIST, STREAM_SYSTEM_INFO, STREAM_MEMORY64_LIST = 4, 5, 7, 9


def run(*arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(list(arguments))
        except SystemExit as exit_request:
            code = exit_request.code
    return code, stdout.getvalue(), stderr.getvalue()


def build_minidump(ranges, modules=(), architecture=9, memory64=True, gap=0):
    """a minidump with the given memory ranges [(address, data)] and modules [(name, base, size)].
    memory64 stores the ranges as Memory64ListStream (full dump) with their data one after another at the end, else
    as MemoryListStream with a gap of the given number of bytes before the data of each range."""
    streams = []  # (type, data)
    system_info = struct.pack("<HHHBBIIIII", architecture, 6, 0, 1, 1, 10, 0, 19045, 2, 0) + bytes(4 + 24)
    streams.append((STREAM_SYSTEM_INFO, system_info))
    module_blobs = bytearray()
    names = bytearray()
    module_entries = []
    # the layout is fixed before the offsets are known: header, directory, streams, strings, memory data
    stream_count = 3
    offset = 32 + 12 * stream_count
    system_info_offset = offset
    offset += len(system_info)
    module_list_offset = offset
    offset += 4 + 108 * len(modules)
    names_offset = offset
    for name, base, size in modules:
        encoded = name.encode("utf-16-le")
        module_entries.append((base, size, names_offset + len(names)))
        names += struct.pack("<I", len(encoded)) + encoded + b"\x00\x00"
    offset += len(names)
    module_blobs += struct.pack("<I", len(modules))
    for base, size, name_rva in module_entries:
        module_blobs += struct.pack("<QIIII", base, size, 0x1234, 0x5678, name_rva) + bytes(108 - 24)
    list_offset = offset
    if memory64:
        list_size = 16 + 16 * len(ranges)
        data_offset = list_offset + list_size
        memory_list = struct.pack("<QQ", len(ranges), data_offset)
        memory_list += b"".join(struct.pack("<QQ", address, len(data)) for address, data in ranges)
        memory_data = b"".join(data for _, data in ranges)
        memory_type = STREAM_MEMORY64_LIST
    else:
        list_size = 4 + 16 * len(ranges)
        position = list_offset + list_size
        memory_list = struct.pack("<I", len(ranges))
        memory_data = b""
        for address, data in ranges:
            position += gap
            memory_data += bytes(gap)
            memory_list += struct.pack("<QII", address, len(data), position)
            memory_data += data
            position += len(data)
        memory_type = STREAM_MEMORY_LIST
    directory = [
        (STREAM_SYSTEM_INFO, len(system_info), system_info_offset),
        (STREAM_MODULE_LIST, len(module_blobs), module_list_offset),
        (memory_type, len(memory_list), list_offset),
    ]
    header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, stream_count, 32, 0, 0, 0)
    body = b"".join(struct.pack("<III", *entry) for entry in directory)
    return header + body + system_info + bytes(module_blobs) + bytes(names) + memory_list + memory_data


def page(*entries, size=0x1000):
    """a page of memory with the given (offset, value, format) entries"""
    data = bytearray(size)
    for offset, value, fmt in entries:
        struct.pack_into(fmt, data, offset, value)
    return bytes(data)


class MinidumpParserTestSuite(unittest.TestCase):
    def testSyntheticFullDump(self):
        dump = build_minidump(
            [(0x400000, page()), (0x401000, page()), (0x10000000, page())],
            [("C:\\Windows\\System32\\KernelBase.dll", 0x10000000, 0x1000), ("C:\\sample.exe", 0x400000, 0x2000)],
        )
        self.assertTrue(Minidump.isMinidump(dump))
        minidump = Minidump(dump)
        self.assertEqual((9, 64), (minidump.architecture, minidump.bitness))
        self.assertEqual(
            [("C:\\Windows\\System32\\KernelBase.dll", 0x10000000, 0x1000, 0x5678, 0x1234), ("C:\\sample.exe",)],
            [
                (m.name, m.base_address, m.size, m.timestamp, m.checksum) if m.size == 0x1000 else (m.name,)
                for m in minidump.getModules()
            ],
        )
        # the adjacent ranges are one region, a view of the file
        ranges = minidump.getRanges()
        self.assertEqual([(0x400000, 0x2000), (0x10000000, 0x1000)], [(start, len(data)) for start, data in ranges])
        self.assertIsInstance(ranges[0][1], memoryview)
        self.assertEqual([], minidump.warnings)

    def testMemoryListWithGapsInTheFile(self):
        data_a, data_b = page((8, 0x11223344, "<I")), page((16, 0x55667788, "<I"))
        dump = build_minidump([(0x1000, data_a), (0x2000, data_b)], architecture=0, memory64=False, gap=7)
        minidump = Minidump(dump)
        self.assertEqual(32, minidump.bitness)
        ranges = minidump.getRanges()
        # the data of the two ranges is not adjacent in the file, so the region is a copy of them
        self.assertEqual([(0x1000, data_a + data_b)], [(start, bytes(data)) for start, data in ranges])

    def testOverlappingRangesKeepTheLowerOnesData(self):
        first, second = b"A" * 0x1000, b"B" * 0x1000
        minidump = Minidump(build_minidump([(0x1000, first), (0x1800, second)]))
        ((start, data),) = minidump.getRanges()
        self.assertEqual(0x1000, start)
        self.assertEqual(first + b"B" * 0x800, bytes(data))

    def testNoMinidump(self):
        self.assertFalse(Minidump.isMinidump(b"MZ\x90\x00"))
        self.assertFalse(Minidump.isMinidump(b"MDM"))
        with self.assertRaises(MinidumpError):
            Minidump(b"MZ" + bytes(100))

    def testTruncatedHeaderAndDirectory(self):
        dump = build_minidump([(0x1000, page())])
        for length in (4, 20, 31, 32, 40, 32 + 12 * 3 - 1):
            with self.assertRaises(MinidumpError, msg=f"length {length}"):
                Minidump(dump[:length])

    def testTruncatedMemoryIsScannedAsFarAsItGoes(self):
        dump = build_minidump([(0x1000, page((0x10, API32, "<I"))), (0x2000, page())])
        minidump = Minidump(dump[:-0x800])
        self.assertEqual([(0x1000, 0x1800)], [(start, len(data)) for start, data in minidump.getRanges()])
        self.assertTrue(minidump.warnings)
        # nothing left of the memory
        with self.assertRaises(MinidumpError):
            Minidump(dump[: len(dump) - 0x2000 - 16 * 2 + 1])

    def testCountsAreCheckedAgainstTheFile(self):
        dump = bytearray(build_minidump([(0x1000, page())], [("a.dll", 0x1000, 0x1000)]))
        # directory: system info, module list, memory list
        module_list_rva = struct.unpack_from("<I", dump, 32 + 12 + 8)[0]
        memory_list_rva = struct.unpack_from("<I", dump, 32 + 24 + 8)[0]
        struct.pack_into("<I", dump, module_list_rva, 0xFFFFFFFF)
        struct.pack_into("<Q", dump, memory_list_rva, 0xFFFFFFFFFFFFFFFF)
        minidump = Minidump(bytes(dump))
        self.assertEqual(1, len(minidump.getModules()))
        self.assertEqual(2, len(minidump.warnings))
        self.assertEqual(1, len(minidump.getRanges()))
        # a stream count for which the directory does not fit into the file
        struct.pack_into("<I", dump, 8, 0xFFFFFFFF)
        with self.assertRaises(MinidumpError):
            Minidump(bytes(dump))

    def testRangesNeverClaimMoreThanTheFile(self):
        # 1000 ranges of a MemoryList that all point at the same 4 KB of data and claim 1 GB each
        count = 1000
        header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, 1, 32, 0, 0, 0)
        list_rva = 32 + 12
        data_rva = list_rva + 4 + 16 * count
        directory = struct.pack("<III", STREAM_MEMORY_LIST, 4 + 16 * count, list_rva)
        descriptors = b"".join(
            struct.pack("<QII", 0x10000000 + index * 0x40000000, 0x40000000, data_rva) for index in range(count)
        )
        dump = header + directory + struct.pack("<I", count) + descriptors + bytes(0x1000)
        minidump = Minidump(dump)
        self.assertLessEqual(sum(len(data) for _, data in minidump.getRanges()), len(dump))
        self.assertTrue(minidump.warnings)
        # a Memory64List with sizes that do not fit into 64 bits
        descriptors = struct.pack("<QQ", 0x1000, 1 << 63) + struct.pack("<QQ", 0xFFFFFFFFFFFFF000, 0x2000)
        header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA793, 1, 32, 0, 0, 0)
        directory = struct.pack("<III", STREAM_MEMORY64_LIST, 16 + 32, 44)
        dump = header + directory + struct.pack("<QQ", 2, 44 + 48) + descriptors + bytes(0x100)
        ranges = Minidump(dump).getRanges()
        self.assertEqual([(0x1000, 0x100)], [(start, len(data)) for start, data in ranges])

    def testDamagedModuleNames(self):
        dump = bytearray(build_minidump([(0x1000, page())], [("kernel32.dll", 0x1000, 0x1000)]))
        module_list_rva = struct.unpack_from("<I", dump, 32 + 12 + 8)[0]
        name_rva = struct.unpack_from("<I", dump, module_list_rva + 4 + 20)[0]
        # a length beyond the end of the file, and a name RVA outside of it
        struct.pack_into("<I", dump, name_rva, 0xFFFFFFF0)
        self.assertEqual(1, len(Minidump(bytes(dump)).getModules()))
        struct.pack_into("<I", dump, module_list_rva + 4 + 20, 0xFFFFFFFF)
        self.assertEqual("", Minidump(bytes(dump)).getModules()[0].name)

    def testGarbageNeverEscapes(self):
        """mutated and random files are read or rejected with MinidumpError, nothing else happens"""
        original = build_minidump(
            [(0x1000, page((4, API32, "<I"))), (0x2000, page()), (0x9000, page())],
            [("C:\\a\\b.dll", 0x1000, 0x1000), ("c.exe", 0x9000, 0x1000)],
        )
        random_generator = random.Random(12345)
        for _ in range(3000):
            dump = bytearray(original)
            for _ in range(random_generator.randint(1, 8)):
                position = random_generator.randrange(min(len(dump), 400))
                dump[position] = random_generator.choice([0x00, 0xFF, 0x7F, 0x80, random_generator.randrange(256)])
            dump = (
                bytes(dump[: random_generator.randint(0, len(original))])
                if random_generator.random() < 0.3
                else bytes(dump)
            )
            try:
                minidump = Minidump(dump)
                total = sum(len(data) for _, data in minidump.getRanges())
            except MinidumpError:
                continue
            self.assertLessEqual(total, len(dump))
        for _ in range(300):
            noise = b"MDMP" + random_generator.randbytes(random_generator.randint(0, 600))
            with contextlib.suppress(MinidumpError):
                Minidump(noise).getRanges()


class MinidumpScanTestSuite(unittest.TestCase):
    def _writeDump(self, directory, dump):
        path = os.path.join(directory, "crash.dmp")
        with open(path, "wb") as f_dump:
            f_dump.write(dump)
        return path

    def _buildDump(self, architecture=9):
        image = page((0xFFE, API32, "<I"), (0x20, API64, "<Q"), size=0x2000)
        ranges = [
            # a pointer straddling the border of two ranges, found because adjacent ranges are one region
            (0x400000, image[:0x1000]),
            (0x401000, image[0x1000:]),
            # in the image of KernelBase.dll of the module list: the DLL's own pointers, not the sample's
            (0x10000000, page((0x40, API32, "<I"))),
            (0x20000000, page((0x80, API32, "<I"))),
        ]
        modules = [
            ("C:\\sample.exe", 0x400000, 0x2000),
            ("C:\\Windows\\System32\\KERNELBASE.dll", 0x10000000, 0x1000),
        ]
        return build_minidump(ranges, modules, architecture=architecture)

    def testScanReportsVirtualAddresses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._writeDump(directory, self._buildDump())
            code, output, errors = run("scan", "--min-confidence", "0", path, "--db", DB_PATH, "--json")
            self.assertEqual(0, code, errors)
            document = json.loads(output)
            found = [(hex(api["offset"]), api["api"]) for api in document["apis"]]
            self.assertEqual(
                [
                    ("0x400020", "WaitForSingleObjectEx"),
                    ("0x400ffe", "InterlockedIncrement"),
                    ("0x20000080", "InterlockedIncrement"),
                ],
                found,
            )
            self.assertEqual(0, document["base_address"])
            self.assertIn("minidump", errors)
            self.assertIn("1 hits in the images of 1 system DLLs left out", errors)
            # a base address makes the offsets relative to it
            code, output, _ = run(
                "scan", "--min-confidence", "0", path, "--db", DB_PATH, "--json", "--base-addr", "0x400000"
            )
            self.assertEqual([0x20, 0xFFE, 0x1FC00080], [api["offset"] for api in json.loads(output)["apis"]])
            # the listing shows the address of every hit
            code, output, _ = run("scan", "--min-confidence", "0", path, "--db", DB_PATH, "--base-addr", "0x400000")
            self.assertIn("0x00400ffe", output)
            self.assertIn("0x20000080", output)

    def testFileNameDoesNotSetTheBaseAddress(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "crash_0x00400000")
            with open(path, "wb") as f_dump:
                f_dump.write(self._buildDump())
            document = json.loads(run("scan", "--min-confidence", "0", path, "--db", DB_PATH, "--json")[1])
            self.assertEqual(0, document["base_address"])
            self.assertEqual(0x400020, document["apis"][0]["offset"])

    def testSystemWithoutQwords(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._writeDump(directory, self._buildDump(architecture=0))
            document = json.loads(run("scan", "--min-confidence", "0", path, "--db", DB_PATH, "--json")[1])
            self.assertEqual({"InterlockedIncrement"}, {api["api"] for api in document["apis"]})

    def testScanErrors(self):
        dump = self._buildDump()
        with tempfile.TemporaryDirectory() as directory:
            path = self._writeDump(directory, dump[:40])
            code, output, errors = run("scan", "--min-confidence", "0", path, "--db", DB_PATH)
            self.assertEqual((1, ""), (code, output))
            self.assertIn("can not read", errors)
            self.assertNotIn("Traceback", errors)
            path = self._writeDump(directory, b"MDMP" + bytes(range(256)) * 4)
            self.assertEqual(1, run("scan", "--min-confidence", "0", path, "--db", DB_PATH)[0])
            path = self._writeDump(directory, dump)
            code, _, errors = run("scan", "--min-confidence", "0", path, "--import-table")
            self.assertEqual(1, code)
            self.assertIn("minidump", errors)
            # a truncated dump is scanned as far as it goes
            path = self._writeDump(directory, dump[:-0x1800])
            code, output, errors = run("scan", "--min-confidence", "0", path, "--db", DB_PATH, "--json")
            self.assertEqual(0, code)
            self.assertIn("cut off", errors)
            self.assertEqual(2, len(json.loads(output)["apis"]))

    def testMinidumpOfSampleGivesTheResultsOfTheFlatDump(self):
        path = os.path.join(SAMPLES_DIR, "trickbot_dump7_0x00400000")
        if not os.path.isfile(path):
            self.skipTest("set APISCOUT_SAMPLES to the folder with the samples")
        with open(path, "rb") as f_sample:
            sample = f_sample.read()
        db_path = os.path.join(THIS_DIR, "..", "dbs", "win7_prof-n_sp1_example.json")
        with tempfile.TemporaryDirectory() as directory:
            dump_path = self._writeDump(directory, build_minidump([(0x400000, sample)], architecture=0))
            from_minidump = json.loads(run("scan", dump_path, "--db", db_path, "--json", "--min-confidence", "0")[1])
        # every hit, the count of 2.x
        flat = json.loads(run("scan", path, "--db", db_path, "--json", "--min-confidence", "0")[1])
        self.assertEqual(183, len({api["api"] for api in flat["apis"]}))
        # the offsets of the minidump are virtual addresses, those of the flat dump relative to its base address
        for api in flat["apis"]:
            api["offset"] += 0x400000
            api["references"] = [reference + 0x400000 for reference in api["references"]]
        self.assertEqual(flat["apis"], from_minidump["apis"])
        self.assertEqual(flat["apivector"], from_minidump["apivector"])

    def testSampleMinidumps(self):
        """Windows minidumps in the samples folder, if there are any"""
        names = []
        if os.path.isdir(SAMPLES_DIR):
            for name in sorted(os.listdir(SAMPLES_DIR)):
                with open(os.path.join(SAMPLES_DIR, name), "rb") as f_sample:
                    if f_sample.read(4) == b"MDMP":
                        names.append(name)
        if not names:
            self.skipTest("no minidump in the samples folder")
        for name in names:
            scout = ApiScout(os.path.join(THIS_DIR, "..", "dbs", "win7_prof-n_sp1_example.json"))
            with open(os.path.join(SAMPLES_DIR, name), "rb") as f_sample:
                minidump = Minidump(f_sample.read())
            self.assertTrue(minidump.getRanges())
            scout.crawlRegions(minidump.getRanges())


if __name__ == "__main__":
    unittest.main()
