import contextlib
import json
import logging
import os
import struct
import sys
import tempfile
import unittest
import unittest.mock

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(THIS_DIR, "..", "apiscout", "db_builder"))

import DatabaseBuilder  # noqa: E402

pefile = DatabaseBuilder.pefile

FILE_ALIGNMENT = 0x200
EXPORT_DIRECTORY_RVA = 0x2000
RESOURCE_RVA = 0x3000


def reference_summary(path):
    """what the DB builder made of a DLL before it read the exports itself: the whole PE parsed by pefile"""
    pe = pefile.PE(path)
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return None
    exports = []
    for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=lambda exp: exp.address):
        name = "None" if exp.name is None else exp.name.decode("utf-8", errors="replace")
        exports.append({"address": exp.address, "name": name, "ordinal": exp.ordinal})
    return {
        "base_address": pe.OPTIONAL_HEADER.ImageBase,
        "bitness": 32 if pe.FILE_HEADER.Machine in (0x14C, 0x1C0, 0x1C2, 0x1C4) else 64,
        "version": DatabaseBuilder.get_product_version(pe),
        "filepath": path,
        "aslr_offset": 0,
        "exports": exports,
    }


def version_info(product=(10, 0, 19041, 1)):
    key = "VS_VERSION_INFO\0".encode("utf-16-le")
    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x10000,
        product[0] << 16 | product[1],
        product[2] << 16 | product[3],
        product[0] << 16 | product[1],
        product[2] << 16 | product[3],
        0x3F,
        0,
        4,
        2,
        0,
        0,
        0,
    )
    body = struct.pack("<HHH", 0, len(fixed), 0) + key
    body += b"\0" * (-len(body) % 4) + fixed
    return struct.pack("<H", len(body) + 2) + body[2:]


def build_resources(product, named_types=0):
    """the resource directory at RESOURCE_RVA: RT_VERSION (after as many named types), one resource in one language"""
    entries = named_types + 1
    type_directory = 16 + 8 * entries
    language_directory = type_directory + 24
    data_entry = language_directory + 24
    names = data_entry + 16
    data = (names + 8 * named_types + 3) // 4 * 4
    blob = bytearray(struct.pack("<IIHHHH", 0, 0, 0, 0, named_types, 1))
    for index in range(named_types):
        blob += struct.pack("<II", 0x80000000 | (names + 8 * index), 0x80000000 | type_directory)
    blob += struct.pack("<II", 16, 0x80000000 | type_directory)
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 1, 0x80000000 | language_directory)
    blob += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, data_entry)
    info = version_info(product)
    blob += struct.pack("<IIII", RESOURCE_RVA + data, len(info), 0, 0)
    for _ in range(named_types):
        blob += (struct.pack("<H", 2) + "ab".encode("utf-16-le")).ljust(8, b"\0")
    return bytes(blob.ljust(data, b"\0")) + info


def build_dll(
    functions,
    names,
    bits=32,
    product=(10, 0, 19041, 1),
    base=1,
    forwarder=None,
    with_resources=True,
    named_types=0,
    with_exports=True,
    machine=None,
):
    """
    A DLL with a section of code, one of the export directory at 0x2000 and one of resources at 0x3000.
    functions: the address of each function by ordinal - base (0: none), names: (name, index in functions)
    machine: the machine type of the header, by default the one of x86 for bits=32 and of AMD64 for bits=64
    """
    export = bytearray()
    count = len(names)
    tables = 40
    functions_at, names_at, ordinals_at = tables, tables + 4 * len(functions), tables + 4 * len(functions) + 4 * count
    strings_at = ordinals_at + 2 * count + 8
    string_positions = []
    strings = bytearray(b"test.dll\0")
    for name, _ in names:
        string_positions.append(strings_at + len(strings))
        strings += name + b"\0"
    forwarder_at = strings_at + len(strings)
    if forwarder is not None:
        strings += forwarder + b"\0"
    export += struct.pack(
        "<IIHHIIIIIII",
        0,
        0,
        0,
        0,
        EXPORT_DIRECTORY_RVA + strings_at,
        base,
        len(functions),
        count,
        EXPORT_DIRECTORY_RVA + functions_at,
        EXPORT_DIRECTORY_RVA + names_at,
        EXPORT_DIRECTORY_RVA + ordinals_at,
    )
    addresses = [EXPORT_DIRECTORY_RVA + forwarder_at if address == "forwarder" else address for address in functions]
    export += struct.pack(f"<{len(addresses)}I", *addresses)
    export += struct.pack(f"<{count}I", *[EXPORT_DIRECTORY_RVA + position for position in string_positions])
    export += struct.pack(f"<{count}H", *[index for _, index in names])
    export = export.ljust(strings_at, b"\0") + strings
    export_size = len(export)
    export = bytes(export).ljust(0x400, b"\0")
    resources = build_resources(product, named_types).ljust(0x200, b"\0")
    code = b"\xc3".ljust(0x200, b"\xcc")
    if not with_exports:
        export, export_size = bytes(0x400), 0
    # headers
    optional_size = 0xE0 if bits == 32 else 0xF0
    header = bytearray(0x400)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    machine = machine or (0x14C if bits == 32 else 0x8664)
    struct.pack_into("<HHIIIHH", header, 0x84, machine, 3, 0x5F000000, 0, 0, optional_size, 0x2102)
    optional = 0x98
    struct.pack_into("<HBB", header, optional, 0x10B if bits == 32 else 0x20B, 14, 0)
    if bits == 32:
        struct.pack_into("<I", header, optional + 28, 0x10000000)
        directories = optional + 96
    else:
        struct.pack_into("<Q", header, optional + 24, 0x180000000)
        directories = optional + 112
    struct.pack_into("<II", header, optional + 32, 0x1000, FILE_ALIGNMENT)
    struct.pack_into("<I", header, optional + 56, 0x4000)
    struct.pack_into("<I", header, optional + 60, 0x400)
    struct.pack_into("<I", header, directories - 4, 16)
    if with_exports:
        struct.pack_into("<II", header, directories, EXPORT_DIRECTORY_RVA, export_size)
    if with_resources:
        struct.pack_into("<II", header, directories + 16, RESOURCE_RVA, 0x200)
    sections = optional + optional_size
    for index, (name, virtual_address, size, pointer) in enumerate(
        ((b".text", 0x1000, 0x200, 0x400), (b".rdata", 0x2000, 0x400, 0x600), (b".rsrc", 0x3000, 0x200, 0xA00))
    ):
        struct.pack_into(
            "<8sIIIIIIHHI",
            header,
            sections + 40 * index,
            name,
            size,
            virtual_address,
            size,
            pointer,
            0,
            0,
            0,
            0,
            0x40000040,
        )
    return bytes(header) + code + export + resources


class DatabaseBuilderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.counter = 0

    def write(self, content):
        self.counter += 1
        path = os.path.join(self.directory.name, f"test{self.counter}.dll")
        with open(path, "wb") as f_out:
            f_out.write(content)
        return path

    def assertSameAsPefile(self, content, plain):
        """the DB builder reads the file as pefile does, by itself (plain) or by asking pefile"""
        path = self.write(content)
        builder = DatabaseBuilder.DatabaseBuilder()
        expected = reference_summary_or_failure(path)
        if plain:
            self.assertEqual(expected, builder._extractPlainPe(path))
        else:
            with self.assertRaises(Exception):  # noqa: B017
                builder._extractPlainPe(path)
        self.assertEqual(expected, builder._extractPeExports(path))
        return builder._extractPeExports(path)

    def testExportsAndVersionOfPlainImages(self):
        functions = [0x1000, 0x1010, 0, 0x1020, "forwarder", 0x1010]
        names = [(b"Alpha", 0), (b"Beta", 3), (b"Gamma", 4), (b"Zeta@8", 1)]
        for bits in (32, 64):
            summary = self.assertSameAsPefile(
                build_dll(functions, names, bits, forwarder=b"NTDLL.Alpha", base=5), plain=True
            )
            self.assertEqual("10.0.19041.1", summary["version"])
            self.assertEqual(bits, summary["bitness"])
            # sorted by address, the one without a name after the one with a name at the same address
            self.assertEqual(
                [("Alpha", 5), ("Zeta@8", 6), ("None", 10), ("Beta", 8), ("Gamma", 9)],
                [(e["name"], e["ordinal"]) for e in summary["exports"]],
            )

    def testBitnessOfTheMachineTypes(self):
        """32bit ARM DLLs are 32bit, as the DLLs of x86; ARM64 and AMD64 are 64bit; by PlainPe and by pefile"""
        machines = {
            0x14C: ("x86", 32),
            0x1C0: ("ARM", 32),
            0x1C2: ("ARM Thumb", 32),
            0x1C4: ("ARM Thumb-2 (ARMNT)", 32),
            0x8664: ("AMD64", 64),
            0xAA64: ("ARM64", 64),
        }
        for machine, (label, bitness) in machines.items():
            # the optional header of a 32bit machine is PE32, the one of a 64bit machine PE32+
            content = build_dll([0x1000], [(b"A", 0)], bitness, machine=machine)
            with self.subTest(label):
                self.assertEqual(bitness, self.assertSameAsPefile(content, plain=True)["bitness"])
                self.assertEqual(bitness, DatabaseBuilder.get_bitness(machine))
                # not plain: pefile reads it
                changed = bytearray(content)
                # 15 data directories instead of 16 is not what the linker writes
                struct.pack_into("<I", changed, 0x98 + (92 if bitness == 32 else 108), 15)
                path = self.write(bytes(changed))
                with self.assertRaises(DatabaseBuilder.NotPlainPe):
                    DatabaseBuilder.PlainPe(bytes(changed))
                builder = DatabaseBuilder.DatabaseBuilder()
                summary = builder._extractPeExports(path)
                self.assertEqual(bitness, summary["bitness"])
                # the machine is remembered by the builder, and not part of what goes into the DB
                self.assertEqual({path: machine}, builder._machines)
                self.assertNotIn("machine", summary)
                plain_path = self.write(content)
                builder._extractPlainPe(plain_path)
                self.assertEqual(machine, builder._machines[plain_path])
        # a machine type that is not known is 64bit as before
        self.assertEqual(64, DatabaseBuilder.get_bitness(0x200))

    def testDllBaseCheckerIsNotAskedForArm32Dlls(self):
        """ARM64 DLLs go to the 64bit DllBaseChecker, which loads the ARM64X DLLs of Windows 11 on ARM"""
        builder = DatabaseBuilder.DatabaseBuilder()
        api_db = {"dlls": {}}
        names = {}
        for machine, bits in ((0x14C, 32), (0x8664, 64), (0x1C4, 32), (0xAA64, 64), (0x1C2, 32)):
            path = self.write(build_dll([0x1000], [(b"A", 0)], bits, machine=machine))
            names[path] = machine
            api_db["dlls"][f"{bits}_{self.counter}"] = builder._extractPeExports(path)
        checked = []

        def get_offset(dll):
            checked.append(names[dll["filepath"]])
            return 0x1000

        logging.disable(logging.NOTSET)
        with contextlib.ExitStack() as stack:
            stack.enter_context(unittest.mock.patch.object(DatabaseBuilder, "check_aslr", return_value=True))
            stack.enter_context(unittest.mock.patch.object(builder, "getAslrOffsetForDll", side_effect=get_offset))
            logs = stack.enter_context(self.assertLogs("DatabaseBuilder", logging.WARNING))
            builder.extractAslrOffsets(api_db)
        self.assertEqual([0x14C, 0x8664, 0xAA64], checked)
        self.assertEqual(1, len(logs.records))
        self.assertIn("offset of 2 of them is left as 0", logs.records[0].getMessage())
        self.assertEqual(
            [0x1000, 0x1000, 0x1000, 0, 0],
            sorted((dll["aslr_offset"] for dll in api_db["dlls"].values()), reverse=True),
        )

    def testNoResourcesAndNoExports(self):
        summary = self.assertSameAsPefile(build_dll([0x1000], [(b"A", 0)], with_resources=False), plain=True)
        self.assertEqual("0.0.0.0", summary["version"])
        self.assertIsNone(self.assertSameAsPefile(build_dll([], [], with_exports=False), plain=True))
        # an export directory without exports
        summary = self.assertSameAsPefile(build_dll([], []), plain=True)
        self.assertEqual([], summary["exports"])

    def testVersionBehindNamedResourceTypes(self):
        self.assertSameAsPefile(
            build_dll([0x1000], [(b"A", 0)], named_types=2, product=(6, 1, 7601, 17514)), plain=True
        )

    def testNamesInAnyOrder(self):
        names = [(b"b", 1), (b"a", 0), (b"c", 2)]
        self.assertSameAsPefile(build_dll([0x1000, 0x1004, 0x1008], names), plain=True)

    def testUnusualFilesArePassedToPefile(self):
        plain = build_dll([0x1000, 0x1004, 0x1008], [(b"a", 0), (b"b", 1), (b"c", 2)])
        cases = {
            "a name with a dot": build_dll([0x1000, 0x1004], [(b"a", 0), (b"b.c", 1), (b"d", 1)]),
            "a name without address": build_dll([0x1000, 0], [(b"a", 0), (b"b", 1)]),
            "an ordinal beyond the functions": build_dll([0x1000], [(b"a", 0), (b"b", 5)]),
            "a repeated name": build_dll([0x1000, 0x1000], [(b"a", 0), (b"a", 1)]),
            "a truncated file": plain[:0xA20],
            "a file that is not a PE": b"MZ" + bytes(0x100),
            "an empty file": b"",
        }
        for label, content in cases.items():
            with self.subTest(label):
                path = self.write(content)
                with self.assertRaises(Exception):  # noqa: B017
                    DatabaseBuilder.DatabaseBuilder()._extractPlainPe(path)
                self.assertEqual(
                    reference_summary_or_failure(path), DatabaseBuilder.DatabaseBuilder()._extractPeExports(path)
                )
        # headers that pefile corrects or reads another way than the plain layout
        for offset, value in ((0x8A, 5), (0x8A, 0), (0xA8 + 4, 0x2000), (0xB0 + 4, 0x200), (0x84 + 20, 0xE0)):
            content = bytearray(plain)
            struct.pack_into("<H" if offset == 0x8A else "<I", content, offset, value)
            with self.subTest(f"header {offset:#x}={value:#x}"):
                path = self.write(bytes(content))
                self.assertEqual(
                    reference_summary_or_failure(path), DatabaseBuilder.DatabaseBuilder()._extractPeExports(path)
                )

    def testJsonIsWrittenAsTheJsonModuleWritesIt(self):
        exports = [{"address": 0x1000, "name": "A", "ordinal": 1}, {"address": 1, "name": 'é"\\\n', "ordinal": 2**40}]
        documents = [
            {"dlls": {"b": {"exports": exports, "version": "1.2", "bitness": 32}, "a": {"exports": []}}, "num": 2},
            {"exports": exports + [{"address": True, "name": "A", "ordinal": 1}]},
            {"exports": [{"address": 1, "name": "A"}], "x": (1, 2.5, None, False, {}), "crawled_paths": ["/a", "é"]},
            {"dlls": {}, "filtered": True, "os_name": "Windows 11 Pro", "aslr_offsets": False},
            {1: "int key"},
            [],
            "text",
        ]
        for document in documents:
            self.assertEqual(json.dumps(document, indent=1, sort_keys=True), DatabaseBuilder.dumps_api_db(document))

    def testOldPythonStopsBeforeAnythingIsDone(self):
        for old_version in ((3, 8, 20, "final", 0), (3, 9, 0, "final", 0)):
            with self.subTest(old_version):
                crawl = unittest.mock.Mock(side_effect=AssertionError("crawled"))
                with contextlib.ExitStack() as stack:
                    stack.enter_context(unittest.mock.patch.object(sys, "version_info", old_version))
                    stack.enter_context(unittest.mock.patch.object(sys, "argv", ["DatabaseBuilder.py", "--paths", "x"]))
                    stack.enter_context(
                        unittest.mock.patch.object(DatabaseBuilder.DatabaseBuilder, "extractRecursively", crawl)
                    )
                    with self.assertRaises(SystemExit) as stopped:
                        DatabaseBuilder.main()
                self.assertIn(
                    "needs Python 3.10 or newer, this is Python {}.{}".format(*old_version[:2]),
                    str(stopped.exception.code),
                )
                self.assertIn("--load_addresses", str(stopped.exception.code))
                crawl.assert_not_called()

    def testFilterIsNotCaseSensitive(self):
        builder = DatabaseBuilder.DatabaseBuilder()
        builder._extractPeExports = lambda path: {
            "base_address": 0x180000000,
            "bitness": 64,
            "version": "1.0",
            "filepath": path,
            "aslr_offset": 0,
            "exports": [],
        }
        for name in ("KERNEL32.DLL", "other.dll", "NtDll.dll"):
            with open(os.path.join(self.directory.name, name), "wb"):
                pass
        api_db = builder.extractRecursively([self.directory.name], True, "W", "1")
        self.assertEqual(
            ["kernel32.dll", "ntdll.dll"],
            sorted(os.path.basename(d["filepath"]).lower() for d in api_db["dlls"].values()),
        )


def reference_summary_or_failure(path):
    """the summary by pefile, None if it can not read the file (the builder skips it with a warning)"""
    try:
        return reference_summary(path)
    except Exception:
        return None


if __name__ == "__main__":
    unittest.main()
