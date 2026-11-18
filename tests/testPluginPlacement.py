"""
The placement of DLLs in the plugins: the functions of LoadAddresses that IDA, Ghidra and Binary Ninja share, and the
case that their tests use, a sample whose DLLs are loaded elsewhere than the API DB has them.
"""

import collections
import functools
import json
import os
import random
import struct
import tempfile
import unittest

from apiscout.LoadAddresses import (
    MAX_IMAGE_SIZE,
    SOURCE_MODULES,
    DllPlacer,
    ModuleListError,
    describe_placements,
    normalize_dll_path,
    placed_image_ranges,
    placer_for_modules,
    read_from_regions,
    split_modules_argument,
)
from tests.testLoadAddresses import build_dll_image, dll_entry, write_db
from tests.testMinidump import page, run

BASE = 0x400000
EXPORTS = {1: 0xA000, 2: 0xA020}


def rebase_db(source_path, folder, only=None, shift=0x10000000):
    """A copy of an API DB in which the DLLs (all, or those with a file name in `only`) are `shift` bytes away from
    where a dump of the DB's own boot has them, as a DB that was built elsewhere has them, and the module list with
    their real load addresses. Returns (path of the DB, path of the module list)."""
    with open(source_path) as f_db:
        api_db = json.load(f_db)
    paths = collections.Counter(normalize_dll_path(dll["filepath"]) for dll in api_db["dlls"].values())
    lines = []
    for dll in api_db["dlls"].values():
        if only and dll["filepath"].rsplit("\\", 1)[-1].lower() not in only:
            continue
        load_address = dll["base_address"] - dll["aslr_offset"]
        dll["base_address"], dll["aslr_offset"] = load_address + shift, 0
        # a path that several DLLs have does not tell which of them is loaded
        if paths[normalize_dll_path(dll["filepath"])] == 1:
            lines.append(f"{load_address:x} {dll['filepath']}\n")
    db_path, modules_path = os.path.join(folder, "rebased_db.json"), os.path.join(folder, "rebased_modules.txt")
    with open(db_path, "w") as f_db:
        json.dump(api_db, f_db)
    with open(modules_path, "w") as f_modules:
        f_modules.writelines(lines)
    return db_path, modules_path


class PlacementCase:
    """
    A sample at 0x400000 with pointers to kernel32!Api1, ntdll!Api2 and user32!Api2. The API DB (in `folder`) has
    kernel32 and ntdll at the load addresses of another boot than the dump, user32 where the dump has it. The module
    list gives the load addresses of kernel32 and ntdll in the dump, so the dump holds 3 APIs with it and 1 without.
    """

    DB_BOOT = {"kernel32.dll": 0x76480000, "ntdll.dll": 0x77000000, "user32.dll": 0x75000000}
    DUMP_BOOT = {"kernel32.dll": 0x7C800000, "ntdll.dll": 0x7C900000, "user32.dll": 0x75000000}
    APIS = [("kernel32.dll", "Api1", 0xA000), ("ntdll.dll", "Api2", 0xA020), ("user32.dll", "Api2", 0xA020)]

    def __init__(self, folder):
        dlls = {}
        for name, load_address in self.DB_BOOT.items():
            key = f"32_10.0.1_{name}_0x10000000"
            dlls[key] = dll_entry(f"C:\\Windows\\SysWOW64\\{name}", 0x10000000, 32, EXPORTS, load_address)
        self.db_path = write_db(folder, dlls, "case_db.json")
        self.sample = page(
            *[(0x10 + 4 * index, self.DUMP_BOOT[dll] + rva, "<I") for index, (dll, _, rva) in enumerate(self.APIS)]
        )
        self.dump_path = os.path.join(folder, f"dump_0x{BASE:08x}")
        with open(self.dump_path, "wb") as f_dump:
            f_dump.write(self.sample)
        self.modules_path = os.path.join(folder, "modules.txt")
        with open(self.modules_path, "w") as f_modules:
            for name in ("kernel32.dll", "ntdll.dll"):
                f_modules.write(f"{self.DUMP_BOOT[name]:x} C:\\Windows\\SysWOW64\\{name}\n")

    def cli_apis(self, *arguments, dump_path=None):
        """what `apiscout scan` finds in the dump of the case: [(address, API)], every hit like the plugins"""
        code, output, _ = run(
            "scan", dump_path or self.dump_path, "--db", self.db_path, "--json", "--min-confidence", "0", *arguments
        )
        assert code == 0
        return [(BASE + api["offset"], api["api"]) for api in json.loads(output)["apis"]]

    IMAGE = BASE + 0x3000

    def with_image(self, folder):
        """
        A dump with the image of kernel32 (SizeOfImage 0x3000) at IMAGE behind the sample, with an entry of its import
        address table at 0x2000 that points to ntdll!Api2, and the module list that puts kernel32 there. The sample
        points to ntdll!Api2 and to kernel32!Api1 at the image, whose exports are beyond its end (a real DLL has them
        inside, where references are not looked for). Returns (the dump, the module list).
        """
        image = bytearray(build_dll_image("kernel32.dll", EXPORTS, size=0x3000))
        struct.pack_into("<I", image, 0x80 + 0x50, 0x3000)
        struct.pack_into("<I", image, 0x2000, self.DUMP_BOOT["ntdll.dll"] + 0xA020)
        sample = page(
            (0x10, self.DUMP_BOOT["ntdll.dll"] + 0xA020, "<I"), (0x14, self.IMAGE + 0xA000, "<I"), size=0x1000
        )
        dump = sample + bytes(0x2000) + bytes(image)
        modules_path = os.path.join(folder, "modules_with_image.txt")
        with open(modules_path, "w") as f_modules:
            f_modules.write(f"{self.IMAGE:x} C:\\Windows\\SysWOW64\\kernel32.dll\n")
            f_modules.write(f"{self.DUMP_BOOT['ntdll.dll']:x} C:\\Windows\\SysWOW64\\ntdll.dll\n")
        return dump, modules_path


class PlacerTestSuite(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.case = PlacementCase(self.folder.name)

    def testModuleList(self):
        placer = placer_for_modules(self.case.modules_path)
        self.assertEqual([SOURCE_MODULES], [source for source, _ in placer.module_lists])
        self.assertEqual([], placer.images)
        place = placer.forDb(self.case.db_path)
        self.assertIsInstance(place, functools.partial)
        self.assertEqual({"db_path": self.case.db_path}, place.keywords)
        with open(self.case.db_path) as f_db:
            placements = place(json.load(f_db))
        self.assertEqual({0x7C800000, 0x7C900000}, set(placements.values()))
        self.assertEqual({SOURCE_MODULES}, {entry["source"] for entry in placer.placed})

    def testWithoutAFile(self):
        for modules_path in (None, ""):
            placer = placer_for_modules(modules_path)
            self.assertTrue(placer.isEmpty())
            self.assertIsNone(placer.forDb(self.case.db_path))
            self.assertEqual([], describe_placements(placer))
        self.assertTrue(placer_for_modules().isEmpty())

    def testModuleListThatCanNotBeUsed(self):
        with self.assertRaisesRegex(ModuleListError, "can not read the module list .*missing.txt"):
            placer_for_modules(os.path.join(self.folder.name, "missing.txt"))
        empty = os.path.join(self.folder.name, "empty.txt")
        with open(empty, "w") as f_empty:
            f_empty.write("# no modules\nnot a line\n")
        with self.assertRaisesRegex(ModuleListError, "no lines of '<hex load address> <DLL path>' in .*empty.txt"):
            placer_for_modules(empty)
        self.assertTrue(issubclass(ModuleListError, ValueError))

    def testReportsWhatTheCommandLineReports(self):
        with open(self.case.db_path) as f_db:
            api_db = json.load(f_db)
        placer = placer_for_modules(self.case.modules_path)
        placer.forDb(self.case.db_path)(api_db)
        lines = describe_placements(placer)
        self.assertEqual(
            [
                "Warning: Placed 2 of 3 DLLs of case_db.json at their load addresses (2 from the modules file), "
                "1 keep the addresses of the DB."
            ],
            lines,
        )
        _, _, errors = run(
            "scan", self.case.dump_path, "--db", self.case.db_path, "--json", "-m", self.case.modules_path
        )
        self.assertIn(lines[0], errors.splitlines())


class ImageRangeTestSuite(unittest.TestCase):
    """the images of the placed DLLs that the memory holds"""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.case = PlacementCase(self.folder.name)
        self.dump, self.modules_path = self.case.with_image(self.folder.name)

    def placed(self, modules_path):
        placer = placer_for_modules(modules_path)
        with open(self.case.db_path) as f_db:
            placer.forDb(self.case.db_path)(json.load(f_db))
        return placer

    def testSizeOfTheImageAtTheLoadAddress(self):
        regions = [(BASE, self.dump)]
        placer = self.placed(self.modules_path)
        read = functools.partial(read_from_regions, regions)
        self.assertEqual([(self.case.IMAGE, self.case.IMAGE + 0x3000)], placed_image_ranges(placer, read))
        # nothing is left out of a DLL whose header is not in the memory (ntdll is not), or is not where the list has it
        placer = self.placed(self.case.modules_path)
        self.assertEqual([], placed_image_ranges(placer, read))
        self.assertEqual([], placed_image_ranges(placer, lambda address, size: b""))
        self.assertEqual([], placed_image_ranges(DllPlacer(), read))

    def testTheSameImageOfSeveralApiDbs(self):
        placer = self.placed(self.modules_path)
        with open(self.case.db_path) as f_db:
            placer.forDb("other.json")(json.load(f_db))
        ranges = placed_image_ranges(placer, functools.partial(read_from_regions, [(BASE, self.dump)]))
        self.assertEqual([(self.case.IMAGE, self.case.IMAGE + 0x3000)], ranges)

    def testHostileHeaders(self):
        placer = self.placed(self.modules_path)
        image = self.dump[0x3000:]
        # no size, too large a size, not a DLL (the image of an executable), no PE magic, PE header out of the page
        for offset, fmt, value in (
            (0x80 + 0x50, "<I", 0),
            (0x80 + 0x50, "<I", MAX_IMAGE_SIZE + 1),
            (0x80 + 0x16, "<H", 0x0102),
            (0x80 + 0x18, "<H", 0),
            (0x3C, "<I", 0x2000),
        ):
            changed = bytearray(image)
            struct.pack_into(fmt, changed, offset, value)
            ranges = placed_image_ranges(placer, functools.partial(read_from_regions, [(self.case.IMAGE, changed)]))
            self.assertEqual([], ranges, hex(offset))
        # a header cut off inside the PE header
        cut = functools.partial(read_from_regions, [(self.case.IMAGE, image[: 0x80 + 0x20])])
        self.assertEqual([], placed_image_ranges(placer, cut))
        random_generator = random.Random(3)
        for _ in range(500):
            changed = bytearray(image[:0x200])
            for _ in range(random_generator.randint(1, 8)):
                changed[random_generator.randrange(len(changed))] = random_generator.randrange(256)
            for start, end in placed_image_ranges(
                placer, functools.partial(read_from_regions, [(self.case.IMAGE, changed)])
            ):
                self.assertLessEqual(end - start, MAX_IMAGE_SIZE)

    def testReadFromRegions(self):
        regions = [(0x1000, b"abcd"), (0x2000, b"efgh")]
        self.assertEqual(b"bcd", read_from_regions(regions, 0x1001, 10))
        self.assertEqual(b"ef", read_from_regions(regions, 0x2000, 2))
        self.assertEqual(b"", read_from_regions(regions, 0x1004, 2))
        self.assertEqual(b"", read_from_regions([], 0x1000, 2))


class ArgumentTestSuite(unittest.TestCase):
    def testModulesArgument(self):
        self.assertEqual((["a.json", "b.json"], None), split_modules_argument(["a.json", "b.json"]))
        self.assertEqual(([], None), split_modules_argument([]))
        # the forms of `apiscout scan`
        for form in (["--modules", "m.txt"], ["-m", "m.txt"], ["--modules=m.txt"]):
            self.assertEqual((["a.json", "b.json"], "m.txt"), split_modules_argument(["a.json", *form, "b.json"]))
        # the last one counts
        self.assertEqual(([], "n.txt"), split_modules_argument(["--modules", "m.txt", "--modules=n.txt"]))
        for arguments in (["a.json", "--modules"], ["-m"], ["--modules="], ["--modules", "-m"], ["-m", "--other"]):
            with self.assertRaisesRegex(ModuleListError, "(--modules|-m) needs the file with the module list"):
                split_modules_argument(arguments)


if __name__ == "__main__":
    unittest.main()
