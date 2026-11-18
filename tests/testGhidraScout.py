import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from apiscout import cli
from tests.testPluginPlacement import BASE, PlacementCase, rebase_db

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
SCRIPT_PATH = os.path.join(os.path.dirname(THIS_DIR), "ghidra_scout.py")
DB_PATH = os.path.join(THIS_DIR, "minimal_db.json")
DUMP_PATH = os.path.join(THIS_DIR, "example_dump.bin")


def load_script():
    """the Ghidra script as module, without running it: Ghidra runs it as __main__"""
    spec = importlib.util.spec_from_file_location("ghidra_scout", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ghidra_scout = load_script()


class FakeAddress:
    """the parts of a Ghidra Address the script uses for scanning"""

    def __init__(self, offset, loaded=True):
        self.offset = offset
        self.loaded = loaded

    def add(self, displacement):
        return FakeAddress(self.offset + displacement, self.loaded)

    def isSuccessor(self, other):
        return other.offset == self.offset + 1

    def getUnsignedOffset(self):
        return self.offset

    def getAddressSpace(self):
        return self

    def isLoadedMemorySpace(self):
        return self.loaded

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and other.offset == self.offset

    def __lt__(self, other):
        return self.offset < other.offset

    def __hash__(self):
        return hash(self.offset)

    def __repr__(self):
        return f"{self.offset:08x}"


class FakeBlock:
    def __init__(self, start, data=b"", size=None, initialized=True, loaded=True):
        self.start = FakeAddress(start, loaded)
        self.data = data
        self.size = len(data) if size is None else size
        self.initialized = initialized

    def getStart(self):
        return self.start

    def getEnd(self):
        return self.start.add(self.size - 1)

    def getSize(self):
        return self.size

    def isInitialized(self):
        return self.initialized


class FakeMonitor:
    def checkCancelled(self):
        pass

    def setMessage(self, message):
        pass


class FakeProgram:
    def __init__(self, blocks, pointer_size=4):
        self.blocks = blocks
        self.pointer_size = pointer_size

    def getDefaultPointerSize(self):
        return self.pointer_size

    def getName(self):
        return "dump"

    def getExecutablePath(self):
        return "dump"

    def getMemory(self):
        return self

    def getBlocks(self):
        return self.blocks


class FakeScript:
    def __init__(self, program):
        self.program = program
        self.output = []
        self.errors = []

    def getCurrentProgram(self):
        return self.program

    def getMonitor(self):
        return FakeMonitor()

    def println(self, message):
        self.output.append(message)

    def printerr(self, message):
        self.errors.append(message)


class FakeGhidraScout(ghidra_scout.GhidraScout):
    regions_read = 0

    def read_region(self, region):
        # instead of a Java byte array filled by Ghidra
        self.regions_read += 1
        return b"".join(block.data for block in region.blocks)

    def read_memory(self, regions, address, size):
        for region in regions:
            for block in region.blocks:
                start = block.getStart().getUnsignedOffset()
                if start <= address < start + block.getSize():
                    return block.data[address - start : address - start + size]
        return b""


def scan_with_cli(base_address):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["scan", DUMP_PATH, "--db", DB_PATH, "--base-addr", hex(base_address), "--json", "--quiet"])
    assert code == 0
    return json.loads(stdout.getvalue())["apis"]


def hit(address, api, dll, bitness):
    return ghidra_scout.ApiHit(address, api, dll, 0, bitness)


class GhidraScoutTestSuite(unittest.TestCase):
    def testLabelNames(self):
        self.assertEqual("ReadFile", ghidra_scout.get_label_name("ReadFile", "kernel32.dll"))
        # exports by ordinal only are named after their DLL
        self.assertEqual("ws2_32.dll_ordinal_9", ghidra_scout.get_label_name("None<9>", "ws2_32.dll"))

    def testDbChoices(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("win7.json", "win10.json", "notes.txt"):
                with open(os.path.join(directory, name), "w") as f_out:
                    f_out.write("{}")
            self.assertEqual(
                ["win10.json", "win7.json", "Other file...", "Module list file..."],
                ghidra_scout.get_db_choices(directory),
            )
            self.assertEqual(
                ["Other file...", "Module list file..."],
                ghidra_scout.get_db_choices(os.path.join(directory, "missing")),
            )

    def testMemoryRegions(self):
        blocks = [
            FakeBlock(0x1000, size=0x1000),
            FakeBlock(0x2000, size=0x800),
            # uninitialized and not loaded blocks are no part of the memory scanned
            FakeBlock(0x2800, size=0x800, initialized=False),
            FakeBlock(0x3000, size=0x1000),
            FakeBlock(0x4000, size=0x100, loaded=False),
            FakeBlock(0x4100, size=0x100),
        ]
        regions = ghidra_scout.get_memory_regions(blocks)
        self.assertEqual([0x1000, 0x3000, 0x4100], [region.start.offset for region in regions])
        self.assertEqual([2, 1, 1], [len(region.blocks) for region in regions])

    def testScanFindsWhatTheCommandLineToolFinds(self):
        with open(DUMP_PATH, "rb") as f_dump:
            dump = f_dump.read()
        expected = [(0x1000 + api["offset"], api["api"], api["dll"]) for api in scan_with_cli(0x1000)]
        self.assertEqual(2, len(expected))
        # a dump split into adjacent blocks is scanned as one, a second region at its own base address
        for blocks in (
            [FakeBlock(0x1000, dump)],
            [FakeBlock(0x1000, dump[:0x80]), FakeBlock(0x1080, dump[0x80:]), FakeBlock(0x8000, b"\0" * 16)],
        ):
            script = FakeScript(FakeProgram(blocks))
            hits = FakeGhidraScout(script).scan([DB_PATH])
            assert hits is not None
            found = [(api.address.offset, api.api, f"{api.dll}({api.bitness} bit)") for api in hits]
            self.assertEqual(expected, found)
            self.assertEqual([], script.errors)

    def testModulesOutliveTheRun(self):
        """PyGhidra removes the modules a script imported after each run, the next run gets the same ones back"""
        import builtins
        import sys

        kept = getattr(builtins, ghidra_scout.KEPT_MODULES, None)
        names = [name for name in sys.modules if name == "apiscout" or name.startswith("apiscout.")]
        removed = {name: sys.modules.pop(name) for name in names}
        try:
            first = ghidra_scout.import_api_scout()
            for name in [name for name in sys.modules if name.startswith("apiscout")]:
                del sys.modules[name]
            self.assertIs(first, ghidra_scout.import_api_scout())
            self.assertIn("apiscout.ApiScout", getattr(builtins, ghidra_scout.KEPT_MODULES))
        finally:
            sys.modules.update(removed)
            if kept is None:
                delattr(builtins, ghidra_scout.KEPT_MODULES)
            else:
                setattr(builtins, ghidra_scout.KEPT_MODULES, kept)

    def testScanWithoutApiDb(self):
        script = FakeScript(FakeProgram([FakeBlock(0x1000, b"\0" * 16)]))
        self.assertIsNone(FakeGhidraScout(script).scan([DUMP_PATH]))
        self.assertIn("not an API DB", script.errors[0])
        self.assertIsNone(FakeGhidraScout(script).scan([DB_PATH + ".missing"]))
        self.assertIn("API DB not found", script.errors[1])

    def testOrderOfHits(self):
        hits = [
            hit(FakeAddress(0x20), "WaitForSingleObjectEx", "KernelBase.dll", 64),
            hit(FakeAddress(0x10), "InterlockedIncrement", "KernelBase.dll", 32),
            hit(FakeAddress(0x10), "ReadFile", "kernel32.dll", 64),
            # the same location resolved by a second API DB
            hit(FakeAddress(0x20), "WaitForSingleObjectEx", "KernelBase.dll", 64),
        ]
        ordered = ghidra_scout.order_hits(hits, 64)
        self.assertEqual(
            [(0x10, "ReadFile"), (0x10, "InterlockedIncrement"), (0x20, "WaitForSingleObjectEx")],
            [(found.address.offset, found.api) for found in ordered],
        )
        self.assertEqual(
            ["InterlockedIncrement", "ReadFile"], [found.api for found in ghidra_scout.order_hits(hits[1:3], 32)]
        )


class HeadlessScript(FakeScript):
    """a script that runs headless with the given arguments, and the answers of the dialogs of a script that does not"""

    def __init__(self, program, arguments=(), answers=()):
        super().__init__(program)
        self.arguments = list(arguments)
        self.answers = list(answers)

    def isRunningHeadless(self):
        return not self.answers

    def getScriptArgs(self):
        return self.arguments

    def askChoices(self, title, message, choices):
        self.asked = (title, message, list(choices))
        return self.answers[0]

    def askFile(self, title, approve):
        return mock.Mock(getAbsolutePath=lambda: self.answers[1])


class AnnotatingNothing(FakeGhidraScout):
    annotated = 0

    def annotate(self, hit):
        AnnotatingNothing.annotated += 1
        return True


def found(hits):
    return [(hit.address.offset, hit.api) for hit in hits]


class PlacementTestSuite(unittest.TestCase):
    """the DLLs of the API DBs are placed where the memory of the program has them, like `apiscout scan` does"""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = folder.name
        self.case = PlacementCase(self.folder)

    def scan(self, dump, modules=None, blocks=None):
        script = FakeScript(FakeProgram(blocks or [FakeBlock(BASE, dump)]))
        hits = FakeGhidraScout(script).scan([self.case.db_path], modules)
        return hits, script

    def testModuleList(self):
        hits, script = self.scan(self.case.sample)
        self.assertEqual(self.case.cli_apis(), found(hits))
        self.assertEqual(1, len(hits))
        self.assertFalse([line for line in script.output if "Placed" in line])
        hits, script = self.scan(self.case.sample, self.case.modules_path)
        self.assertEqual(self.case.cli_apis("--modules", self.case.modules_path), found(hits))
        self.assertEqual(3, len(hits))
        self.assertIn(
            "ApiScout: Warning: Placed 2 of 3 DLLs of case_db.json at their load addresses (2 from the modules file), "
            "1 keep the addresses of the DB.",
            script.output,
        )
        self.assertEqual([], script.errors)

    def testDllImagesDoNotPlace(self):
        # DLL images in the memory place nothing: the dump has kernel32 at the image, the module list does not say so
        dump, _ = self.case.with_image(self.folder)
        hits, script = self.scan(dump)
        self.assertEqual([], hits)
        self.assertFalse([line for line in script.output if "Placed" in line])

    def testHitsInTheImageOfAPlacedDll(self):
        dump, modules_path = self.case.with_image(self.folder)
        # the image is a region of its own: its import address table points to ntdll!Api2 like the sample does
        blocks = [FakeBlock(BASE, dump[:0x1000]), FakeBlock(self.case.IMAGE, dump[0x3000:])]
        hits, script = self.scan(dump, modules_path, blocks)
        self.assertEqual([(0x400010, "Api2"), (0x400014, "Api1")], found(hits))
        self.assertEqual([], script.errors)
        # `scan` of a flat dump does not leave them out
        self.assertEqual(3, len(self.case.cli_apis("--modules", modules_path, dump_path=self.flat(dump))))
        # in one region as well
        hits, _ = self.scan(dump, modules_path)
        self.assertEqual([(0x400010, "Api2"), (0x400014, "Api1")], found(hits))
        # a module list that has kernel32 elsewhere than the dump does, leaves nothing out
        hits, _ = self.scan(dump, self.case.modules_path, blocks)
        self.assertEqual([(0x400010, "Api2"), (self.case.IMAGE + 0x2000, "Api2")], found(hits))

    def flat(self, dump):
        path = os.path.join(self.folder, f"flat_0x{BASE:08x}")
        with open(path, "wb") as f_dump:
            f_dump.write(dump)
        return path

    def testModuleListAndDbsAreCheckedBeforeTheMemoryIsRead(self):
        script = FakeScript(FakeProgram([FakeBlock(BASE, self.case.sample)]))
        scout = FakeGhidraScout(script)
        self.assertIsNone(scout.scan([self.case.db_path], os.path.join(self.folder, "missing.txt")))
        self.assertIsNone(scout.scan([self.case.db_path + ".missing"], self.case.modules_path))
        self.assertEqual(0, scout.regions_read)
        self.assertEqual(2, len(script.errors))
        self.assertIn("can not read the module list", script.errors[0])
        self.assertIn("API DB not found", script.errors[1])
        self.assertIsNotNone(scout.scan([self.case.db_path], self.case.modules_path))
        self.assertEqual(1, scout.regions_read)

    @unittest.skipUnless(os.environ.get("APISCOUT_SAMPLES"), "set APISCOUT_SAMPLES to the folder with the samples")
    def testTrickbotWithTheDbOfAnotherSystem(self):
        sample = os.path.join(os.environ["APISCOUT_SAMPLES"], "trickbot_dump7_0x00400000")
        win7_db = os.path.join(os.path.dirname(THIS_DIR), "dbs", "win7_prof-n_sp1_example.json")
        if not os.path.isfile(sample):
            self.skipTest("sample not found")
        with open(sample, "rb") as f_dump:
            dump = f_dump.read()
        db_path, modules_path = rebase_db(win7_db, self.folder)
        results = {}
        for name, db, modules in (
            ("original", win7_db, None),
            ("rebased", db_path, None),
            ("placed", db_path, modules_path),
        ):
            script = FakeScript(FakeProgram([FakeBlock(0x400000, dump)]))
            results[name] = FakeGhidraScout(script).scan([db], modules)
        self.assertEqual((183, 0, 183), tuple(len(results[name]) for name in ("original", "rebased", "placed")))
        self.assertEqual(found(results["original"]), found(results["placed"]))

    def testModuleListThatCanNotBeUsed(self):
        hits, script = self.scan(self.case.sample, os.path.join(self.folder, "missing.txt"))
        self.assertIsNone(hits)
        self.assertRegex(script.errors[0], "ApiScout: can not read the module list .*missing.txt")

    def testHeadlessArguments(self):
        program = FakeProgram([FakeBlock(BASE, self.case.sample)])
        for arguments, num_hits in (
            ([self.case.db_path], 1),
            ([self.case.db_path, "--modules", self.case.modules_path], 3),
            (["--modules", self.case.modules_path, self.case.db_path], 3),
            ([self.case.db_path, f"--modules={self.case.modules_path}"], 3),
            (["-m", self.case.modules_path, self.case.db_path], 3),
        ):
            script = HeadlessScript(program, arguments)
            AnnotatingNothing.annotated = 0
            AnnotatingNothing(script).run()
            self.assertEqual([], script.errors)
            self.assertIn(f"ApiScout found {num_hits} API references", script.output)
            self.assertEqual(num_hits, AnnotatingNothing.annotated)
        for arguments, message in (
            ([self.case.db_path, "--modules"], "--modules needs the file"),
            (["--modules", self.case.modules_path], "Usage: ghidra_scout.py <path to API DB>"),
            ([self.case.db_path, "--modules", self.case.db_path + ".missing"], "can not read the module list"),
        ):
            script = HeadlessScript(program, arguments)
            AnnotatingNothing(script).run()
            self.assertIn(message, script.errors[0])

    def testDialog(self):
        folder = os.path.join(self.folder, "dbs")
        os.mkdir(folder)
        for name in ("a.json", "b.json"):
            with open(os.path.join(folder, name), "w") as f_db:
                f_db.write("{}")
        modules = {
            "ghidra": mock.Mock(),
            "ghidra.util": mock.Mock(),
            "ghidra.util.exception": mock.Mock(CancelledException=type("CancelledException", (Exception,), {})),
            "java": mock.Mock(),
            "java.util": mock.Mock(ArrayList=list),
        }
        program = FakeProgram([FakeBlock(BASE, self.case.sample)])
        with mock.patch.dict("sys.modules", modules):
            script = HeadlessScript(program, answers=[["b.json", "Module list file..."], self.case.modules_path])
            db_paths, module_list = FakeGhidraScout(script).ask_for_databases(folder)
            self.assertEqual([os.path.join(folder, "b.json")], db_paths)
            self.assertEqual(self.case.modules_path, module_list)
            self.assertEqual(["a.json", "b.json", "Other file...", "Module list file..."], script.asked[2])
            # the module list is optional
            script = HeadlessScript(program, answers=[["a.json"], ""])
            self.assertEqual(
                ([os.path.join(folder, "a.json")], None), FakeGhidraScout(script).ask_for_databases(folder)
            )
            # a module list alone is no choice of API DB
            script = HeadlessScript(program, answers=[["Module list file..."], self.case.modules_path])
            with self.assertRaises(modules["ghidra.util.exception"].CancelledException):
                FakeGhidraScout(script).ask_for_databases(folder)


if __name__ == "__main__":
    unittest.main()
