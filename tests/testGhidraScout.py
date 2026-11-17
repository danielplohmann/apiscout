import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

from apiscout import cli

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
    def read_region(self, region):
        # instead of a Java byte array filled by Ghidra
        return b"".join(block.data for block in region.blocks)


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
            self.assertEqual(["win10.json", "win7.json", "Other file..."], ghidra_scout.get_db_choices(directory))
            self.assertEqual(["Other file..."], ghidra_scout.get_db_choices(os.path.join(directory, "missing")))

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


if __name__ == "__main__":
    unittest.main()
