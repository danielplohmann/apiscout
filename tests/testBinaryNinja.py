"""
Tests of the Binary Ninja plugin against a stand-in for the binaryninja module, which follows the signatures of
the Binary Ninja Python API (binaryninja-api/python). Binary Ninja itself is not needed.

The tests on real memory dumps need the folder with the samples in $APISCOUT_SAMPLES, they are reported as
skipped without it.
"""

import contextlib
import enum
import importlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from apiscout import cli

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_DIR = os.path.dirname(THIS_DIR)
DB_DIR = os.path.join(REPO_DIR, "dbs")
WIN7_DB = os.path.join(DB_DIR, "win7_prof-n_sp1_example.json")
WIN10_DB = os.path.join(DB_DIR, "win10_prof_1803_example.json")
SAMPLE_DIR = os.environ.get("APISCOUT_SAMPLES", "")
TRICKBOT = os.path.join(SAMPLE_DIR, "trickbot_dump7_0x00400000")
COBALT_STRIKE = os.path.join(SAMPLE_DIR, "cobalt_strike_e8a66911_dump7_0x00000000001c0000")


def needs_sample(path):
    return unittest.skipUnless(
        SAMPLE_DIR and os.path.isfile(path),
        f"sample {os.path.basename(path)} not found, set APISCOUT_SAMPLES to the folder with the samples",
    )


# ---------------------------------------------------------------------------------------------------------------
# the stand-in for the binaryninja module


class SymbolType(enum.IntEnum):
    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5


class TypeClass(enum.IntEnum):
    VoidTypeClass = 0
    IntegerTypeClass = 2
    PointerTypeClass = 6
    FunctionTypeClass = 8


class FakeType:
    def __init__(self, type_class, width=0, target=None, name=""):
        self.type_class = type_class
        self.width = width
        self.target = target
        self.name = name

    def __repr__(self):
        return f"<type {self.type_class.name} {self.width} {self.target or self.name}>"

    @staticmethod
    def void():
        return FakeType(TypeClass.VoidTypeClass)

    @staticmethod
    def int(width, sign=True, alternate_name=""):
        return FakeType(TypeClass.IntegerTypeClass, width, name=f"{'' if sign else 'u'}int{width * 8}_t")

    @staticmethod
    def pointer_of_width(width, type, const=False, volatile=False, ref_type=None):
        return FakeType(TypeClass.PointerTypeClass, width, target=type)

    @staticmethod
    def function(ret=None, params=None, calling_convention=None, variable_arguments=None, stack_adjust=None):
        return FakeType(TypeClass.FunctionTypeClass, name=f"function({len(params or [])})")


class FakeSymbol:
    def __init__(
        self, sym_type, addr, short_name, full_name=None, raw_name=None, binding=None, namespace=None, ordinal=0
    ):
        self.type = sym_type
        self.address = addr
        self.name = short_name
        self.short_name = short_name
        self.namespace = namespace
        self.auto = False

    def __repr__(self):
        return f"<{self.type.name}: {self.name} @ 0x{self.address:x}>"


class FakePluginCommand:
    registered = []

    @classmethod
    def register(cls, name, description, action, is_valid=None):
        cls.registered.append((name, description, action, is_valid))


class FakeBackgroundTaskThread:
    started = []

    def __init__(self, initial_progress_text="", can_cancel=False):
        self.progress = initial_progress_text
        self.can_cancel = can_cancel
        self.cancelled = False
        self.thread = threading.Thread(target=self.run)

    def run(self):
        pass

    def start(self):
        FakeBackgroundTaskThread.started.append(self)
        self.thread.start()

    def join(self, timeout=None):
        self.thread.join(timeout)


class Field:
    def __init__(self, prompt, *args):
        self.prompt = prompt
        self.args = args
        self.result = None


class CheckboxField(Field):
    pass


class OpenFileNameField(Field):
    pass


class IntegerField(Field):
    pass


class FakeInteraction:
    """answers the forms with the function in form_handler, which sets the results of the fields"""

    form_handler = None
    forms = []

    @classmethod
    def get_form_input(cls, fields, title):
        cls.forms.append((title, fields))
        return cls.form_handler(fields) if cls.form_handler else False


LOG = []


def make_module(name, **attributes):
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    return module


def fake_binaryninja_modules():
    interaction = make_module(
        "binaryninja.interaction",
        CheckboxField=CheckboxField,
        OpenFileNameField=OpenFileNameField,
        IntegerField=IntegerField,
        get_form_input=FakeInteraction.get_form_input,
    )
    modules = {
        "binaryninja.enums": make_module("binaryninja.enums", SymbolType=SymbolType, TypeClass=TypeClass),
        "binaryninja.types": make_module("binaryninja.types", Symbol=FakeSymbol, Type=FakeType),
        "binaryninja.plugin": make_module(
            "binaryninja.plugin", PluginCommand=FakePluginCommand, BackgroundTaskThread=FakeBackgroundTaskThread
        ),
        "binaryninja.interaction": interaction,
        "binaryninja.log": make_module(
            "binaryninja.log",
            log_info=lambda text, logger="": LOG.append(("info", text)),
            log_warn=lambda text, logger="": LOG.append(("warn", text)),
            log_error=lambda text, logger="": LOG.append(("error", text)),
        ),
    }
    package = make_module("binaryninja", interaction=interaction)
    package.__path__ = []
    modules["binaryninja"] = package
    return modules


@contextlib.contextmanager
def fake_binaryninja():
    """the stand-in is only visible while the plugin modules are imported"""
    fakes = fake_binaryninja_modules()
    names = list(fakes) + ["apiscout.BinaryNinjaTools", "apiscout.binja_scout", "binja_scout"]
    previous = {name: sys.modules.get(name) for name in names}
    for name in names:
        sys.modules.pop(name, None)
    sys.modules.update(fakes)
    try:
        yield
    finally:
        for name, module in previous.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with fake_binaryninja():
    tools = importlib.import_module("apiscout.BinaryNinjaTools")


class FakeSegment:
    def __init__(self, start, length, content):
        self.start = start
        self.end = start + length
        self.length = length
        # bytes backed by data, the rest of the segment reads as nothing here
        self.content = content
        self.data_length = len(content)

    def __contains__(self, address):
        return self.start <= address < self.end


class FakeTypeLibrary:
    def __init__(self, name, objects, alternate_names=()):
        self.name = name
        self.objects = objects
        self.alternate_names = list(alternate_names)

    def get_named_object(self, name):
        return self.objects.get(str(name))


class FakePlatform:
    def __init__(self, name, libraries):
        self.name = name
        self.libraries = libraries

    @property
    def type_libraries(self):
        return list(self.libraries)

    def get_type_libraries_by_name(self, name):
        return [lib for lib in self.libraries if name in [lib.name] + lib.alternate_names]


class FakeRef:
    def __init__(self, address):
        self.address = address
        self.function = None
        self.arch = None


class FakeFunction:
    def __init__(self, start):
        self.start = start

    def __repr__(self):
        return f"<func 0x{self.start:x}>"


class FakeBasicBlock:
    def __init__(self, function):
        self.function = function


class FakeBinaryView:
    def __init__(self, segments, address_size=4, platform=None):
        self.segments = segments
        self.address_size = address_size
        self.platform = platform
        self.arch = object()
        self.session_data = {}
        self.data_vars = {}
        self.symbols = {}
        self.type_libraries = []
        self.recorded = {}
        self.code_refs = {}
        self.data_refs = {}
        # addresses of instructions of the entry function, which always counts as referenced
        self.code = set()
        self.entry_point = 0
        self.entry_function = FakeFunction(0)
        self.entry_functions = [self.entry_function]
        # addresses of instructions of other functions: {address: function}
        self.function_code = {}
        self.removed_functions = []
        self.calls = []
        self.undo = []
        self.reports = []

    @property
    def start(self):
        return min(segment.start for segment in self.segments)

    def get_segment_at(self, addr):
        return next((segment for segment in self.segments if addr in segment), None)

    def read(self, addr, length):
        """at most length bytes, up to the first address without data"""
        result = b""
        while len(result) < length:
            segment = self.get_segment_at(addr + len(result))
            if segment is None:
                break
            offset = addr + len(result) - segment.start
            chunk = segment.content[offset : offset + length - len(result)]
            if not chunk:
                break
            result += chunk
        return result

    def get_basic_blocks_at(self, addr):
        blocks = [FakeBasicBlock(self.entry_function)] if addr in self.code else []
        if addr in self.function_code:
            blocks.append(FakeBasicBlock(self.function_code[addr]))
        return blocks

    def add_function_code(self, start, end):
        """a function without references at start with instructions up to end"""
        function = FakeFunction(start)
        for address in range(start, end):
            self.function_code[address] = function
        return function

    def remove_user_function(self, func):
        self.calls.append(("remove_user_function", func.start))
        self.removed_functions.append(func.start)
        self.function_code = {addr: function for addr, function in self.function_code.items() if function is not func}

    def get_code_refs(self, addr, length=None, max_items=None):
        yield from (FakeRef(address) for address in self.code_refs.get(addr, []))

    def get_data_refs(self, addr, length=None, max_items=None):
        yield from self.data_refs.get(addr, [])

    def define_user_data_var(self, addr, var_type, name=None):
        self.calls.append(("define_user_data_var", addr, var_type))
        self.data_vars[addr] = var_type

    def define_user_symbol(self, sym):
        self.calls.append(("define_user_symbol", sym.address, sym))
        self.symbols.setdefault(sym.address, []).append(sym)

    def undefine_user_symbol(self, sym):
        self.calls.append(("undefine_user_symbol", sym.address, sym))
        self.symbols[sym.address].remove(sym)

    def get_symbol_at(self, addr, namespace=None):
        # the symbol with the lowest type value is used, ties are broken by name
        candidates = sorted(self.symbols.get(addr, []), key=lambda sym: (sym.type, sym.name))
        return candidates[0] if candidates else None

    def get_type_library(self, name):
        return next((lib for lib in self.type_libraries if lib.name == name), None)

    def add_type_library(self, lib):
        self.type_libraries.append(lib)

    def import_library_object(self, name, lib=None):
        libraries = [lib] if lib is not None else self.type_libraries
        for library in libraries:
            assert library in self.type_libraries, "objects are imported from libraries of the view"
            if library.get_named_object(name) is not None:
                return library.get_named_object(name)
        return None

    def record_imported_object_library(self, lib, name, addr, platform=None):
        self.recorded[addr] = (lib.name, name)

    def begin_undo_actions(self, anonymous_allowed=True):
        self.undo.append("begin")
        return f"state{len(self.undo)}"

    def commit_undo_actions(self, id=None):
        self.undo.append(("commit", id))

    def update_analysis(self):
        self.calls.append(("update_analysis",))

    def show_markdown_report(self, title, contents, plaintext=""):
        self.reports.append((title, contents, plaintext))

    def symbol_names(self):
        return {addr: self.get_symbol_at(addr).name for addr in self.symbols if self.get_symbol_at(addr)}


def function_type(name="prototype"):
    return FakeType(TypeClass.FunctionTypeClass, name=name)


def cli_hits(dump, db):
    """the number of API references `apiscout scan --json` reports"""
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["scan", dump, "--db", db, "--json", "--quiet"])
    assert code == 0
    return json.loads(output.getvalue())


def dump_view(path, base, address_size, platform=None):
    with open(path, "rb") as f_dump:
        content = f_dump.read()
    return FakeBinaryView([FakeSegment(base, len(content), content)], address_size, platform)


def write_db(path, dlls):
    """a minimal API DB: dlls as {name: (bitness, base address, [(name or None, ordinal, rva)])}"""
    db = {"os_name": "test", "os_version": "1", "aslr_offsets": False, "num_dlls": len(dlls), "num_apis": 0, "dlls": {}}
    for name, (bitness, base, exports) in dlls.items():
        db["dlls"][f"{bitness}_1.0_{name}_0x{base:x}"] = {
            "bitness": bitness,
            "base_address": base,
            "exports": [{"name": api or "None", "ordinal": ordinal, "address": rva} for api, ordinal, rva in exports],
        }
        db["num_apis"] += len(exports)
    with open(path, "w") as f_db:
        json.dump(db, f_db)


class BinaryNinjaImportTest(unittest.TestCase):
    def testPackageDoesNotImportBinaryNinja(self):
        code = (
            "import sys, apiscout, apiscout.ApiScout, apiscout.cli; "
            "sys.exit(1 if any(name.split('.')[0] == 'binaryninja' for name in sys.modules) else 0)"
        )
        result = subprocess.run([sys.executable, "-c", code], cwd=REPO_DIR, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)

    @unittest.skipIf(importlib.util.find_spec("binaryninja"), "Binary Ninja's Python API is installed")
    def testWithoutBinaryNinja(self):
        result = subprocess.run(
            [sys.executable, "-c", "import apiscout.BinaryNinjaTools"], cwd=REPO_DIR, capture_output=True, text=True
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("binaryninja", result.stderr)

    def testPluginRegistersCommands(self):
        FakePluginCommand.registered.clear()
        with fake_binaryninja():
            sys.path.insert(0, REPO_DIR)
            try:
                plugin = importlib.import_module("binja_scout")
            finally:
                sys.path.remove(REPO_DIR)
        self.assertTrue(callable(plugin.scan_and_annotate))
        names = [entry[0] for entry in FakePluginCommand.registered]
        self.assertEqual(
            [
                "ApiScout\\Scan for API references...",
                "ApiScout\\Show results",
                "ApiScout\\Annotate all",
                "ApiScout\\Annotate filtered...",
                "ApiScout\\Scan and annotate all...",
            ],
            names,
        )
        # the module the extension manager imports for the plugin installed as "apiscout" registers them once
        self.assertEqual(len(names), len(set(names)))
        FakePluginCommand.registered.clear()
        with fake_binaryninja():
            module = importlib.import_module("apiscout.binja_scout")
        self.assertEqual("apiscout.BinaryNinjaTools", module.scan_and_annotate.__module__)
        self.assertEqual(names, [entry[0] for entry in FakePluginCommand.registered])
        view = FakeBinaryView([FakeSegment(0x1000, 0x10, b"\0" * 0x10)])
        is_valid = {entry[0]: entry[3] for entry in FakePluginCommand.registered}
        self.assertIsNone(is_valid["ApiScout\\Scan for API references..."])
        self.assertFalse(is_valid["ApiScout\\Annotate all"](view))
        view.session_data["apiscout"] = {"rows": [], "status": {}}
        self.assertFalse(is_valid["ApiScout\\Annotate all"](view))
        view.session_data["apiscout"] = {"rows": [[0x1000, 1, "a.dll (32bit)", "A", 1]], "status": {}}
        self.assertTrue(is_valid["ApiScout\\Annotate all"](view))

    def testPluginJson(self):
        with open(os.path.join(REPO_DIR, "plugin.json")) as f_json:
            metadata = json.load(f_json)
        with open(os.path.join(REPO_DIR, "pyproject.toml")) as f_project:
            self.assertIn(f'version = "{metadata["version"]}"', f_project.read())
        # Binary Ninja 6.0 ignores subdir: it installs the whole repository and imports its root
        self.assertNotIn("subdir", metadata)
        self.assertTrue(os.path.isfile(os.path.join(REPO_DIR, "__init__.py")))
        self.assertEqual(["python3"], metadata["api"])
        # the package comes with the repository, only its dependencies are installed
        self.assertEqual(["numpy"], metadata["dependencies"]["pip"])


class MemoryTest(unittest.TestCase):
    def testSegmentsWithGaps(self):
        view = FakeBinaryView(
            [
                FakeSegment(0x3000, 0x100, b"c" * 0x100),
                FakeSegment(0x1000, 0x1000, b"a" * 0x1000),
                # adjacent to the first one
                FakeSegment(0x2000, 0x800, b"b" * 0x800),
                # only part of it has data, the next one is adjacent to the end of the segment, not of the data
                FakeSegment(0x5000, 0x1000, b"d" * 0x10),
                FakeSegment(0x6000, 0x10, b"e" * 0x10),
                # no data at all
                FakeSegment(0x8000, 0x10, b""),
            ]
        )
        # read as zeros by Binary Ninja, without bytes of the dump, e.g. its section of synthetic builtins
        synthetic = FakeSegment(0x9000, 0x18, b"\0" * 0x18)
        synthetic.data_length = 0
        view.segments.append(synthetic)
        memory = tools.get_memory(view)
        self.assertEqual([0x1000, 0x3000, 0x5000, 0x6000], sorted(memory))
        self.assertEqual(b"a" * 0x1000 + b"b" * 0x800, memory[0x1000])
        self.assertEqual(b"c" * 0x100, memory[0x3000])
        self.assertEqual(b"d" * 0x10, memory[0x5000])
        self.assertEqual(b"e" * 0x10, memory[0x6000])

    def testScanAcrossSegments(self):
        # API addresses in two segments separated by a gap, one pointing into the view itself
        path = os.path.join(THIS_DIR, "minimal_db.json")
        with open(path) as f_db:
            db = json.load(f_db)
        entry = next(iter(db["dlls"].values()))
        api_address = entry["base_address"] + entry["exports"][0]["address"]
        api_name = entry["exports"][0]["name"]
        first = b"\0" * 0x10 + api_address.to_bytes(4, "little") + b"\0" * 0x0C
        second = b"\0" * 8 + api_address.to_bytes(4, "little") + (0x1004).to_bytes(4, "little")
        view = FakeBinaryView([FakeSegment(0x1000, len(first), first), FakeSegment(0x3000, len(second), second)])
        view.code_refs[0x3008] = [0x1000, 0x1100]
        rows = tools.scan(view, [path])
        self.assertEqual([0x1010, 0x3008], [row[0] for row in rows])
        self.assertEqual({api_name}, {row[3] for row in rows})
        self.assertEqual([api_address] * 2, [row[1] for row in rows])
        # the references known to Binary Ninja count as well
        self.assertEqual([0, 2], [row[4] for row in rows])


class DumpTest(unittest.TestCase):
    def setUp(self):
        LOG.clear()

    @needs_sample(TRICKBOT)
    def testTrickbot32bit(self):
        expected = cli_hits(TRICKBOT, WIN7_DB)
        libraries = [
            FakeTypeLibrary("ws2_32.dll", {"getaddrinfo": function_type("getaddrinfo"), "WSAStartup": function_type()}),
            FakeTypeLibrary("user32.dll", {"SetTimer": function_type("SetTimer")}),
            # found through the libraries of the platform, not by the name of the DLL
            FakeTypeLibrary("ntdll_types.dll", {"ZwDelayExecution": function_type("ZwDelayExecution")}),
            # an object that is no function is not taken as prototype
            FakeTypeLibrary("other.dll", {"gethostname": FakeType.int(4)}),
        ]
        view = dump_view(TRICKBOT, 0x400000, 4, FakePlatform("windows-x86", libraries))
        state = tools.scan_and_annotate(view, [WIN7_DB])
        rows = state["rows"]
        self.assertEqual(len(expected["apis"]), len(rows))
        self.assertEqual(183, len(rows))
        self.assertEqual(
            sorted((0x400000 + api["offset"], api["api"]) for api in expected["apis"]), [(r[0], r[3]) for r in rows]
        )
        self.assertEqual(len(rows), state["annotated"] + state["skipped"])
        self.assertEqual(len(rows), state["annotated"])
        self.assertEqual(["begin", ("commit", "state1")], view.undo)
        self.assertEqual(("update_analysis",), view.calls[-1])
        by_address = {row[0]: row for row in rows}
        self.assertEqual("getaddrinfo", by_address[0x420004][3])
        symbol = view.get_symbol_at(0x420004)
        self.assertEqual((SymbolType.ImportAddressSymbol, "getaddrinfo"), (symbol.type, symbol.name))
        pointer = view.data_vars[0x420004]
        self.assertEqual((TypeClass.PointerTypeClass, 4), (pointer.type_class, pointer.width))
        self.assertEqual("getaddrinfo", pointer.target.name)
        self.assertEqual(("ws2_32.dll", "getaddrinfo"), view.recorded[0x420004])
        self.assertEqual("annotated", state["status"][tuple(by_address[0x420004][:4])])
        self.assertEqual("SetTimer", view.data_vars[0x420014].target.name)
        zw_delay = next(row for row in rows if row[3] == "ZwDelayExecution")
        self.assertEqual("ZwDelayExecution", view.data_vars[zw_delay[0]].target.name)
        self.assertEqual(("ntdll_types.dll", "ZwDelayExecution"), view.recorded[zw_delay[0]])
        # without prototype, the location is still a named pointer
        self.assertEqual("gethostname", view.get_symbol_at(0x420008).name)
        self.assertEqual(TypeClass.VoidTypeClass, view.data_vars[0x420008].target.type_class)
        self.assertEqual("annotated (no type information)", state["status"][tuple(by_address[0x420008][:4])])
        self.assertNotIn(0x420008, view.recorded)
        # only the libraries that provide a prototype are added to the view
        self.assertEqual(["ws2_32.dll", "user32.dll", "ntdll_types.dll"], [lib.name for lib in view.type_libraries])
        self.assertEqual(len(rows), len(view.symbol_names()))
        self.assertTrue(all(name == by_address[address][3] for address, name in view.symbol_names().items()))

    @needs_sample(TRICKBOT)
    def testTrickbotSplitIntoSegments(self):
        # the same memory as two adjacent segments and a copy of a part behind a gap
        with open(TRICKBOT, "rb") as f_dump:
            content = f_dump.read()
        whole = tools.scan(dump_view(TRICKBOT, 0x400000, 4), [WIN7_DB])
        view = FakeBinaryView(
            [
                FakeSegment(0x400000, 0x20000, content[:0x20000]),
                FakeSegment(0x420000, len(content) - 0x20000, content[0x20000:]),
            ]
        )
        self.assertEqual(whole, tools.scan(view, [WIN7_DB]))
        table = content[0x20000:0x20200]
        view.segments.append(FakeSegment(0x500000, len(table), table))
        rows = tools.scan(view, [WIN7_DB])
        copied = [row for row in rows if row[0] >= 0x500000]
        self.assertEqual(
            [(row[0] - 0xE0000, row[3]) for row in copied],
            [(row[0], row[3]) for row in whole if 0x420000 <= row[0] < 0x420200 - 3],
        )

    @needs_sample(TRICKBOT)
    def testFilteredAnnotation(self):
        view = dump_view(TRICKBOT, 0x400000, 4, FakePlatform("windows-x86", []))
        state = tools.scan_and_annotate(view, [WIN7_DB], distance=32)
        # the chance hit far away from all other APIs is left out
        self.assertNotIn(0x409AEF, view.symbols)
        self.assertEqual(len(tools.filter_by_distance(state["rows"], 32)), state["annotated"])
        self.assertLess(state["annotated"], len(state["rows"]))

    @needs_sample(COBALT_STRIKE)
    def testCobaltStrike64bitWin10(self):
        # the dump was not taken on the system of this DB: its hits are chance 32bit values in a 64bit view
        expected = cli_hits(COBALT_STRIKE, WIN10_DB)
        view = dump_view(COBALT_STRIKE, 0x1C0000, 8, FakePlatform("windows-x86_64", []))
        state = tools.scan_and_annotate(view, [WIN10_DB])
        rows = state["rows"]
        self.assertEqual(len(expected["apis"]), len(rows))
        self.assertEqual(13, len(rows))
        self.assertEqual({32}, {tools.get_bitness(row) for row in rows})
        for row in rows:
            self.assertEqual(SymbolType.DataSymbol, view.get_symbol_at(row[0]).type)
            self.assertEqual((TypeClass.IntegerTypeClass, 4), (view.data_vars[row[0]].type_class, 4))
            self.assertEqual("annotated (no pointer of this view)", state["status"][tuple(row[:4])])

    @needs_sample(COBALT_STRIKE)
    def testCobaltStrike64bitWin7(self):
        expected = cli_hits(COBALT_STRIKE, WIN7_DB)
        libraries = [
            FakeTypeLibrary("advapi32.dll", {"OpenProcessToken": function_type("OpenProcessToken")}),
            FakeTypeLibrary("kernel32.dll", {"ReadProcessMemory": function_type("ReadProcessMemory")}),
        ]
        view = dump_view(COBALT_STRIKE, 0x1C0000, 8, FakePlatform("windows-x86_64", libraries))
        state = tools.scan_and_annotate(view, [WIN7_DB])
        rows = state["rows"]
        self.assertEqual(len(expected["apis"]), len(rows))
        self.assertEqual(196, len(rows))
        self.assertEqual({64}, {tools.get_bitness(row) for row in rows})
        self.assertEqual(len(rows), state["annotated"])
        token = next(row for row in rows if row[3] == "OpenProcessToken")
        self.assertEqual(0x1EC008, token[0])
        self.assertEqual(SymbolType.ImportAddressSymbol, view.get_symbol_at(token[0]).type)
        self.assertEqual((TypeClass.PointerTypeClass, 8), (view.data_vars[token[0]].type_class, 8))
        self.assertEqual("OpenProcessToken", view.data_vars[token[0]].target.name)
        read_memory = [row for row in rows if row[3] == "ReadProcessMemory"]
        for row in read_memory:
            self.assertEqual("ReadProcessMemory", view.data_vars[row[0]].target.name)
            self.assertEqual("ReadProcessMemory", view.get_symbol_at(row[0]).name)
        self.assertEqual(
            {tuple(row[:4]): "annotated" for row in [token] + read_memory},
            {key: value for key, value in state["status"].items() if value == "annotated"},
        )


class AnnotationTest(unittest.TestCase):
    def setUp(self):
        LOG.clear()

    def makeView(self, address_size=4, libraries=()):
        return FakeBinaryView(
            [FakeSegment(0x1000, 0x100, b"\0" * 0x100)], address_size, FakePlatform("windows", list(libraries))
        )

    def testOrdinalNames(self):
        view = self.makeView(libraries=[FakeTypeLibrary("ws2_32.dll", {"None<23>": function_type()})])
        rows = [
            [0x1000, 0x41AC1234, "ws2_32.dll_0x41ac0000 (32bit)", "None<23>", 1],
            [0x1008, 0x41AC2234, "oleaut32.dll (32bit)", "None<9>", 1],
        ]
        status = {}
        self.assertEqual((2, 0), tools.annotate(view, rows, status))
        self.assertEqual("ws2_32_dll_ordinal_23", view.get_symbol_at(0x1000).name)
        self.assertEqual(SymbolType.ImportAddressSymbol, view.get_symbol_at(0x1000).type)
        self.assertEqual("oleaut32_dll_ordinal_9", view.get_symbol_at(0x1008).name)
        # no prototype is looked up for an API without a name
        self.assertEqual(TypeClass.VoidTypeClass, view.data_vars[0x1000].target.type_class)
        self.assertEqual([], view.type_libraries)
        self.assertEqual("annotated (no type information)", status[tuple(rows[0][:4])])
        self.assertEqual("ws2_32_dll_ordinal_23", tools.get_api_name(rows[0]))
        self.assertFalse(any("No type information" in text for _, text in LOG))

    def testOrdinalNamesOfCrawl(self):
        # an export without name in an API DB gets the name None<ordinal> in the crawl
        folder = tempfile.mkdtemp()
        db_path = os.path.join(folder, "ordinal.json")
        write_db(db_path, {"ws2_32.dll": (64, 0x7FF00000000, [(None, 23, 0x1234), ("bind", 2, 0x2000)])})
        try:
            content = (0x7FF00001234).to_bytes(8, "little") + (0x7FF00002000).to_bytes(8, "little")
            view = FakeBinaryView([FakeSegment(0x180000, len(content), content)], 8, FakePlatform("windows", []))
            state = tools.scan_and_annotate(view, [db_path])
        finally:
            shutil.rmtree(folder)
        self.assertEqual(["None<23>", "bind"], [row[3] for row in state["rows"]])
        self.assertEqual("ws2_32_dll_ordinal_23", view.get_symbol_at(0x180000).name)
        self.assertEqual("bind", view.get_symbol_at(0x180008).name)
        self.assertEqual(8, view.data_vars[0x180000].width)

    def testBothBitnessesAtOneLocation(self):
        # a 64bit view: the 64bit hit is applied, the 32bit hit at the same location is skipped
        view = self.makeView(8, [FakeTypeLibrary("kernel32.dll", {"ReadProcessMemory": function_type("RPM")})])
        rows = [
            [0x1000, 0x7777, "user32.dll_0x7000 (32bit)", "SetTimer", 0],
            [0x1000, 0x7FF00007777, "kernel32.dll_0x7ff00000000 (64bit)", "ReadProcessMemory", 0],
        ]
        status = {}
        self.assertEqual((1, 1), tools.annotate(view, rows, status))
        self.assertEqual("ReadProcessMemory", view.get_symbol_at(0x1000).name)
        self.assertEqual("RPM", view.data_vars[0x1000].target.name)
        self.assertEqual(8, view.data_vars[0x1000].width)
        self.assertEqual("skipped: location is annotated as ReadProcessMemory", status[tuple(rows[0][:4])])
        # a 32bit view: the 32bit hit is the pointer
        view = self.makeView(4)
        status = {}
        self.assertEqual((1, 1), tools.annotate(view, rows, status))
        self.assertEqual("SetTimer", view.get_symbol_at(0x1000).name)
        self.assertEqual(4, view.data_vars[0x1000].width)
        self.assertEqual(SymbolType.ImportAddressSymbol, view.get_symbol_at(0x1000).type)

    def testSkippedLocations(self):
        view = self.makeView(4)
        view.code.add(0x1022)
        rows = [
            [0x1010, 0x7000, "a.dll (32bit)", "First", 0],
            # overlaps the pointer at 0x1010
            [0x1012, 0x7004, "a.dll (32bit)", "Overlapping", 0],
            # within an instruction
            [0x1020, 0x7008, "a.dll (32bit)", "InCode", 0],
            # reaches beyond the segment
            [0x10FE, 0x700C, "a.dll (32bit)", "AtTheEnd", 0],
            [0x1040, 0x7010, "a.dll", "NoBitness", 0],
        ]
        status = {}
        self.assertEqual((1, 4), tools.annotate(view, rows, status))
        self.assertEqual(
            [
                "annotated (no type information)",
                "skipped: overlapping First",
                "skipped: part of an instruction",
                "skipped: at the end of its segment",
                "skipped: of unknown pointer size",
            ],
            [status[tuple(row[:4])] for row in rows],
        )
        self.assertEqual([0x1010], list(view.symbols))
        # an annotation made before also blocks overlapping locations later
        self.assertEqual((0, 1), tools.annotate(view, [rows[1]], status))

    def testFunctionsInTheWay(self):
        # the linear sweep of Binary Ninja finds functions in a table of pointers, e.g. in a raw memory dump
        view = self.makeView(4, [FakeTypeLibrary("kernel32.dll", {"ReadProcessMemory": function_type("RPM")})])
        spurious = view.add_function_code(0x100E, 0x1018)
        called = view.add_function_code(0x1040, 0x1048)
        view.code_refs[0x1040] = [0x1000]
        pointed_to = view.add_function_code(0x1060, 0x1068)
        view.data_refs[0x1060] = [0x1080]
        rows = [
            [0x1010, 0x7000, "kernel32.dll (32bit)", "ReadProcessMemory", 1],
            # the function is gone after the first row
            [0x1014, 0x7004, "kernel32.dll (32bit)", "CreateFileA", 1],
            [0x1044, 0x7008, "kernel32.dll (32bit)", "Called", 1],
            [0x1060, 0x700C, "kernel32.dll (32bit)", "PointedTo", 1],
        ]
        status = {}
        self.assertEqual((2, 2), tools.annotate(view, rows, status))
        self.assertEqual([0x100E], view.removed_functions)
        self.assertEqual(
            [
                "annotated",
                "annotated (no type information)",
                "skipped: part of an instruction",
                "skipped: part of an instruction",
            ],
            [status[tuple(row[:4])] for row in rows],
        )
        self.assertEqual("RPM", view.data_vars[0x1010].target.name)
        # the function is removed before the pointer is defined
        self.assertLess(
            view.calls.index(("remove_user_function", 0x100E)),
            view.calls.index(("define_user_data_var", 0x1010, view.data_vars[0x1010])),
        )
        self.assertEqual({called, pointed_to}, set(view.function_code.values()))
        self.assertNotIn(spurious, view.function_code.values())
        self.assertTrue(any("Removing the function at 0x100e" in text for _, text in LOG))

    def testEntryFunctionIsKept(self):
        view = self.makeView(4)
        view.entry_point = 0x1010
        view.add_function_code(0x1010, 0x1014)
        status = {}
        rows = [[0x1010, 0x7000, "a.dll (32bit)", "A", 0]]
        self.assertEqual((0, 1), tools.annotate(view, rows, status))
        self.assertEqual("skipped: part of an instruction", status[tuple(rows[0][:4])])
        self.assertEqual([], view.removed_functions)

    def testCodeIsKeptForValuesOfTheOtherBitness(self):
        view = self.makeView(8)
        view.add_function_code(0x1010, 0x1018)
        status = {}
        rows = [[0x1010, 0x7000, "a.dll (32bit)", "A", 0]]
        self.assertEqual((0, 1), tools.annotate(view, rows, status))
        self.assertEqual("skipped: part of an instruction", status[tuple(rows[0][:4])])
        self.assertEqual([], view.removed_functions)

    def testZwPrototypeOfNtName(self):
        library = FakeTypeLibrary("ntdll.dll", {"NtDelayExecution": function_type("NtDelayExecution")})
        view = self.makeView(4, [library])
        rows = [
            [0x1000, 0x7000, "ntdll.dll_0x7de70000 (32bit)", "ZwDelayExecution", 1],
            [0x1004, 0x7004, "ntdll.dll_0x7de70000 (32bit)", "ZwUnknown", 1],
        ]
        status = {}
        self.assertEqual((2, 0), tools.annotate(view, rows, status))
        self.assertEqual("ZwDelayExecution", view.get_symbol_at(0x1000).name)
        self.assertEqual("NtDelayExecution", view.data_vars[0x1000].target.name)
        self.assertEqual(("ntdll.dll", "NtDelayExecution"), view.recorded[0x1000])
        self.assertEqual("annotated", status[tuple(rows[0][:4])])
        self.assertEqual("annotated (no type information)", status[tuple(rows[1][:4])])

    def testCancelledScanKeepsLastResults(self):
        folder = tempfile.mkdtemp()
        db_path = os.path.join(folder, "one.json")
        write_db(db_path, {"kernel32.dll": (32, 0x7C800000, [("A", 1, 0x10)])})
        try:
            view = self.makeView(4)
            last = {"rows": [[0x1000, 0x7000, "a.dll (32bit)", "A", 0]], "status": {}}
            view.session_data["apiscout"] = last
            task = FakeBackgroundTaskThread()
            task.cancelled = True
            state = tools.scan_and_annotate(view, [db_path], task=task)
        finally:
            shutil.rmtree(folder)
        self.assertEqual((0, 0), (state["annotated"], state["skipped"]))
        self.assertIs(last, view.session_data["apiscout"])
        self.assertEqual({}, view.symbols)

    def testReannotationReplacesOwnName(self):
        view = self.makeView(4)
        auto_symbol = FakeSymbol(SymbolType.DataSymbol, 0x1000, "data_1000")
        auto_symbol.auto = True
        view.symbols[0x1000] = [auto_symbol]
        rows = [[0x1000, 0x7000, "a.dll (32bit)", "First", 0]]
        status = {}
        tools.annotate(view, rows, status)
        self.assertEqual("First", view.get_symbol_at(0x1000).name)
        # a scan with another DB names the location differently
        other = [[0x1000, 0x7000, "b.dll (32bit)", "Second", 0]]
        tools.annotate(view, other, status)
        self.assertEqual(["Second", "data_1000"], sorted(sym.name for sym in view.symbols[0x1000]))
        self.assertEqual("skipped: location is annotated as Second", status[tuple(rows[0][:4])])
        self.assertEqual("annotated (no type information)", status[tuple(other[0][:4])])
        self.assertEqual(1, len([sym for sym in view.symbols[0x1000] if not sym.auto]))
        self.assertIn(("info", "No type information available for 1 APIs: Second"), LOG)
        # annotating again keeps the one name
        tools.annotate(view, other, status)
        self.assertEqual(["Second", "data_1000"], sorted(sym.name for sym in view.symbols[0x1000]))

    def testStatusOfUndoneAnnotationIsDropped(self):
        view = self.makeView(4)
        rows = [[0x1000, 0x7000, "a.dll (32bit)", "First", 0]]
        status = {}
        tools.annotate(view, rows, status)
        self.assertEqual("annotated (no type information)", status[tuple(rows[0][:4])])
        # an undo removes the symbols again
        view.symbols.clear()
        tools.annotate(view, [], status)
        self.assertEqual({}, status)

    def testNoPlatform(self):
        view = FakeBinaryView([FakeSegment(0x1000, 0x10, b"\0" * 0x10)], 4, None)
        rows = [[0x1000, 0x7000, "kernel32.dll (32bit)", "ReadProcessMemory", 0]]
        self.assertEqual((1, 0), tools.annotate(view, rows))
        self.assertEqual("ReadProcessMemory", view.get_symbol_at(0x1000).name)

    def testCancel(self):
        view = self.makeView(4)
        task = FakeBackgroundTaskThread()
        task.cancelled = True
        self.assertEqual((0, 0), tools.annotate(view, [[0x1000, 0x7000, "a.dll (32bit)", "A", 0]], task=task))
        self.assertEqual({}, view.symbols)
        self.assertEqual(["begin", ("commit", "state1")], view.undo)


class CommandTest(unittest.TestCase):
    def setUp(self):
        LOG.clear()
        FakeInteraction.forms.clear()
        FakeBackgroundTaskThread.started.clear()
        self.folder = tempfile.mkdtemp()
        self.db_path = os.path.join(self.folder, "three_apis.json")
        write_db(self.db_path, {"kernel32.dll": (32, 0x7C800000, [("A", 1, 0x10), ("B", 2, 0x20), ("C", 3, 0x30)])})

    def tearDown(self):
        FakeInteraction.form_handler = None
        shutil.rmtree(self.folder)

    def runTasks(self):
        for task in FakeBackgroundTaskThread.started:
            task.join(120)
            self.assertFalse(task.thread.is_alive())

    def makeView(self):
        content = b"".join(address.to_bytes(4, "little") for address in (0x7C800010, 0x7C800020, 0x7C800030))
        return FakeBinaryView([FakeSegment(0x1000, len(content), content)], 4, FakePlatform("windows-x86", []))

    def testScanAnnotateAndShow(self):
        db_path = self.db_path

        def answer(fields):
            self.assertIn("API DBs of the system the memory dump was taken from:", fields)
            other = next(field for field in fields if isinstance(field, OpenFileNameField))
            # the result of a file field is taken as text or as bytes
            other.result = db_path.encode()
            for field in fields:
                if isinstance(field, CheckboxField):
                    field.result = False
            return True

        FakeInteraction.form_handler = answer
        view = self.makeView()
        tools.command_scan(view)
        self.runTasks()
        state = view.session_data["apiscout"]
        self.assertEqual(3, len(state["rows"]))
        self.assertEqual([db_path], state["db_paths"])
        self.assertEqual({}, view.symbols)
        title, markdown, text = view.reports[-1]
        self.assertEqual("ApiScout", title)
        self.assertIn("[0x1000](binaryninja://?expr=0x1000)", markdown)
        self.assertIn("kernel32.dll (32bit)", text)
        self.assertEqual(["A", "B", "C"], [row[3] for row in state["rows"]])

        FakeInteraction.form_handler = lambda fields: setattr(fields[0], "result", 4) or True
        tools.command_annotate_filtered(view)
        self.runTasks()
        self.assertEqual([0x1000, 0x1004, 0x1008], sorted(view.symbols))

        FakeBackgroundTaskThread.started.clear()
        tools.command_annotate_all(view)
        self.runTasks()
        self.assertEqual(
            [["A"], ["B"], ["C"]], [[sym.name for sym in view.symbols[addr]] for addr in sorted(view.symbols)]
        )
        self.assertEqual(3, view.reports[-1][1].count("| annotated (no type information) |"))

    def testScanWithDbOfFolder(self):
        def answer(fields):
            checkboxes = [field for field in fields if isinstance(field, CheckboxField)]
            names = [field.prompt for field in checkboxes]
            self.assertIn("win7_prof-n_sp1_example.json", names)
            self.assertEqual("Ignore the ASLR offsets stored in the API DBs", names[-1])
            for field in checkboxes:
                field.result = field.prompt == "win7_prof-n_sp1_example.json"
            return True

        FakeInteraction.form_handler = answer
        parameters = tools.ask_parameters()
        self.assertEqual([os.path.realpath(WIN7_DB)], [os.path.realpath(path) for path in parameters["db_paths"]])
        self.assertFalse(parameters["ignore_aslr_offsets"])

    def testSameDbInTwoFoldersIsOfferedOnce(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        shutil.copy(self.db_path, other)
        names = []

        def answer(fields):
            names.extend(field.prompt for field in fields if isinstance(field, CheckboxField))
            return False

        FakeInteraction.form_handler = answer
        with mock.patch.object(tools, "get_db_folders", return_value=[self.folder, other]):
            tools.ask_parameters()
        self.assertEqual(1, names.count("three_apis.json"))

    def testCancelledAndEmptyForms(self):
        view = self.makeView()
        FakeInteraction.form_handler = None
        tools.command_scan(view)
        tools.command_scan_and_annotate(view)
        tools.command_annotate_filtered(view)
        self.assertEqual([], FakeBackgroundTaskThread.started)
        FakeInteraction.form_handler = lambda fields: True
        tools.command_scan(view)
        self.assertEqual([], FakeBackgroundTaskThread.started)
        self.assertIn(("warn", "No API DB selected, nothing to do."), LOG)

    def testScanAndAnnotateCommand(self):
        db_path = self.db_path

        def answer(fields):
            next(field for field in fields if isinstance(field, OpenFileNameField)).result = db_path
            return True

        FakeInteraction.form_handler = answer
        view = self.makeView()
        tools.command_scan_and_annotate(view)
        self.runTasks()
        self.assertEqual(3, view.session_data["apiscout"]["annotated"])
        self.assertEqual(3, len(view.symbols))

    def testBrokenDb(self):
        db_path = os.path.join(self.folder, "broken.json")
        with open(db_path, "w") as f_db:
            f_db.write("{}")
        FakeInteraction.form_handler = lambda fields: (
            setattr(next(f for f in fields if isinstance(f, OpenFileNameField)), "result", db_path) or True
        )
        view = self.makeView()
        tools.command_scan(view)
        self.runTasks()
        self.assertNotIn("apiscout", view.session_data)
        self.assertTrue(any(level == "error" for level, _ in LOG))

    def testShowWithoutResults(self):
        view = self.makeView()
        tools.show_results(view)
        self.assertEqual([], view.reports)
        self.assertEqual("warn", LOG[-1][0])


if __name__ == "__main__":
    unittest.main()
