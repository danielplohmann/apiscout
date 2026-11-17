"""
Tests of the Binary Ninja plugin in Binary Ninja itself, run headless in a subprocess on small memory dumps built
from an API DB. They need Binary Ninja's Python API (scripts/install_api.py) and a license that allows headless use,
and are reported as skipped without them.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPO_DIR = os.path.dirname(THIS_DIR)
WIN7_DB = os.path.join(REPO_DIR, "dbs", "win7_prof-n_sp1_example.json")
APIS = [("kernel32", "ReadProcessMemory", 5), ("kernel32", "CreateFileA", 7), ("kernel32", "VirtualAlloc", 4)]

# run in the subprocess: load the dump as mapped view, annotate it and print what Binary Ninja shows
SCRIPT = """
import json, sys
import binaryninja
from apiscout.BinaryNinjaTools import scan_and_annotate

path, base, platform, db = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
with binaryninja.load(path, options={"loader.imageBase": base, "loader.platform": platform}) as bv:
    # without entry point, as a user would: a function at the start, the linear sweep finds others in the table
    if bv.get_function_at(base) is None:
        bv.create_user_function(base)
    bv.update_analysis_and_wait()
    functions = sorted(function.start for function in bv.functions)
    state = scan_and_annotate(bv, [db])
    bv.update_analysis_and_wait()
    pointers = {}
    for row in state["rows"]:
        symbol = bv.get_symbol_at(row[0])
        data_var = bv.get_data_var_at(row[0])
        pointers[hex(row[0])] = {
            "symbol": [symbol.type.name, symbol.name] if symbol else None,
            "type": str(data_var.type) if data_var else None,
            "status": state["status"][tuple(row[:4])],
        }
    hlil = [str(line) for function in bv.functions for line in function.hlil.instructions]
    after = sorted(function.start for function in bv.functions)
    print(json.dumps({"view": bv.view_type, "pointers": pointers, "hlil": hlil, "functions": [functions, after]}))
"""


def binary_ninja_python():
    """None if the Python running the tests can import Binary Ninja with a valid license, else the reason why not"""
    check = "import binaryninja; binaryninja.core_product()"
    result = subprocess.run([sys.executable, "-c", check], capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        lines = (result.stderr or result.stdout).strip().splitlines()
        return lines[-1] if lines else "binaryninja not usable"
    return None


REASON = binary_ninja_python() if os.environ.get("APISCOUT_SKIP_BINARYNINJA") is None else "disabled"


def api_addresses(bitness):
    with open(WIN7_DB) as f_db:
        db = json.load(f_db)
    addresses = []
    for dll, name, _ in APIS:
        entry = next(v for k, v in db["dlls"].items() if v["bitness"] == bitness and f"_{dll}.dll_" in k)
        export = next(e for e in entry["exports"] if e["name"] == name)
        addresses.append(entry["base_address"] + export["address"] - entry["aslr_offset"])
    return addresses


def dump_32bit(base):
    """calls through a table of pointers at base + 0x2000 behind pushes of the arguments, no entry point"""
    code = b"\x55\x89\xe5"
    for index, (_, _, num_args) in enumerate(APIS):
        code += b"\x6a\x00" * num_args + b"\xff\x15" + struct.pack("<I", base + 0x2000 + 4 * index)
    code += b"\x89\xec\x5d\xc3"
    table = b"".join(struct.pack("<I", address) for address in api_addresses(32))
    return code.ljust(0x2000, b"\0") + table.ljust(0x1000, b"\0")


def dump_64bit(base):
    code = b"\x48\x83\xec\x48"
    for index in range(len(APIS)):
        code += b"\x31\xc9\x31\xd2\x45\x31\xc0\x45\x31\xc9"
        code += b"\xff\x15" + struct.pack("<i", base + 0x2000 + 8 * index - (base + len(code) + 6))
    code += b"\x48\x83\xc4\x48\xc3"
    table = b"".join(struct.pack("<Q", address) for address in api_addresses(64))
    return code.ljust(0x2000, b"\0") + table.ljust(0x1000, b"\0")


@unittest.skipIf(REASON, f"Binary Ninja not available: {REASON}")
class HeadlessTest(unittest.TestCase):
    def analyze(self, content, base, platform):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "dump")
            with open(path, "wb") as f_dump:
                f_dump.write(content)
            result = subprocess.run(
                [sys.executable, "-c", SCRIPT, path, str(base), platform, WIN7_DB],
                capture_output=True,
                text=True,
                timeout=600,
                cwd=REPO_DIR,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def check(self, result, base, size, prototype):
        self.assertEqual("Mapped", result["view"])
        self.assertEqual([hex(base + 0x2000 + size * index) for index in range(len(APIS))], list(result["pointers"]))
        for (_, name, _), pointer in zip(APIS, result["pointers"].values(), strict=True):
            self.assertEqual(["ImportAddressSymbol", name], pointer["symbol"])
            self.assertEqual("annotated", pointer["status"])
            self.assertIn(prototype, pointer["type"])
        hlil = "\n".join(result["hlil"])
        for _, name, _ in APIS:
            self.assertIn(f"{name}(", hlil)
        return hlil

    def test32bit(self):
        base = 0x400000
        result = self.analyze(dump_32bit(base), base, "windows-x86")
        hlil = self.check(result, base, 4, "__stdcall*")
        self.assertIn("ReadProcessMemory(nullptr, nullptr, nullptr, 0, nullptr)", hlil)
        self.assertIn("HANDLE hProcess", result["pointers"][hex(base + 0x2000)]["type"])
        # the function the linear sweep found in the table of pointers is removed
        before, after = result["functions"]
        self.assertEqual([base], after)
        self.assertIn(base, before)
        self.assertGreater(len(before), 1)

    def test64bit(self):
        base = 0x1C0000
        result = self.analyze(dump_64bit(base), base, "windows-x86_64")
        hlil = self.check(result, base, 8, "(*)(")
        self.assertIn("VirtualAlloc(nullptr, 0, 0, 0)", hlil)


if __name__ == "__main__":
    unittest.main()
