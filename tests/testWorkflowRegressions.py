import errno
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apiscout import cli, db_index

from .testCli import DB_PATH, DUMP_PATH, VECTOR, run
from .testLoadAddresses import build_dll_image
from .testMinidump import build_minidump, page


class WorkflowRegressionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name).resolve()

    def _writeDb(self, db_base, *, bitness=32):
        path = self.folder / "kernel32.json"
        path.write_text(
            json.dumps(
                {
                    "os_name": "Windows fixture",
                    "os_version": "1.0",
                    "dlls": {
                        f"{bitness}_1.0_kernel32.dll_0x{db_base:x}": {
                            "filepath": r"C:\Windows\System32\kernel32.dll",
                            "bitness": bitness,
                            "base_address": db_base,
                            "exports": [
                                {"ordinal": 1, "name": "CreateFileW", "address": 0x1500},
                                {"ordinal": 2, "name": "WriteFile", "address": 0x1510},
                            ],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return str(path)

    def _scan(self, dump, *args):
        status, output, errors = run("scan", str(dump), "--json", *args)
        self.assertEqual(0, status, errors)
        return json.loads(output)

    def testDbDiscoveryFallsThroughEmptyAndMixedFolders(self):
        local = self.folder / "dbs"
        downloaded = self.folder / "downloaded"
        local.mkdir()
        downloaded.mkdir()
        available = downloaded / "downloaded.json"
        shutil.copyfile(DB_PATH, available)
        previous_cwd = Path.cwd()
        try:
            os.chdir(self.folder)
            with (
                mock.patch.dict(os.environ),
                mock.patch.object(db_index, "get_data_dir", return_value=str(downloaded)),
            ):
                os.environ.pop(cli.DB_DIR_VARIABLE, None)
                self.assertEqual([str(available)], self._scan(DUMP_PATH)["api_dbs"])
                (local / "scan-results.json").write_text('{"apis": []}', encoding="utf-8")
                self.assertEqual([str(available)], self._scan(DUMP_PATH)["api_dbs"])
                local_db = local / "local.json"
                shutil.copyfile(DB_PATH, local_db)
                self.assertEqual([str(local_db)], self._scan(DUMP_PATH)["api_dbs"])
                self.assertEqual([str(available)], self._scan(DUMP_PATH, "--db", available.name)["api_dbs"])
        finally:
            os.chdir(previous_cwd)

    def testScanRejectsOutputAtAnInputPath(self):
        dump = self.folder / "dump.bin"
        db = self.folder / "db.json"
        shutil.copyfile(DUMP_PATH, dump)
        shutil.copyfile(DB_PATH, db)
        for output in (dump, db):
            with self.subTest(path=output):
                original = output.read_bytes()
                status, _, errors = run("scan", str(dump), "--db", str(db), "-o", str(output))
                self.assertEqual(1, status, errors)
                self.assertIn("output would overwrite an input file", errors)
                self.assertEqual(original, output.read_bytes())

    def testScanRejectsOutputHardlinkedToDatabase(self):
        database = self.folder / "db.json"
        result = self.folder / "output.json"
        shutil.copyfile(DB_PATH, database)
        try:
            os.link(database, result)
        except OSError as exc:
            self.skipTest(f"cannot create a hard link: {exc}")
        original = database.read_bytes()
        status, _, errors = run("scan", DUMP_PATH, "--db", str(database), "--json", "-o", str(result))
        self.assertEqual(1, status, errors)
        self.assertIn("output would overwrite an input file", errors)
        self.assertEqual(original, database.read_bytes())
        self.assertEqual(original, result.read_bytes())

    def testScanCanExitWhenPipeReaderHasClosed(self):
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb") as pipe:
            completed = subprocess.run(
                [sys.executable, "-m", "apiscout", "scan", DUMP_PATH, "--db", DB_PATH, "--quiet"],
                cwd=Path(__file__).resolve().parents[1],
                stdout=pipe,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)

    def testWindowsInvalidArgumentIsOnlyABrokenPipeForPipeOutput(self):
        reader, writer = os.pipe()
        os.close(reader)
        with os.fdopen(writer, "wb") as pipe, (self.folder / "regular.txt").open("wb") as regular:
            for stream, expected in ((pipe, BrokenPipeError), (regular, OSError)):
                stdout = mock.Mock()
                stdout.fileno.return_value = stream.fileno()
                stdout.flush.side_effect = OSError(errno.EINVAL, "Invalid argument")
                with (
                    self.subTest(stream=stream),
                    mock.patch.object(sys, "platform", "win32"),
                    mock.patch.object(sys, "stdout", stdout),
                    self.assertRaises(expected) as caught,
                ):
                    cli.flush_stdout()
                self.assertIs(type(caught.exception), expected)

    def testFlatDumpRecognizesPointersToACompletePlacedDll(self):
        base = 0x400000
        dll_base = base + 0x1000
        dll = bytearray(build_dll_image("kernel32.dll", {1: 0x1500, 2: 0x1510}))
        struct.pack_into("<I", dll, 0x80 + 0x50, len(dll))
        # The pointer in the sample survives. The duplicate pointer in the DLL itself is excluded.
        struct.pack_into("<I", dll, 0x2000, dll_base + 0x1500)
        dump = self.folder / f"dump_0x{base:08x}.bin"
        dump.write_bytes(page((0x40, dll_base + 0x1500, "<I")) + dll)
        result = self._scan(dump, "--db", self._writeDb(0x900000), "--min-confidence", "0")
        self.assertEqual(base, result["base_address"])
        self.assertEqual(dll_base, result["placed_dlls"][0]["load_address"])
        self.assertEqual([(0x40, "CreateFileW")], [(row["offset"], row["api"]) for row in result["apis"]])

    def testCollectMatchesScanAndIgnoresItsOwnOutput(self):
        family = self.folder / "family"
        family.mkdir()
        dump = family / "sample.dmp"
        loaded = 0x7FF700000000
        memory = page((0x40, loaded + 0x1500, "<Q"), (0x48, loaded + 0x1510, "<Q"))
        dump.write_bytes(
            build_minidump([(0x140000000, memory)], [(r"C:\Windows\System32\kernel32.dll", loaded, 0x3000)])
        )
        database = self._writeDb(0x180000000, bitness=64)
        result = self._scan(dump, "--db", database)
        self.assertEqual(2, result["apis_in_vector"])
        output = family / "collection.csv"
        output.write_text("Previous output\n", encoding="utf-8")
        status, _, errors = run(
            "collect", str(self.folder), "--db", database, "--jobs", "1", "--min-confidence", "20", "-o", str(output)
        )
        self.assertEqual(0, status, errors)
        self.assertEqual(f"family;sample.dmp;2;2;{result['apivector']}\n", output.read_text(encoding="utf-8"))

    def testCollectSkipEmptyKeepsHitsOutsideTheVectorCatalog(self):
        family = self.folder / "family"
        family.mkdir()
        shutil.copyfile(DUMP_PATH, family / "uncatalogued.bin")
        (family / "empty.bin").write_bytes(bytes(16))
        output = self.folder / "collection.csv"
        status, _, errors = run(
            "collect", str(family.parent), "--db", DB_PATH, "--jobs", "1", "--skip-empty", "-o", str(output)
        )
        self.assertEqual(0, status, errors)
        fields = output.read_text(encoding="utf-8").strip().split(";")
        self.assertEqual(["family", "uncatalogued.bin", "0", "2"], fields[:4])
        self.assertEqual(5, len(fields))

    def testCollectRefreshReplacesCachedRows(self):
        family = self.folder / "family"
        family.mkdir()
        (family / "sample.bin").write_bytes(bytes(16))
        collection = self.folder / "collection.csv"
        cached_row = "family;sample.bin;1;1;A171\n"
        other_row = "other;sample.bin;1;1;A171\n"
        collection.write_text(cached_row + other_row, encoding="utf-8")
        args = ("collect", str(family.parent), "--db", DB_PATH, "--update", str(collection))
        with mock.patch("multiprocessing.Pool", side_effect=AssertionError("all inputs were cached")):
            status, _, errors = run(*args)
        self.assertEqual(0, status, errors)
        self.assertCountEqual(
            [cached_row.strip(), other_row.strip()], collection.read_text(encoding="utf-8").splitlines()
        )
        status, _, errors = run(*args, "--refresh", "--skip-empty", "--jobs", "1")
        self.assertEqual(0, status, errors)
        self.assertEqual(other_row, collection.read_text(encoding="utf-8"))

    def testCollectRejectsAmbiguousSampleIds(self):
        family = self.folder / "family"
        family.mkdir()
        for name in ("sample;name.bin", "sample_name.bin"):
            (family / name).write_bytes(bytes(16))
        output = self.folder / "collection.csv"
        status, _, errors = run("collect", str(family.parent), "--db", DB_PATH, "--jobs", "1", "-o", str(output))
        self.assertEqual(1, status, errors)
        self.assertIn("Same collection ID", errors)
        self.assertFalse(output.exists())

    @unittest.skipUnless(importlib.util.find_spec("requests"), "requests is not installed")
    def testUpdateKeepsPriorCollectionWhenDownloadIsInvalid(self):
        token = self.folder / "token"
        token.write_text("placeholder", encoding="utf-8")
        previous = self.folder / "2026-01-01-apivectors-v1.csv"
        original = b"family;sample;0;0;A171\n"
        previous.write_bytes(original)
        metadata = mock.Mock()
        metadata.json.return_value = {"version": 2}
        download = mock.Mock(
            status_code=200,
            headers={"Content-Disposition": "filename=2026-01-02-apivectors-v2.csv"},
            content=b"family;sample;1;1;invalid-vector\n",
        )
        with mock.patch("requests.get", side_effect=[metadata, download]):
            status, _, errors = run("update", "--db-dir", str(self.folder), "--token-file", str(token))
        self.assertEqual(1, status, errors)
        self.assertIn("invalid collection", errors)
        self.assertEqual(original, previous.read_bytes())
        self.assertCountEqual([token, previous], list(self.folder.iterdir()))

    def testOutputKeepsSampleNamesThatAreNotUtf8(self):
        collection = self.folder / "collection.csv"
        collection.write_bytes(b"family;caf\xe9;1;1;" + VECTOR.encode() + b"\n")
        output = self.folder / "result.txt"
        for explain in ([], ["--explain"]):
            arguments = ["match", VECTOR, "-c", str(collection), *explain]
            status, _, errors = run(*arguments, "-o", str(output))
            self.assertEqual(0, status, errors)
            expected = output.read_bytes().replace(os.linesep.encode(), b"\n")
            self.assertIn(b"family - caf\xe9", expected)
            # a terminal or a pipe is strict by default. UTF-8 takes the bytes, another encoding has none for them
            for encoding, name in (("utf-8", b"caf\xe9"), ("cp1252", b"caf\\udce9")):
                raw = io.BytesIO()
                stream = io.TextIOWrapper(raw, encoding=encoding, errors="strict", newline="\n")
                with self.subTest(arguments=arguments[3:], output=encoding), mock.patch.object(sys, "stdout", stream):
                    self.assertEqual(0, cli.main(arguments))
                    self.assertEqual(expected.replace(b"caf\xe9", name), raw.getvalue())
                    self.assertEqual("strict", stream.errors)

    def testOutputEscapesSurrogatesThatAreNoBytes(self):
        # a file name of Windows can hold half a surrogate pair, which no encoding has bytes for
        text = "caf\udce9 \ud800\n"
        output = self.folder / "result.txt"
        cli.write_output(text, str(output))
        self.assertEqual(b"caf\\udce9 \\ud800", output.read_bytes().rstrip())
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="utf-8", errors="strict", newline="\n")
        with mock.patch.object(sys, "stdout", stream):
            cli.write_output(text, "-")
            cli.write_output("caf\udce9\n", None)
            stream.flush()
        self.assertEqual(b"caf\\udce9 \\ud800\ncaf\xe9\n", raw.getvalue())
        self.assertEqual("strict", stream.errors)

    @unittest.skipUnless(importlib.util.find_spec("requests"), "requests is not installed")
    def testUpdateTellsAnAnswerThatIsNotJsonFromAFailedRequest(self):
        import requests

        token = self.folder / "token"
        token.write_text("placeholder", encoding="utf-8")
        for content in (
            b"<html>maintenance</html>",
            b"",
            b"[7]",
            b"{}",
            b'{"version": "7"}',
            b'{"version": true}',
            b'{"version": 0}',
            b"[" * 100000,
        ):
            # a real response, so that json() fails as it does in requests
            answer = requests.Response()
            answer.status_code, answer._content = 200, content
            with self.subTest(content=content), mock.patch("requests.get", side_effect=[answer]):
                status, _, errors = run("update", "--db-dir", str(self.folder), "--token-file", str(token))
                self.assertEqual(1, status, errors)
                self.assertIn("not understood", errors)
                self.assertNotIn("request to Malpedia failed", errors)
                self.assertNotIn("Traceback", errors)
        with mock.patch("requests.get", side_effect=requests.ConnectionError("no route")):
            status, _, errors = run("update", "--db-dir", str(self.folder), "--token-file", str(token))
        self.assertEqual(1, status, errors)
        self.assertIn("request to Malpedia failed: no route", errors)

    @unittest.skipUnless(importlib.util.find_spec("requests"), "requests is not installed")
    def testUpdateReadsTheTokenFile(self):
        token = self.folder / "token"
        arguments = ["update", "--db-dir", str(self.folder), "--token-file", str(token)]
        download = mock.Mock(
            status_code=200,
            headers={"Content-Disposition": "filename=2026-01-02-apivectors-v2.csv"},
            content=f"family;sample;1;1;{VECTOR}\n".encode(),
        )
        # as Notepad and PowerShell store it
        utf16 = ["placeholder\r\n".encode(encoding) for encoding in ("utf-16", "utf-16-le", "utf-16-be")]
        utf16[1:] = [b"\xff\xfe" + utf16[1], b"\xfe\xff" + utf16[2]]
        for content in (b"placeholder\n", b"\xef\xbb\xbfplaceholder\r\n", *utf16):
            token.write_bytes(content)
            metadata = mock.Mock()
            metadata.json.return_value = {"version": 2}
            with self.subTest(content=content), mock.patch("requests.get", side_effect=[metadata, download]) as get:
                status, _, errors = run(*arguments)
                self.assertEqual(0, status, errors)
                self.assertEqual("apitoken placeholder", get.call_args.kwargs["headers"]["Authorization"])
            (self.folder / "2026-01-02-apivectors-v2.csv").unlink()
        # requests names the value of a header it refuses, which must not get that far
        for content in (
            b"placeholder\nsecond line\n",
            b"place holder",
            b"placeholder\xe9",
            "placeh\u00f6lder".encode(),
            b"",
        ):
            token.write_bytes(content)
            with self.subTest(content=content), mock.patch("requests.get") as get:
                status, _, errors = run(*arguments)
                self.assertEqual(1, status, errors)
                self.assertIn("no API token in", errors)
                self.assertNotIn("placeh", errors.replace(str(self.folder), ""))
                get.assert_not_called()
