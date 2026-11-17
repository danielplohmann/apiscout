import contextlib
import io
import json
import os
import tempfile
import unittest

from apiscout import cli

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(THIS_DIR, "minimal_db.json")
DUMP_PATH = os.path.join(THIS_DIR, "example_dump.bin")
VECTOR = "WDBCAgBBAAgCA159"
OTHER_VECTOR = "WDBCABBACAgAEAAgA155"


def run(*arguments):
    """runs the command line tool, returns (exit code, standard output, standard error)"""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(list(arguments))
        except SystemExit as exit_request:
            code = exit_request.code
    return code, stdout.getvalue(), stderr.getvalue()


class CliTestSuite(unittest.TestCase):
    def testHelp(self):
        code, output, _ = run()
        self.assertEqual(0, code)
        self.assertIn("examples:", output)
        for arguments in (["--help"], ["help"], ["help", "scan"], ["scan", "--help"]):
            code, output, _ = run(*arguments)
            self.assertEqual(0, code)
            self.assertIn("usage: apiscout", output)
        self.assertIn("apiscout ", run("--version")[1])

    def testUsageErrors(self):
        code, output, errors = run("scna", DUMP_PATH)
        self.assertEqual((2, ""), (code, output))
        self.assertIn("Did you mean 'scan'?", errors)
        self.assertEqual(2, run("scan")[0])
        self.assertEqual(2, run("scan", DUMP_PATH, "--base-addr", "nothing")[0])
        self.assertEqual(2, run("help", "nothing")[0])

    def testScan(self):
        code, output, errors = run("scan", DUMP_PATH, "--db", DB_PATH, "--base-addr", "0x1000")
        self.assertEqual(0, code)
        self.assertIn("InterlockedIncrement", output)
        # what is not the result goes to standard error, and is left out on request
        self.assertNotIn("Scanned", output)
        self.assertIn("base address 0x1000", errors)
        self.assertEqual("", run("scan", DUMP_PATH, "--db", DB_PATH, "--quiet")[2])
        code, output, _ = run("scan", DUMP_PATH, "--db", DB_PATH, "--json")
        document = json.loads(output)
        self.assertEqual(["InterlockedIncrement", "WaitForSingleObjectEx"], [api["api"] for api in document["apis"]])
        self.assertEqual([DB_PATH], document["api_dbs"])
        self.assertTrue(document["apivector"])
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "result.json")
            code, output, _ = run("scan", DUMP_PATH, "--db", DB_PATH, "--json", "--output", target)
            self.assertEqual((0, ""), (code, output))
            with open(target) as f_result:
                self.assertEqual(document, json.load(f_result))

    def testScanErrors(self):
        code, output, errors = run("scan", "no_such_file", "--db", DB_PATH)
        self.assertEqual((1, ""), (code, output))
        self.assertIn("dump not found: no_such_file", errors)
        self.assertIn("API DB not found", run("scan", DUMP_PATH, "--db", "no_such_db.json")[2])
        with tempfile.TemporaryDirectory() as directory:
            code, _, errors = run("scan", DUMP_PATH, "--db-dir", directory)
            self.assertEqual(1, code)
            self.assertIn("no API DB found", errors)

    def testScanImportTable(self):
        from tests.testRobustness import build_pe32

        with tempfile.TemporaryDirectory() as directory:
            pe_path = os.path.join(directory, "sample.exe")
            with open(pe_path, "wb") as f_pe:
                f_pe.write(build_pe32())
            code, output, _ = run("scan", pe_path, "--import-table", "--json")
            self.assertEqual(0, code)
            self.assertEqual(["CreateFileW", "recv", "send"], [api["api"] for api in json.loads(output)["apis"]])
        code, _, errors = run("scan", DUMP_PATH, "--import-table")
        self.assertEqual(1, code)
        self.assertIn("not a PE file", errors)

    def testScanWithCollection(self):
        with tempfile.TemporaryDirectory() as directory:
            collection = os.path.join(directory, "collection.csv")
            with open(collection, "w") as f_collection:
                f_collection.write(f"family;sample;1;1;{VECTOR}\n")
            code, output, _ = run("scan", DUMP_PATH, "--db", DB_PATH, "--collection", collection)
            self.assertEqual(0, code)
            self.assertIn("Collection Results", output)
            document = json.loads(run("scan", DUMP_PATH, "--db", DB_PATH, "--collection", collection, "--json")[1])
            self.assertEqual(1, document["collection_matches"]["vectors_in_collection"])
            # found out before the scan, and without traceback
            for bad_collection, message in (
                (os.path.join(directory, "missing"), "collection not found"),
                (DB_PATH, "no ApiVectors in"),
            ):
                code, output, errors = run("scan", DUMP_PATH, "--db", DB_PATH, "--collection", bad_collection)
                self.assertEqual((1, ""), (code, output))
                self.assertIn(message, errors)
                self.assertNotIn("Traceback", errors)

    def testFilesThatAreNoApiDbs(self):
        with tempfile.TemporaryDirectory() as directory:
            for content in ("no json", "[1, 2]", '{"dlls": 1}'):
                bad_db = os.path.join(directory, "bad.json")
                with open(bad_db, "w") as f_db:
                    f_db.write(content)
                for arguments in (
                    ["scan", DUMP_PATH, "--db", bad_db],
                    ["collect", directory, "--db", bad_db, "-o", "-"],
                ):
                    code, _, errors = run(*arguments)
                    self.assertEqual(1, code)
                    self.assertIn("not an API DB", errors)
                    self.assertNotIn("Traceback", errors)
                self.assertIn("Not an API DB, ignored", run("dbs", "--db-dir", directory)[2])

    def testNumbersAreChecked(self):
        for arguments in (
            ["scan", DUMP_PATH, "--db", DB_PATH, "--filter", "-1"],
            ["match", VECTOR, VECTOR, "--max-results", "0"],
            ["update", "--timeout", "0"],
            ["update", "--timeout", "nan"],
            ["scan", DUMP_PATH, "--base-addr", "-4"],
        ):
            self.assertEqual(2, run(*arguments)[0])

    def testFlagsAreNotAbbreviated(self):
        code, _, errors = run("update", "--token", "secret")
        self.assertEqual(2, code)
        self.assertNotIn("secret-file", errors)
        self.assertIn("apiscout update: error: unrecognized arguments", errors)
        self.assertIn("Try 'apiscout update --help'", errors)

    def testStandardStreams(self):
        import sys
        import unittest.mock

        with open(DUMP_PATH, "rb") as f_dump:
            dump = f_dump.read()

        class Input:
            def __init__(self, data):
                self.buffer = io.BytesIO(data)

            def isatty(self):
                return False

            def read(self):
                return self.buffer.read().decode()

        with unittest.mock.patch.object(sys, "stdin", Input(dump)):
            code, output, _ = run("scan", "-", "--db", DB_PATH, "--json", "--output", "-")
        self.assertEqual(0, code)
        self.assertEqual(2, len(json.loads(output)["apis"]))
        with unittest.mock.patch.object(sys, "stdin", Input(b"")):
            self.assertIn("no data on standard input", run("scan", "-", "--db", DB_PATH)[2])
        # match reads a vector, or the JSON result of scan, from standard input
        for piped in (VECTOR.encode() + b"\n", output.encode()):
            with unittest.mock.patch.object(sys, "stdin", Input(piped)):
                self.assertIn("score", json.loads(run("match", "-", VECTOR, "--json")[1]))

    def testDbs(self):
        code, output, _ = run("dbs", "--db-dir", THIS_DIR, "--json")
        self.assertEqual(0, code)
        self.assertEqual(["minimal_db.json"], [os.path.basename(db["path"]) for db in json.loads(output)["api_dbs"]])
        self.assertIn("minimal_db.json", run("dbs", "--db-dir", THIS_DIR)[1])
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn("No API DBs", run("dbs", "--db-dir", directory)[1])
            code, _, errors = run("dbs", "--db-dir", os.path.join(directory, "missing"))
            self.assertEqual(1, code)
            self.assertIn("folder not found", errors)

    def testMatch(self):
        code, output, _ = run("match", VECTOR, VECTOR, "--json")
        self.assertEqual(0, code)
        self.assertEqual({"vector_a": VECTOR, "vector_b": VECTOR, "score": 1.0}, json.loads(output))
        self.assertAlmostEqual(0.572, json.loads(run("match", VECTOR, OTHER_VECTOR, "--json")[1])["score"], places=3)
        with tempfile.TemporaryDirectory() as directory:
            collection = os.path.join(directory, "collection.csv")
            with open(collection, "w") as f_collection:
                f_collection.write(f"family;sample;1;1;{VECTOR}\n")
            code, output, _ = run("match", VECTOR, "--collection", collection)
            self.assertEqual(0, code)
            self.assertIn("Collection Results", output)
            self.assertEqual(1, run("match", VECTOR, VECTOR, "--collection", collection)[0])
        self.assertEqual(1, run("match", VECTOR)[0])
        code, _, errors = run("match", "!!", VECTOR)
        self.assertEqual(1, code)
        self.assertIn("Not a valid ApiVector", errors)

    def testExport(self):
        with tempfile.TemporaryDirectory() as directory:
            png, html = os.path.join(directory, "vector.png"), os.path.join(directory, "vector.html")
            code, output, errors = run("export", VECTOR, "--png", png, "--html", html)
            self.assertEqual((0, ""), (code, output))
            self.assertIn("Wrote", errors)
            self.assertTrue(os.path.getsize(png) and os.path.getsize(html))
            self.assertEqual("", run("export", VECTOR, "--png", png, "--quiet")[2])
        self.assertEqual(1, run("export", VECTOR)[0])

    def testCollect(self):
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, "family"))
            with open(DUMP_PATH, "rb") as f_dump, open(os.path.join(directory, "family", "x_dump"), "wb") as f_copy:
                f_copy.write(f_dump.read())
            target = os.path.join(directory, "collection.csv")
            code, _, errors = run("collect", directory, "--db", DB_PATH, "--output", target, "--require", "_dump")
            self.assertEqual(0, code)
            self.assertIn("Wrote 1 fingerprints", errors)
            with open(target) as f_collection:
                self.assertTrue(f_collection.read().startswith("family;"))
            self.assertEqual(1, run("collect", os.path.join(directory, "missing"), "--db", DB_PATH)[0])
            # --update keeps the entries of dumps that are not in the folder, --output has those of the folder only
            with open(target, "a") as f_collection:
                f_collection.write(f"other;sample;1;1;{VECTOR}\n")
            with open(os.path.join(directory, "family", "y_dump"), "wb") as f_copy:
                f_copy.write(b"another dump")
            added = os.path.join(directory, "added.csv")
            arguments = ["collect", directory, "--db", DB_PATH, "--require", "_dump", "--update", target, "-o", added]
            self.assertEqual(0, run(*arguments)[0])
            with open(target) as f_collection, open(added) as f_added:
                self.assertEqual((3, 2), (len(f_collection.readlines()), len(f_added.readlines())))
            self.assertEqual(
                1, run("collect", directory, "--db", DB_PATH, "-o", os.path.join(directory, "no", "x.csv"))[0]
            )

    def testExamplesOfTheHelpWork(self):
        import re
        import shlex

        with tempfile.TemporaryDirectory() as directory:
            collection = os.path.join(directory, "apivectors.csv")
            with open(collection, "w") as f_collection:
                f_collection.write(f"family;sample;1;1;{OTHER_VECTOR}\n")
            lines = [line.strip() for text in cli.EXAMPLES.values() for line in text.splitlines()]
            commands = [line for line in lines if re.match(r"apiscout (match|export) '", line) and "|" not in line]
            self.assertGreaterEqual(len(commands), 4)
            for command in commands:
                arguments = shlex.split(command.split(" > ")[0])[1:]
                arguments = [collection if argument == "apivectors.csv" else argument for argument in arguments]
                arguments = [
                    os.path.join(directory, argument) if argument.startswith("vector.") else argument
                    for argument in arguments
                ]
                if "-" in arguments:
                    continue
                self.assertEqual(0, run(*arguments)[0], command)

    def testVerbosePrintsWhatTheLibraryLogs(self):
        import logging

        try:
            with self.assertLogs("apiscout", level="DEBUG") as logged:
                self.assertEqual(0, run("scan", DUMP_PATH, "--db", DB_PATH, "--verbose")[0])
            self.assertTrue(any("building address map" in message for message in logged.output))
        finally:
            logging.getLogger("apiscout").setLevel(logging.NOTSET)

    def testExportToOneFileOnly(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "vector")
            code, _, errors = run("export", VECTOR, "--png", target, "--html", target)
            self.assertEqual(1, code)
            self.assertIn("same file", errors)
            self.assertFalse(os.path.exists(target))

    def testQuietBeforeAndAfterTheCommand(self):
        for arguments in (["-q", "scan", DUMP_PATH, "--db", DB_PATH], ["scan", "-q", DUMP_PATH, "--db", DB_PATH]):
            code, _, errors = run(*arguments)
            self.assertEqual((0, ""), (code, errors))

    def testFoldersAndEmptyFiles(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = os.path.join(directory, "empty")
            open(empty, "w").close()
            self.assertIn("file is empty", run("scan", empty, "--db", DB_PATH)[2])
            self.assertIn("is a folder", run("scan", directory, "--db", DB_PATH)[2])
            self.assertIn("is a folder", run("scan", DUMP_PATH, "--db", directory)[2])
            # the output file is checked before the scan
            code, _, errors = run("scan", DUMP_PATH, "--db", DB_PATH, "-o", os.path.join(directory, "no", "result"))
            self.assertEqual(1, code)
            self.assertNotIn("Scanned", errors)
            same = os.path.join(directory, "c.csv")
            self.assertIn("same file", run("collect", directory, "--db", DB_PATH, "-u", same, "-o", same)[2])

    def testOutputToStandardOutput(self):
        import sys
        import unittest.mock

        class Output:
            def __init__(self):
                self.buffer = io.BytesIO()

            def flush(self):
                pass

            def isatty(self):
                return False

        for arguments, start in (
            (["export", VECTOR, "--png", "-"], b"\x89PNG"),
            (["export", VECTOR, "--html", "-"], b"<"),
        ):
            output = Output()
            with unittest.mock.patch.object(sys, "stdout", output):
                self.assertEqual(0, cli.main(arguments))
            self.assertTrue(output.buffer.getvalue().lstrip().startswith(start))
        self.assertEqual(1, run("export", VECTOR, "--png", "-", "--html", "-")[0])

    def testDbFolderResolution(self):
        import unittest.mock

        variable = cli.DB_DIR_VARIABLE
        with tempfile.TemporaryDirectory() as directory, unittest.mock.patch.dict(os.environ, {variable: directory}):
            self.assertEqual(directory, cli.get_default_db_dir())
            self.assertIn(directory, run("dbs")[1])
            # the option wins over the variable
            self.assertIn("minimal_db.json", run("dbs", "--db-dir", THIS_DIR)[1])

    def testUpdate(self):
        import unittest.mock

        class Response:
            def __init__(self, status_code=200, version=None, content=b"", headers=None):
                self.status_code, self.content, self.headers, self._version = (
                    status_code,
                    content,
                    headers or {},
                    version,
                )

            def raise_for_status(self):
                pass

            def json(self):
                return {"version": self._version}

        try:
            import requests  # noqa: F401
        except ImportError:
            self.skipTest("requests is not installed")
        with tempfile.TemporaryDirectory() as directory:
            token, db_dir = os.path.join(directory, "token"), os.path.join(directory, "dbs")
            with open(token, "w") as f_token:
                f_token.write("secret\n")
            os.mkdir(db_dir)
            old_collection = os.path.join(db_dir, "2020-01-01-apivectors-v5.csv")
            open(old_collection, "w").close()
            name = "2026-01-01-apivectors-v7.csv"
            download = Response(
                content=b"family;sample;1;1;A171\n", headers={"Content-Disposition": f"filename={name}"}
            )
            arguments = ["update", "--db-dir", db_dir, "--token-file", token]
            with unittest.mock.patch("requests.get", side_effect=[Response(version=7), download]) as get:
                code, _, errors = run(*arguments)
            self.assertEqual(0, code)
            self.assertEqual("apitoken secret", get.call_args.kwargs["headers"]["Authorization"])
            self.assertEqual([name], os.listdir(db_dir))
            self.assertIn("removed 1 older", errors)
            self.assertNotIn("secret", errors)
            with unittest.mock.patch("requests.get", side_effect=[Response(version=7)]):
                self.assertIn("most recent", run(*arguments)[2])
            with unittest.mock.patch("requests.get", side_effect=[Response(version=8), Response(status_code=403)]):
                code, _, errors = run(*arguments)
            self.assertEqual(1, code)
            self.assertIn("rejected the API token", errors)
            self.assertNotIn("Traceback", errors)
            with unittest.mock.patch("requests.get", side_effect=[Response(version="x")]):
                self.assertIn("not understood", run(*arguments)[2])

    def testCollectWithWorkersThatCanNotStart(self):
        import multiprocessing
        import unittest.mock

        if multiprocessing.get_start_method() != "fork":
            self.skipTest("the workers only see the patched function when they are forked")
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, "family"))
            with open(os.path.join(directory, "family", "x_dump"), "wb") as f_dump:
                f_dump.write(b"dump")
            target = os.path.join(directory, "collection.csv")
            real_create = cli.create_crawler
            calls = []

            def create_once(*arguments):
                # the main process succeeds, its workers do not
                if calls:
                    raise OSError("API DB vanished")
                calls.append(1)
                return real_create(*arguments)

            with unittest.mock.patch.object(cli, "create_crawler", create_once):
                code, _, errors = run("collect", directory, "--db", DB_PATH, "-o", target)
            self.assertEqual(1, code)
            self.assertIn("a worker process could not load", errors)
            self.assertFalse(os.path.exists(target))

    def testUpdateNeedsToken(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, errors = run("update", "--db-dir", directory, "--token-file", os.path.join(directory, "token"))
            self.assertEqual(1, code)
            self.assertTrue("no Malpedia API token" in errors or "requests package" in errors)


if __name__ == "__main__":
    unittest.main()
