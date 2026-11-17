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
VECTOR = "A171"


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
        self.assertIn("file not found: no_such_file", errors)
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
                self.assertEqual(0.0, json.loads(run("match", "-", VECTOR, "--json")[1])["score"])

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
        self.assertEqual({"vector_a": VECTOR, "vector_b": VECTOR, "score": 0.0}, json.loads(output))
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

    def testUpdateNeedsToken(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, errors = run("update", "--db-dir", directory, "--token-file", os.path.join(directory, "token"))
            self.assertEqual(1, code)
            self.assertTrue("no Malpedia API token" in errors or "requests package" in errors)


if __name__ == "__main__":
    unittest.main()
