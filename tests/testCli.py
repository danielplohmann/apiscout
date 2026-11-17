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
        self.assertEqual((0, ""), (code, errors))
        self.assertIn("InterlockedIncrement", output)
        self.assertIn("base address 0x1000", output)
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
        code, output, _ = run("scan", DUMP_PATH, "--import-table", "--json")
        self.assertEqual(0, code)
        self.assertEqual([], json.loads(output)["apis"])

    def testDbs(self):
        code, output, _ = run("dbs", "--db-dir", THIS_DIR, "--json")
        self.assertEqual(0, code)
        self.assertEqual(["minimal_db.json"], [os.path.basename(db["path"]) for db in json.loads(output)["api_dbs"]])
        self.assertIn("minimal_db.json", run("dbs", "--db-dir", THIS_DIR)[1])
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn("No API DBs", run("dbs", "--db-dir", directory)[1])

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

    def testUpdateNeedsToken(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, errors = run("update", "--db-dir", directory, "--token-file", os.path.join(directory, "token"))
            self.assertEqual(1, code)
            self.assertTrue("no Malpedia API token" in errors or "requests package" in errors)


if __name__ == "__main__":
    unittest.main()
