import email.message
import hashlib
import io
import os
import tempfile
import unittest
import unittest.mock
import urllib.error

from apiscout import cli, db_index
from tests.testCli import run

REPOSITORY_DBS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dbs")


class FakeRepository:
    """serves files like raw.githubusercontent.com, for one ref"""

    def __init__(self, files, ref="v1.0"):
        self.files = dict(files)
        self.ref = ref
        self.index = "".join(f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in files.items())
        self.requests = []

    def urlopen(self, request, timeout=None):
        url = request.full_url
        self.requests.append(url)
        prefix = db_index.SOURCE_URL.format(ref=self.ref)
        name = url[len(prefix) :] if url.startswith(prefix) else None
        if name == db_index.INDEX_NAME:
            return io.BytesIO(self.index.encode())
        if name in self.files:
            return io.BytesIO(self.files[name])
        raise urllib.error.HTTPError(url, 404, "Not Found", email.message.Message(), None)


class DbDownloadTestSuite(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository({"a.json": b'{"os_name": "A"}', "b.csv": b"family;sample;1;1;x\n"})
        patches = [
            unittest.mock.patch("urllib.request.urlopen", self.repository.urlopen),
            unittest.mock.patch.object(cli, "get_version", return_value="1.0"),
            unittest.mock.patch.dict(os.environ, {cli.DB_DIR_VARIABLE: ""}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.directory = tempfile.mkdtemp()
        self.addCleanup(lambda: [os.remove(os.path.join(self.directory, n)) for n in os.listdir(self.directory)])

    def files(self):
        return sorted(os.listdir(self.directory))

    def testIndexOfTheRepositoryIsCurrent(self):
        with open(os.path.join(REPOSITORY_DBS, db_index.INDEX_NAME), encoding="utf-8") as f_index:
            self.assertEqual(
                db_index.build_index(REPOSITORY_DBS),
                f_index.read(),
                "dbs changed, rewrite the index: python -m apiscout.db_index dbs",
            )

    def testDownload(self):
        code, output, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual((0, ""), (code, output), errors)
        self.assertEqual(["a.json", "b.csv"], self.files())
        with open(os.path.join(self.directory, "a.json"), "rb") as f_db:
            self.assertEqual(self.repository.files["a.json"], f_db.read())
        self.assertTrue(self.repository.requests[0].endswith("/v1.0/dbs/SHA256SUMS"))
        # a second run downloads nothing
        self.repository.requests.clear()
        code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(0, code)
        self.assertEqual(1, len(self.repository.requests))
        self.assertIn("Up to date", errors)

    def testOnlyNamedFiles(self):
        self.assertEqual(0, run("dbs", "download", "b.csv", "b.csv", "--db-dir", self.directory)[0])
        self.assertEqual(["b.csv"], self.files())
        code, _, errors = run("dbs", "download", "c.json", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("c.json", errors)
        self.assertIn("Available: a.json, b.csv", errors)

    def testChangedFilesAreKeptUnlessForced(self):
        path = os.path.join(self.directory, "a.json")
        with open(path, "wb") as f_db:
            f_db.write(b"own DB")
        code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("--force", errors)
        with open(path, "rb") as f_db:
            self.assertEqual(b"own DB", f_db.read())
        self.assertEqual(["a.json", "b.csv"], self.files())
        self.assertEqual(0, run("dbs", "download", "--force", "--db-dir", self.directory)[0])
        with open(path, "rb") as f_db:
            self.assertEqual(self.repository.files["a.json"], f_db.read())

    def testWrongContentIsNotStored(self):
        self.repository.files["a.json"] = b"tampered"
        code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("SHA-256", errors)
        self.assertEqual([], self.files())
        with unittest.mock.patch.object(db_index, "MAX_SIZE", 4):
            code, _, errors = run("dbs", "download", "b.csv", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("larger than 4 bytes", errors)
        self.assertEqual([], self.files())

    def testMissingVersionAndNetworkErrors(self):
        self.repository.ref = "master"
        code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("HTTP 404", errors)
        self.assertIn("--ref master", errors)
        self.assertEqual(0, run("dbs", "download", "--ref", "master", "--db-dir", self.directory)[0])

        def offline(request, timeout=None):
            raise urllib.error.URLError("Name or service not known")

        with unittest.mock.patch("urllib.request.urlopen", offline):
            code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("Name or service not known", errors)

    def testIndexIsChecked(self):
        for line in ("0" * 64 + "  ../a.json", "0" * 64 + "  dbs/a.json", "0" * 63 + "  a.json", "a.json"):
            with self.assertRaises(ValueError, msg=line):
                db_index.parse_index(line)
        self.assertEqual({"a.json": "0" * 64}, db_index.parse_index("0" * 64 + " *a.json\n"))
        self.repository.index = "not a list\n"
        code, _, errors = run("dbs", "download", "--db-dir", self.directory)
        self.assertEqual(1, code)
        self.assertIn("not a list of SHA-256 sums", errors)

    def testFolders(self):
        # --db-dir given to dbs is used by download, the data folder is the default of both
        self.assertEqual(0, run("dbs", "--db-dir", self.directory, "download", "a.json")[0])
        self.assertEqual(["a.json"], self.files())
        data_dir = os.path.join(self.directory, "data")
        with unittest.mock.patch.object(db_index, "get_data_dir", return_value=data_dir):
            self.assertEqual(0, run("dbs", "download", "a.json")[0])
            self.assertEqual(["a.json"], os.listdir(data_dir))
            with tempfile.TemporaryDirectory() as cwd, unittest.mock.patch.object(os, "getcwd", return_value=cwd):
                self.assertEqual(data_dir, cli.get_default_db_dir())
        os.remove(os.path.join(data_dir, "a.json"))
        os.rmdir(data_dir)
        for platform, variable, expected in (
            ("linux", "XDG_DATA_HOME", os.path.join("/xdg", "apiscout", "dbs")),
            ("win32", "LOCALAPPDATA", os.path.join("/local", "apiscout", "dbs")),
        ):
            value = os.path.dirname(os.path.dirname(expected))
            with (
                unittest.mock.patch.object(db_index.sys, "platform", platform),
                unittest.mock.patch.dict(os.environ, {variable: value}),
            ):
                self.assertEqual(expected, db_index.get_data_dir())

    def testBareNamesAreFoundInTheDbFolder(self):
        from tests.testCli import DB_PATH, DUMP_PATH

        with open(DB_PATH, "rb") as f_db, open(os.path.join(self.directory, "own.json"), "wb") as f_copy:
            f_copy.write(f_db.read())
        with unittest.mock.patch.dict(os.environ, {cli.DB_DIR_VARIABLE: self.directory}):
            code, output, errors = run("scan", DUMP_PATH, "--db", "own.json", "--json")
            self.assertEqual(0, code, errors)
            self.assertIn("own.json", output)
            code, _, errors = run("scan", DUMP_PATH, "--db", "missing.json")
            self.assertEqual(1, code)
            self.assertIn(f"also not in the DB folder {self.directory}", errors)
            code, _, errors = run("scan", DUMP_PATH, "--db", os.path.join("sub", "own.json"))
            self.assertEqual(1, code)
            self.assertNotIn("DB folder", errors)
