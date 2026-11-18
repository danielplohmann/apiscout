import json
import logging
import os
import shutil
import struct
import tempfile
import unittest

from apiscout.ApiScout import ApiScout
from apiscout.FingerprintCrawler import FingerprintCrawler

THIS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
WINAPI1024_PATH = os.sep.join([PROJECT_ROOT, "apiscout", "data", "winapi1024v1.txt"])


class _RecordingHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _buildDll(bitness, base_address, aslr_offset, exports):
    return {
        "aslr_offset": aslr_offset,
        "base_address": base_address,
        "bitness": bitness,
        "exports": [
            {"address": address, "name": name, "ordinal": index + 1} for index, (address, name) in enumerate(exports)
        ],
        "filepath": "/test/some.dll",
        "version": "10.0.17134.1",
    }


# two 64bit DLLs sharing the file ImageBase 0x180000000 (as on Windows 10) with exports at identical RVAs,
# but loaded at different addresses in the boot the DB was built in.
ASLR_DB = {
    "aslr_offsets": True,
    "dlls": {
        "64_10.0.17134.1_kernel32.dll_0x180000000": _buildDll(
            64, 0x180000000, 0x180000000 - 0x7FFA55930000, [(0x1000, "CreateFileW"), (0x2000, "WriteFile")]
        ),
        "64_10.0.17134.1_advapi32.dll_0x180000000": _buildDll(
            64, 0x180000000, 0x180000000 - 0x7FFA54A10000, [(0x1000, "RegOpenKeyExW"), (0x2000, "RegSetValueExW")]
        ),
    },
    "os_name": "Test Windows 10",
    "os_version": "10.0.17134",
}

DUMP_OF_DB_BOOT = (
    b"\x00" * 0x10
    + struct.pack("<QQQQ", 0x7FFA55931000, 0x7FFA55932000, 0x7FFA54A11000, 0x7FFA54A12000)
    + b"\x00" * 0x10
)


class FingerprintCrawlerTestSuite(unittest.TestCase):
    """Test cases for ASLR offset handling in API DBs."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._aslr_db_path = os.path.join(self._tmp_dir, "aslr_db.json")
        with open(self._aslr_db_path, "w") as f_out:
            f_out.write(json.dumps(ASLR_DB))
        self._root_path = os.path.join(self._tmp_dir, "root")
        os.makedirs(os.path.join(self._root_path, "family"))
        self._dump_path = os.path.join(self._root_path, "family", "sample_dump")
        with open(self._dump_path, "wb") as f_out:
            f_out.write(DUMP_OF_DB_BOOT)

    def tearDown(self):
        shutil.rmtree(self._tmp_dir)

    def _loadWithRecordedLog(self, db_path, ignore_aslr_offsets):
        handler = _RecordingHandler()
        logger = logging.getLogger("apiscout.ApiScout")
        logger.addHandler(handler)
        try:
            scout = ApiScout()
            scout.ignoreAslrOffsets(ignore_aslr_offsets)
            scout.loadDbFile(db_path)
        finally:
            logger.removeHandler(handler)
        return scout, [record for record in handler.records if record.levelno >= logging.WARNING]

    def testDbHasAslrOffsets(self):
        self.assertTrue(FingerprintCrawler.dbHasAslrOffsets(self._aslr_db_path))
        self.assertFalse(FingerprintCrawler.dbHasAslrOffsets(os.path.join(THIS_DIR, "minimal_db.json")))
        # flag not set but offsets present
        unflagged_db = dict(ASLR_DB, aslr_offsets=False)
        unflagged_path = os.path.join(self._tmp_dir, "unflagged_db.json")
        with open(unflagged_path, "w") as f_out:
            f_out.write(json.dumps(unflagged_db))
        self.assertTrue(FingerprintCrawler.dbHasAslrOffsets(unflagged_path))

    def testExampleDbsAslrOffsets(self):
        expected = {
            "win10_prof_1803_example.json": True,
            "win7_prof-n_sp1_example.json": False,
            "winxp_prof_sp3_example.json": False,
        }
        for db_name, has_offsets in sorted(expected.items()):
            self.assertEqual(
                has_offsets, FingerprintCrawler.dbHasAslrOffsets(os.sep.join([PROJECT_ROOT, "dbs", db_name]))
            )

    def testCollectSkipsAslrDbsByDefault(self):
        import contextlib
        import io

        from apiscout import cli

        minimal_db_path = os.path.join(THIS_DIR, "minimal_db.json")
        target = os.path.join(self._tmp_dir, "collection.csv")
        arguments = ["collect", self._root_path, "--db", self._aslr_db_path, "--db", minimal_db_path, "-o", target]
        for extra, is_skipped in (([], True), (["--use-aslr-dbs"], False), (["--ignore-aslr"], False)):
            messages = io.StringIO()
            with contextlib.redirect_stderr(messages):
                self.assertEqual(0, cli.main(arguments + extra))
            self.assertEqual(is_skipped, "Skipping API DB with ASLR offsets" in messages.getvalue())

    def testCollectAslrOptionsExcludeEachOther(self):
        import contextlib
        import io

        from apiscout import cli

        arguments = ["collect", self._root_path, "--db", self._aslr_db_path, "-o", os.path.join(self._tmp_dir, "c.csv")]
        messages = io.StringIO()
        with contextlib.redirect_stderr(messages), self.assertRaises(SystemExit) as exit_request:
            cli.main(arguments + ["--use-aslr-dbs", "--ignore-aslr"])
        self.assertEqual(2, exit_request.exception.code)
        self.assertIn("not allowed with", messages.getvalue())
        self.assertFalse(os.path.exists(os.path.join(self._tmp_dir, "c.csv")))

    def testCollectParsesEachDbOnceInTheMainProcess(self):
        import contextlib
        import io
        from unittest import mock

        from apiscout import ApiScout as api_scout_module
        from apiscout import FingerprintCrawler as crawler_module
        from apiscout import cli

        minimal_db_path = os.path.join(THIS_DIR, "minimal_db.json")
        target = os.path.join(self._tmp_dir, "collection.csv")
        arguments = ["collect", self._root_path, "--db", self._aslr_db_path, "--db", minimal_db_path, "-o", target]
        parsed = []

        def counting_read_json(path):
            parsed.append(path)
            with open(path, encoding="utf-8") as f_db:
                return json.load(f_db)

        # the workers are forked after the DBs were loaded and count in their own copy of this list
        with (
            mock.patch.object(api_scout_module, "read_json", counting_read_json),
            mock.patch.object(crawler_module, "read_json", counting_read_json),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(0, cli.main(arguments + ["--use-aslr-dbs"]))
            self.assertEqual(sorted([self._aslr_db_path, minimal_db_path]), sorted(parsed))
            # a skipped DB is read for the check and not loaded
            del parsed[:]
            self.assertEqual(0, cli.main(arguments))
            self.assertEqual(sorted([self._aslr_db_path, minimal_db_path]), sorted(parsed))

    def testCrawlerTakesParsedApiDbs(self):
        crawler = FingerprintCrawler(
            [self._aslr_db_path],
            WINAPI1024_PATH,
            self._root_path,
            0,
            ignore_aslr_offsets=False,
            api_dbs={self._aslr_db_path: FingerprintCrawler.readApiDb(self._aslr_db_path)},
        )
        # the file is gone, the crawler has not read it
        os.remove(self._aslr_db_path)
        self.assertEqual((4, 4), crawler.getFingerprint(self._dump_path)[2:4])
        self.assertTrue(FingerprintCrawler.apiDbHasAslrOffsets(ASLR_DB))

    def testCrawlerAppliesAslrOffsetsOnRequest(self):
        crawler = FingerprintCrawler(
            [self._aslr_db_path], WINAPI1024_PATH, self._root_path, 0, ignore_aslr_offsets=False
        )
        family, path, in_api_vector, num_unique_apis, vector = crawler.getFingerprint(self._dump_path)
        self.assertEqual(("family", "sample_dump"), (family, path))
        self.assertEqual((4, 4), (in_api_vector, num_unique_apis))
        self.assertNotEqual(crawler.getEmptyFingerprint(), vector)

    def testCrawlerIgnoresAslrOffsetsByDefault(self):
        # previous behaviour: offsets are dropped, so the dump of the DB's boot is not resolved
        crawler = FingerprintCrawler([self._aslr_db_path], WINAPI1024_PATH, self._root_path, 0)
        family, path, in_api_vector, num_unique_apis, vector = crawler.getFingerprint(self._dump_path)
        self.assertEqual((0, 0), (in_api_vector, num_unique_apis))
        self.assertEqual(crawler.getEmptyFingerprint(), vector)

    def testIgnoredAslrOffsetsCollide(self):
        scout, warnings = self._loadWithRecordedLog(self._aslr_db_path, True)
        # both DLLs end up at 0x180000000, the DLL loaded last wins for both addresses
        api_map = scout.api_maps["Test Windows 10"]
        self.assertEqual(2, len(api_map))
        self.assertEqual(1, len(set(entry[0] for entry in api_map.values())))
        self.assertEqual(1, len(warnings))
        self.assertTrue("collide" in warnings[0].getMessage())

    def testDllsAtTheirOwnAslrOffsetsSharingAnAddressAreNoted(self):
        # DllBaseChecker loads every DLL in a process of its own, so DLLs of different processes get the same address
        # (the example DBs: 3 to 6 % of the exports), which is only logged as a note and not as a warning
        db = {
            "aslr_offsets": True,
            "dlls": {
                f"32_1.0_dll{index}.dll_0x10000000": _buildDll(
                    32, 0x10000000, 0x10000000 - 0x74000000, [(0x1000 + 0x10 * i, f"Api{index}_{i}") for i in range(10)]
                )
                for index in range(3)
            },
            "os_name": "Test Windows 10",
            "os_version": "10.0.17134",
        }
        db_path = os.path.join(self._tmp_dir, "shared_address_db.json")
        with open(db_path, "w") as f_out:
            f_out.write(json.dumps(db))
        with self.assertLogs("apiscout.ApiScout", logging.INFO) as logs:
            scout = ApiScout()
            scout.loadDbFile(db_path)
        self.assertEqual(10, len(scout.api_maps["Test Windows 10"]))
        self.assertEqual([logging.INFO], sorted({record.levelno for record in logs.records} - {logging.DEBUG}))
        self.assertTrue(any("20 of 30 exports" in record.getMessage() for record in logs.records))

    def testOverlapWithADllPlacedByAModuleListWarns(self):
        # A is where the module list of the scan puts it, which is where the stale offset of B (another boot) puts
        # B: this is a real overlap, not the sharing of addresses by DLLs that were loaded in separate processes
        exports = [(0x1000 + 0x10 * i, f"Api{i}") for i in range(10)]
        db = {
            "aslr_offsets": True,
            "dlls": {
                "32_1.0_a.dll_0x10000000": _buildDll(32, 0x10000000, 0x10000000 - 0x74000000, exports),
                "32_1.0_b.dll_0x10000000": _buildDll(32, 0x10000000, 0x10000000 - 0x75000000, exports),
            },
            "os_name": "Test Windows 10",
            "os_version": "10.0.17134",
        }
        db_path = os.path.join(self._tmp_dir, "placed_db.json")
        with open(db_path, "w") as f_out:
            f_out.write(json.dumps(db))
        with self.assertNoLogs("apiscout.ApiScout", logging.WARNING):
            ApiScout().loadDbFile(db_path)
        with self.assertLogs("apiscout.ApiScout", logging.WARNING) as logs:
            ApiScout().loadDbFile(db_path, lambda api_db: {"32_1.0_a.dll_0x10000000": 0x75000000})
        self.assertIn("10 of 20 exports collide", logs.records[0].getMessage())

    def testCollisionsOfDllsWithoutAslrOffsetWarn(self):
        # a DLL that was not given an offset stays at its ImageBase: this is a real collision, with or without
        # the offsets of the other DLLs
        db = json.loads(json.dumps(ASLR_DB))
        db["dlls"]["64_10.0.17134.1_unplaced.dll_0x180000000"] = _buildDll(
            64, 0x180000000, 0, [(0x1000, "Unplaced1"), (0x2000, "Unplaced2")]
        )
        db["dlls"]["64_10.0.17134.1_unplaced2.dll_0x180000000"] = _buildDll(
            64, 0x180000000, 0, [(0x1000, "Other1"), (0x2000, "Other2")]
        )
        db_path = os.path.join(self._tmp_dir, "partial_db.json")
        with open(db_path, "w") as f_out:
            f_out.write(json.dumps(db))
        scout, warnings = self._loadWithRecordedLog(db_path, False)
        self.assertEqual(1, len(warnings))
        self.assertIn("2 of 8 exports collide", warnings[0].getMessage())

    def testExampleDbsLoadWithoutWarnings(self):
        for db_name in ("win10_prof_1803_example.json", "win7_prof-n_sp1_example.json"):
            scout, warnings = self._loadWithRecordedLog(os.sep.join([PROJECT_ROOT, "dbs", db_name]), False)
            self.assertEqual([], warnings, db_name)

    def testAppliedAslrOffsetsDoNotCollide(self):
        scout, warnings = self._loadWithRecordedLog(self._aslr_db_path, False)
        expected = {
            0x7FFA55931000: ("kernel32.dll_0x180000000", "CreateFileW", 64),
            0x7FFA55932000: ("kernel32.dll_0x180000000", "WriteFile", 64),
            0x7FFA54A11000: ("advapi32.dll_0x180000000", "RegOpenKeyExW", 64),
            0x7FFA54A12000: ("advapi32.dll_0x180000000", "RegSetValueExW", 64),
        }
        self.assertEqual(expected, scout.api_maps["Test Windows 10"])
        self.assertEqual([], warnings)

    def testNoCollisionWarningWithoutAslrOffsets(self):
        scout, warnings = self._loadWithRecordedLog(os.path.join(THIS_DIR, "minimal_db.json"), True)
        self.assertEqual([], warnings)


if __name__ == "__main__":
    unittest.main()
