import contextlib
import email.message
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(THIS_DIR, "..", "apiscout", "db_builder"))

NAME = "foo.dll"
DATA_X64 = b"MZ" + b"x64 file" * 40
DATA_X86 = b"MZ" + b"x86 file" * 30
DATA_OLD_X64 = b"MZ" + b"old x64" * 50


def load_module():
    import DllDownloader

    return DllDownloader


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_update(kb, build, date, architecture="amd64", destination="$(runtime.system32)\\", name=NAME, others=None):
    """an update of a file in the index: its assembly installs the file to a destination"""
    heading = f"{date}—{kb} (OS Build {build})" if build else ""
    update_info = {"heading": heading, "releaseDate": date}
    if build:
        update_info["releaseVersion"] = build
    if others:
        update_info["otherWindowsVersions"] = others
    assembly = {
        "assemblyIdentity": {"processorArchitecture": architecture},
        "attributes": [{"name": name, "destinationPath": destination, "sourceName": name}],
    }
    return {"updateInfo": update_info, "assemblies": {f"{architecture}_asm_{kb}": assembly}}


def make_file(data, machine, timestamp, versions, **extra):
    """(SHA-256, entry) of the index for a file"""
    info = {"size": len(data), "machineType": machine, "timestamp": timestamp, "virtualSize": 0x5000}
    info.update(extra)
    return sha256(data), {"fileInfo": info, "windowsVersions": versions}


def make_index(*files):
    return dict(files)


def default_index():
    """foo.dll for 11-24H2: x64 and x86 files in KB5000002 (KB5000002 is also the update of 11-25H2), an older x64 file in KB5000001
    only, and a forwarder stub that must not be taken"""
    return make_index(
        make_file(
            DATA_X64,
            34404,
            0x66000001,
            {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2000", "2024-11-12", others=["11-25H2"])}},
        ),
        make_file(
            DATA_OLD_X64,
            34404,
            0x65000000,
            {"11-24H2": {"KB5000001": make_update("KB5000001", "26100.1000", "2024-10-01")}},
        ),
        make_file(
            DATA_X86,
            332,
            0x66000002,
            {
                "11-24H2": {
                    "KB5000002": make_update("KB5000002", "26100.2000", "2024-11-12", "wow64", others=["11-25H2"])
                }
            },
        ),
        make_file(
            b"MZ forwarder",
            34404,
            0x66000003,
            {
                "11-24H2": {
                    "KB5000002": make_update(
                        "KB5000002", "26100.2000", "2024-11-12", destination="$(runtime.system32)\\forwarders\\"
                    )
                }
            },
        ),
        make_file(
            b"MZ arm64",
            43620,
            0x66000004,
            {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2000", "2024-11-12", "arm64")}},
        ),
        make_file(
            b"MZ later",
            34404,
            0x67000000,
            {"11-24H2": {"KB5000003": make_update("KB5000003", "26100.3000", "2025-01-14", name="other.dll")}},
        ),
    )


def gz(index):
    return gzip.compress(json.dumps(index).encode("utf-8"))


class FakeNetwork:
    """stands for http_get: serves the Winbindex indexes and the files of the symbol server, and counts requests"""

    def __init__(self, indexes=None, files=None):
        self.indexes = indexes or {}
        self.files = files or {}
        self.requests = []

    def __call__(self, url, max_bytes):
        self.requests.append(url)
        D = load_module()
        if url.startswith("https://winbindex.m417z.com/data/by_filename_compressed/"):
            name = url.rsplit("/", 1)[1][: -len(".json.gz")]
            if name not in self.indexes:
                raise D.NotFound(url)
            return gz(self.indexes[name])
        if url.startswith("https://msdl.microsoft.com/download/symbols/"):
            if url not in self.files:
                raise D.NotFound(url)
            data = self.files[url]
            if len(data) > max_bytes:
                raise D.Mismatch(f"larger than the {max_bytes} bytes of Winbindex")
            return data
        raise AssertionError("request to " + url)

    def downloads(self):
        return [url for url in self.requests if "msdl.microsoft.com" in url]


def http_error(code, retry_after=None):
    headers = email.message.Message()
    if retry_after:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("https://msdl.microsoft.com/x", code, "error", headers, None)


def symbol_url(timestamp, virtual_size, name=NAME):
    return f"https://msdl.microsoft.com/download/symbols/{name}/{timestamp:08X}{virtual_size:x}/{name}"


class IndexTestSuite(unittest.TestCase):
    def setUp(self):
        self.D = load_module()

    def test_parse_index(self):
        index = default_index()
        self.assertEqual(index, self.D.parse_index(gz(index)))
        for raw in (b"not gzip", gzip.compress(b"not json"), gzip.compress(b"[1, 2]")):
            with self.assertRaises(self.D.DownloaderError):
                self.D.parse_index(raw)

    def test_list_updates(self):
        updates = self.D.list_updates(default_index())
        self.assertEqual(
            {("11-24H2", "KB5000001"), ("11-24H2", "KB5000002"), ("11-24H2", "KB5000003"), ("11-25H2", "KB5000002")},
            set(updates),
        )
        self.assertTrue(updates[("11-24H2", "KB5000002")].primary)
        self.assertFalse(updates[("11-25H2", "KB5000002")].primary)
        self.assertEqual("26100.2000", updates[("11-25H2", "KB5000002")].release)
        self.assertEqual("2024-11-12", updates[("11-25H2", "KB5000002")].date)

    def test_update_selector(self):
        parse = self.D.parse_update_selector
        self.assertEqual(("kb", "KB5046617"), parse("KB5046617"))
        self.assertEqual(("kb", "KB5046617"), parse("kb5046617"))
        self.assertEqual(("kb", "KB5046617"), parse("5046617"))
        self.assertEqual(("build", "26100.2605"), parse("26100.2605"))
        self.assertEqual(("build", "26100.2605"), parse("10.0.26100.2605"))
        self.assertEqual(("base", "BASE"), parse("base"))
        for text in ("", "latest", "10.0", "KB12"):
            with self.assertRaises(self.D.DownloaderError):
                parse(text)

    def test_select_update(self):
        updates = self.D.list_updates(default_index())
        select = self.D.select_update
        by_kb = select(updates, "11-24H2", "KB5000002")
        self.assertEqual(("11-24H2", "KB5000002"), (by_kb.windows, by_kb.kb))
        self.assertEqual("KB5000002", select(updates, "11-24H2", "10.0.26100.2000").kb)
        self.assertEqual("KB5000002", select(updates, None, "26100.2000").kb)
        # the update is stored under 11-24H2 and applies to 11-25H2 as well
        other = select(updates, "11-25H2", "KB5000002")
        self.assertEqual("11-25H2", other.windows)
        self.assertEqual({"11-24H2", "11-25H2"}, other.family)
        self.assertEqual("11-24H2", select(updates, None, "KB5000002").windows)

    def test_select_update_errors(self):
        updates = self.D.list_updates(default_index())
        with self.assertRaisesRegex(self.D.DownloaderError, "no update 'KB5000009'"):
            self.D.select_update(updates, "11-24H2", "KB5000009")
        with self.assertRaisesRegex(self.D.DownloaderError, "no Windows version '1607'.*11-24H2"):
            self.D.select_update(updates, "1607", "KB5000002")
        with self.assertRaisesRegex(self.D.DownloaderError, "no update '26100.9999'"):
            self.D.select_update(updates, None, "26100.9999")

    def test_ambiguous_build_and_base(self):
        index = make_index(
            make_file(
                DATA_X64,
                34404,
                1,
                {
                    "1607": {
                        "KB5000010": make_update("KB5000010", "14393.100", "2020-01-01"),
                        "KB5000011": make_update("KB5000011", "14393.100", "2020-01-02"),
                        "BASE": {
                            "windowsVersionInfo": {"releaseDate": "2016-08-02"},
                            "sourcePaths": ["Windows\\System32\\foo.dll"],
                        },
                    },
                    "1507": {"BASE": {"windowsVersionInfo": {"releaseDate": "2015-07-29"}, "sourcePaths": []}},
                },
            )
        )
        updates = self.D.list_updates(index)
        with self.assertRaisesRegex(self.D.DownloaderError, "several updates \\(KB5000010, KB5000011\\)"):
            self.D.select_update(updates, "1607", "14393.100")
        with self.assertRaisesRegex(self.D.DownloaderError, "BASE exists for every Windows version"):
            self.D.select_update(updates, None, "BASE")
        base = self.D.select_update(updates, "1607", "BASE")
        self.assertEqual(("1607", "BASE", None, "2016-08-02"), (base.windows, base.kb, base.release, base.date))

    def test_windows_family(self):
        updates = self.D.list_updates(
            make_index(
                make_file(
                    b"MZ a",
                    34404,
                    1,
                    {"2004": {"KB5000001": make_update("KB5000001", "19041.1", "2020-06-01", others=["20H2"])}},
                ),
                make_file(
                    b"MZ b",
                    34404,
                    2,
                    {"20H2": {"KB5000002": make_update("KB5000002", "19042.2", "2020-11-01", others=["21H2"])}},
                ),
                make_file(
                    b"MZ c", 34404, 3, {"1607": {"KB5000003": make_update("KB5000003", "14393.3", "2020-11-01")}}
                ),
            )
        )
        self.assertEqual({"2004", "20H2", "21H2"}, self.D.windows_family(updates, "2004"))
        self.assertEqual({"1607"}, self.D.windows_family(updates, "1607"))


class FindFilesTestSuite(unittest.TestCase):
    def setUp(self):
        self.D = load_module()
        self.index = default_index()
        self.updates = self.D.list_updates(self.index)

    def select(self, windows, update):
        return self.D.select_update(self.updates, windows, update)

    def test_system32_and_syswow64(self):
        files = self.D.find_files(self.index, "FOO.dll", self.select("11-24H2", "KB5000002"))
        self.assertEqual({"System32", "SysWOW64"}, set(files))
        # no forwarder (another folder) and no ARM64 file
        self.assertEqual([sha256(DATA_X64)], [file.sha256 for file in files["System32"]])
        self.assertEqual([sha256(DATA_X86)], [file.sha256 for file in files["SysWOW64"]])
        self.assertEqual("foo.dll", files["System32"][0].filename)
        self.assertEqual("KB5000002", files["System32"][0].source_kb)

    def test_other_windows_version_of_the_update(self):
        files = self.D.find_files(self.index, NAME, self.select("11-25H2", "KB5000002"))
        self.assertEqual([sha256(DATA_X64)], [file.sha256 for file in files["System32"]])

    def test_file_not_changed_by_the_update(self):
        # KB5000001 lists the DLL for System32 only: KB5000002's x64 file is exact, there is no x86 file before KB5000002
        files = self.D.find_files(self.index, NAME, self.select("11-24H2", "KB5000001"))
        self.assertEqual({"System32"}, set(files))
        self.assertEqual([sha256(DATA_OLD_X64)], [file.sha256 for file in files["System32"]])
        # an update that does not list the DLL at all takes the latest earlier one, never a later one
        files = self.D.find_files(self.index, NAME, self.select("11-24H2", "KB5000003"))
        self.assertEqual("KB5000002", files["System32"][0].source_kb)
        self.assertEqual([sha256(DATA_X64)], [file.sha256 for file in files["System32"]])
        self.assertEqual({}, self.D.find_files(self.index, NAME, self.select("11-24H2", "KB5000003"), fallback=False))
        self.assertEqual({}, self.D.find_files(self.index, "other.dll", self.select("11-24H2", "KB5000002")))

    def test_x86_assembly_is_syswow64(self):
        index = make_index(
            make_file(
                DATA_X86, 332, 5, {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12", "x86")}}
            )
        )
        files = self.D.find_files(index, NAME, self.D.select_update(self.D.list_updates(index), None, "KB5000002"))
        self.assertEqual({"SysWOW64"}, set(files))
        # the machine type has to fit the architecture
        index = make_index(
            make_file(
                DATA_X86,
                34404,
                5,
                {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12", "wow64")}},
            )
        )
        self.assertEqual(
            {}, self.D.find_files(index, NAME, self.D.select_update(self.D.list_updates(index), None, "KB5000002"))
        )

    def test_first_release_has_source_paths(self):
        base = {"windowsVersionInfo": {"releaseDate": "2024-09-30"}, "sourcePaths": ["Windows\\SysWOW64\\foo.dll"]}
        base64 = {"windowsVersionInfo": {"releaseDate": "2024-09-30"}, "sourcePaths": ["Windows\\System32\\foo.dll"]}
        wbem = {
            "windowsVersionInfo": {"releaseDate": "2024-09-30"},
            "sourcePaths": ["Windows\\System32\\wbem\\foo.dll"],
        }
        index = make_index(
            make_file(DATA_X86, 332, 5, {"11-24H2": {"BASE": base}}),
            make_file(DATA_X64, 34404, 6, {"11-24H2": {"BASE": base64}}),
            make_file(DATA_OLD_X64, 34404, 7, {"11-24H2": {"BASE": wbem}}),
        )
        update = self.D.select_update(self.D.list_updates(index), "11-24H2", "BASE")
        files = self.D.find_files(index, NAME, update)
        self.assertEqual([sha256(DATA_X64)], [file.sha256 for file in files["System32"]])
        self.assertEqual([sha256(DATA_X86)], [file.sha256 for file in files["SysWOW64"]])

    def test_several_files_newest_first(self):
        older = make_file(
            DATA_OLD_X64, 34404, 100, {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12")}}
        )
        newer = make_file(
            DATA_X64, 34404, 200, {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12")}}
        )
        index = make_index(older, newer)
        update = self.D.select_update(self.D.list_updates(index), None, "KB5000002")
        files = self.D.find_files(index, NAME, update)["System32"]
        self.assertEqual([sha256(DATA_X64), sha256(DATA_OLD_X64)], [file.sha256 for file in files])

    def test_unsafe_names_are_not_used_as_file_names(self):
        index = make_index(
            make_file(
                DATA_X64,
                34404,
                5,
                {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12", name="foo.dll")}},
            )
        )
        entry = next(iter(index.values()))
        attribute = next(iter(entry["windowsVersions"]["11-24H2"]["KB5000002"]["assemblies"].values()))["attributes"][0]
        attribute["name"] = "../FOO.dll"
        targets = self.D._install_targets(entry["windowsVersions"]["11-24H2"]["KB5000002"], 34404, "../foo.dll")
        self.assertEqual([("System32", "../foo.dll")], targets)
        self.assertEqual("foo.dll", self.D._safe_filename("../foo.dll", "foo.dll"))
        self.assertEqual("Foo.dll", self.D._safe_filename("Foo.dll", "foo.dll"))

    def test_a_newline_at_the_end_is_not_part_of_a_name(self):
        """a name or a hash that ends with a line feed is not one ($ matches before it)"""
        self.assertEqual("foo.dll", self.D._safe_filename("foo.dll\n", "foo.dll"))
        with self.assertRaisesRegex(self.D.DownloaderError, "not a file name"):
            self.D.dll_names(["kernel32.dll\n"])
        self.assertEqual(["kernel32.dll"], self.D.dll_names(["kernel32.dll"]))
        sha, entry = make_file(
            DATA_X64, 34404, 5, {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12")}}
        )
        update = self.D.select_update(self.D.list_updates({sha: entry}), None, "KB5000002")
        self.assertEqual(["System32"], list(self.D.find_files({sha: entry}, NAME, update)))
        self.assertEqual({}, self.D.find_files({sha + "\n": entry}, NAME, update))

    def test_entries_without_a_verifiable_hash_are_ignored(self):
        sha, entry = make_file(
            DATA_X64, 34404, 5, {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12")}}
        )
        update = self.D.select_update(self.D.list_updates({sha: entry}), None, "KB5000002")
        self.assertEqual(["System32"], list(self.D.find_files({sha: entry}, NAME, update)))
        self.assertEqual({}, self.D.find_files({"abc": entry}, NAME, update))
        entry["fileInfo"]["sha256"] = "0" * 64
        self.assertEqual({}, self.D.find_files({sha: entry}, NAME, update))
        entry["fileInfo"]["sha256"] = sha.upper()
        self.assertEqual(["System32"], list(self.D.find_files({sha: entry}, NAME, update)))

    def test_names_of_the_db(self):
        update = self.select("11-24H2", "KB5000002")
        self.assertEqual(("Windows 11 24H2 KB5000002 (AMD64)", "10.0.26100.2000"), self.D.os_names(update))
        self.assertEqual("10.0.26200.2000", self.D.os_names(update, "26200.2000")[1])
        self.assertEqual("win11_24h2_kb5000002.json", self.D.default_db_name(update))


class FileEntryTestSuite(unittest.TestCase):
    def setUp(self):
        self.D = load_module()

    def test_symbol_server_url(self):
        # kernel32.dll of 1809, as the example of Winbindex shows it
        file = self.D.FileEntry("System32", "Kernel32.dll", "0" * 64, {"timestamp": 0x5E6AFCC5, "virtualSize": 0x1D000})
        self.assertEqual(
            "https://msdl.microsoft.com/download/symbols/kernel32.dll/5E6AFCC51d000/kernel32.dll",
            file.symbolServerUrl(0x1D000),
        )
        # a timestamp with leading zeros has 8 digits
        file = self.D.FileEntry("System32", "a.dll", "0" * 64, {"timestamp": 0x2B0001, "virtualSize": 0x3000})
        self.assertEqual("002B00013000", file.symbolServerUrl(0x3000).split("/")[-2])

    def test_image_sizes(self):
        known = self.D.FileEntry("System32", "a.dll", "0" * 64, {"timestamp": 1, "virtualSize": 0x1D000})
        self.assertEqual([0x1D000], known.imageSizes())
        # limited information: the sizes between the end of the file's last section and the size of the whole file
        limited = self.D.FileEntry(
            "System32",
            "a.dll",
            "0" * 64,
            {
                "timestamp": 1,
                "size": 0x5800,
                "lastSectionVirtualAddress": 0x3000,
                "lastSectionPointerToRawData": 0x3000,
            },
        )
        self.assertEqual([0x6000, 0x5000, 0x4000], limited.imageSizes())
        self.assertEqual([], self.D.FileEntry("System32", "a.dll", "0" * 64, {"timestamp": 1}).imageSizes())


class DownloadTestSuite(unittest.TestCase):
    def setUp(self):
        self.D = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")
        self.cache = os.path.join(self.out, ".winbindex")
        self.index = default_index()
        self.update = self.D.select_update(self.D.list_updates(self.index), "11-24H2", "KB5000002")
        self.url64 = symbol_url(0x66000001, 0x5000)
        self.url86 = symbol_url(0x66000002, 0x5000)

    def network(self, **files):
        return FakeNetwork({NAME: self.index}, {self.url64: DATA_X64, self.url86: DATA_X86, **files})

    def read(self, folder):
        with open(os.path.join(self.out, folder, NAME), "rb") as f_in:
            return f_in.read()

    def test_download_verified_files(self):
        network = self.network()
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        self.assertEqual(["downloaded", "downloaded"], [status for status, _ in results])
        self.assertEqual(DATA_X64, self.read("System32"))
        self.assertEqual(DATA_X86, self.read("SysWOW64"))
        self.assertEqual([self.url64, self.url86], sorted(network.downloads()))
        self.assertEqual([], [n for n in os.listdir(os.path.join(self.out, "System32")) if n.endswith(".part")])

    def test_hash_mismatch_is_rejected_and_not_kept(self):
        # same size and timestamp, other content: the symbol server's copy is not the file of the index
        tampered = DATA_X64[:-1] + b"!"
        network = self.network(**{self.url64: tampered})
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        self.assertEqual("rejected", results[0][0])
        self.assertIn("differs from the file of Winbindex", results[0][1])
        self.assertEqual("downloaded", results[1][0])
        self.assertFalse(os.path.exists(os.path.join(self.out, "System32", NAME)))
        self.assertEqual([], [n for n in os.listdir(os.path.join(self.out, "System32"))])

    def test_wrong_size_is_rejected(self):
        for body in (DATA_X64 + b"more", DATA_X64[:-4]):
            network = self.network(**{self.url64: body})
            results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
            self.assertEqual("rejected", results[0][0])
            self.assertFalse(os.path.exists(os.path.join(self.out, "System32", NAME)))

    def test_bad_file_replaced_only_by_a_verified_one(self):
        os.makedirs(os.path.join(self.out, "System32"))
        target = os.path.join(self.out, "System32", NAME)
        with open(target, "wb") as f_out:
            f_out.write(DATA_OLD_X64)  # the file of an update before, or a truncated download
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, self.network())
        self.assertEqual("downloaded", results[0][0])
        self.assertEqual(DATA_X64, self.read("System32"))
        # when the new download is wrong, the existing file is left alone
        with open(target, "wb") as f_out:
            f_out.write(DATA_OLD_X64)
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, self.network(**{self.url64: b"MZ bad"}))
        self.assertEqual("rejected", results[0][0])
        self.assertEqual(DATA_OLD_X64, self.read("System32"))

    def test_resume_skips_verified_files(self):
        network = self.network()
        self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        before = len(network.downloads())
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        self.assertEqual(["present", "present"], [status for status, _ in results])
        self.assertEqual(before, len(network.downloads()))
        # the index is cached as well
        self.assertEqual(1, len([url for url in network.requests if "winbindex" in url]))
        # a file that was lost is fetched again, the other is kept
        os.remove(os.path.join(self.out, "SysWOW64", NAME))
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        self.assertEqual(["present", "downloaded"], [status for status, _ in results])
        self.assertEqual(before + 1, len(network.downloads()))

    def test_interrupted_download_leaves_no_file(self):
        def failing(url, max_bytes):
            if "msdl" in url:
                raise self.D.DownloaderError("connection reset (gave up after 5 attempts)")
            return gz(self.index)

        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, failing)
        self.assertEqual(["failed", "failed"], [status for status, _ in results])
        self.assertIn("connection reset", results[0][1])
        self.assertEqual([], os.listdir(os.path.join(self.out, "System32")))

    def test_missing_files(self):
        network = FakeNetwork({NAME: self.index}, {})
        results = self.D.fetch_dll(NAME, self.update, self.out, self.cache, network)
        self.assertEqual(["missing", "missing"], [status for status, _ in results])
        self.assertIn("System32: not on the symbol server", results[0][1])
        # not in Winbindex
        results = self.D.fetch_dll("bar.dll", self.update, self.out, self.cache, network)
        self.assertEqual([("missing", "not in Winbindex")], results)
        # in Winbindex, but without a file for the update
        network = FakeNetwork({"other.dll": self.index}, {})
        update = self.D.select_update(self.D.list_updates(self.index), "11-24H2", "KB5000001")
        results = self.D.fetch_dll("other.dll", update, self.out, self.cache, network)
        self.assertEqual("missing", results[0][0])
        self.assertIn("no file in System32 or SysWOW64 of KB5000001", results[0][1])

    def test_one_bitness_missing(self):
        update = self.D.select_update(self.D.list_updates(self.index), "11-24H2", "KB5000001")
        results = self.D.fetch_dll(
            NAME, update, self.out, self.cache, self.network(**{symbol_url(0x65000000, 0x5000): DATA_OLD_X64})
        )
        self.assertEqual([("downloaded", "System32: downloaded"), ("missing", "SysWOW64: no x86 file")], results)

    def test_image_size_candidates(self):
        # an index with limited information: the symbol server is asked for several sizes
        data = DATA_X64
        info = {
            "size": len(data),
            "machineType": 34404,
            "timestamp": 0x66000001,
            "lastSectionVirtualAddress": 0x3000,
            "lastSectionPointerToRawData": len(data) - 0x100,
        }
        index = make_index(
            (
                sha256(data),
                {
                    "fileInfo": info,
                    "windowsVersions": {"11-24H2": {"KB5000002": make_update("KB5000002", "26100.2", "2024-11-12")}},
                },
            )
        )
        update = self.D.select_update(self.D.list_updates(index), None, "KB5000002")
        network = FakeNetwork({NAME: index}, {symbol_url(0x66000001, 0x4000): data})
        results = self.D.fetch_dll(NAME, update, self.out, self.cache, network)
        self.assertEqual("downloaded", results[0][0])
        self.assertEqual([symbol_url(0x66000001, 0x4000)], network.downloads()[-1:])
        self.assertEqual(data, self.read("System32"))

    def test_http_get_retries_with_backoff(self):
        D = self.D
        pauses = []
        error = urllib.error.URLError("connection reset")
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.side_effect = [b"body", b""]
        with unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=[error, error, response]) as urlopen:
            self.assertEqual(b"body", D.http_get("https://msdl.microsoft.com/x", 100, sleep=pauses.append))
        self.assertEqual(3, urlopen.call_count)
        self.assertEqual([2.0, 4.0], pauses)
        self.assertEqual("Microsoft-Symbol-Server/10.0", urlopen.call_args[0][0].get_header("User-agent"))
        # the file does not exist: no retry
        pauses.clear()
        missing = http_error(404)
        with (
            unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=missing) as urlopen,
            self.assertRaises(D.NotFound),
        ):
            D.http_get("https://msdl.microsoft.com/x", 100, sleep=pauses.append)
        self.assertEqual((1, []), (urlopen.call_count, pauses))
        # a busy server is waited for, then given up on
        busy = http_error(503, "7")
        with (
            unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=busy) as urlopen,
            self.assertRaisesRegex(D.DownloaderError, "HTTP 503.*gave up after 3 attempts"),
        ):
            D.http_get("https://msdl.microsoft.com/x", 100, retries=2, sleep=pauses.append)
        self.assertEqual((3, [7, 7]), (urlopen.call_count, pauses))
        # other errors are not worth a retry
        denied = http_error(403)
        with (
            unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=denied) as urlopen,
            self.assertRaisesRegex(D.DownloaderError, "HTTP 403"),
        ):
            D.http_get("https://msdl.microsoft.com/x", 100, sleep=pauses.append)
        self.assertEqual(1, urlopen.call_count)

    def test_http_get_limits_the_size(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.side_effect = lambda limit: b"x" * min(limit, 1000)
        with (
            unittest.mock.patch.object(self.D.urllib.request, "urlopen", return_value=response),
            self.assertRaises(self.D.Mismatch),
        ):
            self.D.http_get("https://msdl.microsoft.com/x", 100)

    def test_http_get_ends_when_the_run_is_interrupted(self):
        D = self.D
        self.addCleanup(D.INTERRUPTED.clear)
        error = urllib.error.URLError("connection reset")
        # nothing is requested after the interrupt
        D.INTERRUPTED.set()
        with (
            unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=error) as urlopen,
            self.assertRaises(D.Interrupted),
        ):
            D.http_get("https://msdl.microsoft.com/x", 100)
        self.assertEqual(0, urlopen.call_count)
        # a pause between the attempts (2 s the first time) ends when the run is interrupted, the request is not repeated
        D.INTERRUPTED.clear()
        timer = threading.Timer(0.2, D.INTERRUPTED.set)
        started = time.monotonic()
        with unittest.mock.patch.object(D.urllib.request, "urlopen", side_effect=error) as urlopen:
            timer.start()
            with self.assertRaises(D.Interrupted):
                D.http_get("https://msdl.microsoft.com/x", 100)
        timer.join()
        self.assertEqual(1, urlopen.call_count)
        self.assertLess(time.monotonic() - started, 1.5)
        # so does the download of a body, which is read piece by piece
        D.INTERRUPTED.clear()
        reads = []

        def read(size):
            reads.append(size)
            D.INTERRUPTED.set()
            return b"x" * size

        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.side_effect = read
        with (
            unittest.mock.patch.object(D.urllib.request, "urlopen", return_value=response),
            self.assertRaises(D.Interrupted),
        ):
            D.http_get("https://msdl.microsoft.com/x", 1 << 20)
        self.assertEqual([D.READ_SIZE], reads)

    def test_http_get_reads_the_body_in_pieces(self):
        D = self.D
        body = bytes(range(256)) * 1000
        response = unittest.mock.MagicMock()
        stream = io.BytesIO(body)
        response.__enter__.return_value.read.side_effect = stream.read
        with unittest.mock.patch.object(D, "READ_SIZE", 10000):
            with unittest.mock.patch.object(D.urllib.request, "urlopen", return_value=response):
                self.assertEqual(body, D.http_get("https://msdl.microsoft.com/x", len(body)))
            sizes = [call.args[0] for call in response.__enter__.return_value.read.call_args_list]
            self.assertEqual([10000] * 25 + [6001, 1], sizes)
            stream.seek(0)
            with (
                unittest.mock.patch.object(D.urllib.request, "urlopen", return_value=response),
                self.assertRaises(D.Mismatch),
            ):
                D.http_get("https://msdl.microsoft.com/x", len(body) - 1)

    def test_only_two_hosts_in_the_code(self):
        path = os.path.join(THIS_DIR, "..", "apiscout", "db_builder", "DllDownloader.py")
        with open(path, encoding="utf-8") as f_in:
            hosts = set(re.findall(r"https?://([^/\s\"'{]+)", f_in.read()))
        self.assertEqual({"winbindex.m417z.com", "msdl.microsoft.com"}, hosts)


class RunTestSuite(unittest.TestCase):
    def setUp(self):
        self.D = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")
        # ntdll.dll is the reference of the update, foo.dll has no x86 file in KB5000001
        self.index = default_index()
        self.indexes = {"ntdll.dll": self.index, NAME: self.index}
        self.fetch = self.network = FakeNetwork(
            self.indexes, {symbol_url(0x66000001, 0x5000): DATA_X64, symbol_url(0x66000002, 0x5000): DATA_X86}
        )

    def run_main(self, *argv):
        out = io.StringIO()
        err = io.StringIO()
        with (
            unittest.mock.patch.object(self.D, "http_get", self.fetch),
            unittest.mock.patch.object(self.D.config, "DLL_FILTER", ["foo.DLL", "FOO.dll", "bar.dll"]),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = self.D.main(["--out", self.out, *argv])
        return code, out.getvalue(), err.getvalue()

    def test_old_python_stops_at_once(self):
        with (
            unittest.mock.patch.object(sys, "version_info", (3, 9, 0, "final", 0)),
            unittest.mock.patch.object(self.D, "http_get", side_effect=AssertionError("downloaded")),
            self.assertRaises(SystemExit) as stopped,
        ):
            self.D.main(["--out", self.out, "--list"])
        self.assertIn("needs Python 3.10 or newer, this is Python 3.9", str(stopped.exception.code))

    def test_download_with_missing_dll(self):
        code, out, _ = self.run_main("--windows", "11-24H2", "--update", "26100.2000", "--download-only", "--jobs", "1")
        self.assertEqual(0, code)
        self.assertIn("Update: 11-24H2 KB5000002 (26100.2000)", out)
        # the filter names a DLL twice, in different cases
        self.assertEqual(1, out.count("foo.dll "))
        self.assertIn("System32: downloaded; SysWOW64: downloaded", out)
        self.assertIn("bar.dll", out)
        self.assertIn("not in Winbindex", out)
        self.assertIn("2 downloaded, 0 already present, 1 not available", out)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "System32", NAME)))
        self.assertTrue(os.path.isfile(os.path.join(self.out, "SysWOW64", NAME)))
        # a second run does not download anything
        count = len(self.network.downloads())
        code, out, _ = self.run_main("--windows", "11-24H2", "--update", "KB5000002", "--download-only")
        self.assertEqual(0, code)
        self.assertIn("0 downloaded, 2 already present", out)
        self.assertEqual(count, len(self.network.downloads()))

    def test_builds_the_db_from_the_rest(self):
        built = {}

        def build_db(out_dir, update, os_version_hint, outfile, files=None):
            built.update(out_dir=out_dir, update=update, hint=os_version_hint, outfile=outfile)
            return {"num_dlls": 2, "num_apis": 3}

        with unittest.mock.patch.object(self.D, "build_db", build_db):
            code, out, _ = self.run_main("--windows", "11-24H2", "--update", "10.0.26100.2000")
        self.assertEqual(0, code)
        self.assertEqual("26100.2000", built["hint"])
        self.assertEqual(os.path.join(self.out, "win11_24h2_kb5000002.json"), built["outfile"])
        self.assertIn("2 DLLs, 3 APIs", out)

    def test_first_release_is_named_by_its_ntdll(self):
        base = {"windowsVersionInfo": {"releaseDate": "2024-09-30"}, "sourcePaths": ["Windows\\System32\\ntdll.dll"]}
        data = b"MZ ntdll"
        self.indexes["ntdll.dll"] = make_index(
            make_file(data, 34404, 9, {"11-24H2": {"BASE": base}}, version="10.0.26100.1 (WinBuild.160101.0800)")
        )
        self.network.files[symbol_url(9, 0x5000, "ntdll.dll")] = data
        built = {}

        def build_db(out_dir, update, os_version_hint, outfile, files=None):
            built.update(update=update, hint=os_version_hint)
            return {"num_dlls": 1, "num_apis": 1}

        with unittest.mock.patch.object(self.D, "build_db", build_db):
            code, out, _ = self.run_main("--windows", "11-24H2", "--update", "base", "--dlls", "ntdll.dll")
        self.assertEqual(0, code)
        self.assertEqual("26100.1", built["hint"])
        self.assertIn("System32: downloaded; SysWOW64: no x86 file", out)
        self.assertEqual(
            ("Windows 11 24H2 RTM (AMD64)", "10.0.26100.1"), self.D.os_names(built["update"], built["hint"])
        )
        self.assertEqual("win11_24h2_base.json", self.D.default_db_name(built["update"]))

    def test_files_of_an_earlier_run_are_left_out(self):
        built = []

        def build_db(out_dir, update, os_version_hint, outfile, files=()):
            built.append(sorted(os.path.relpath(path, out_dir).replace(os.sep, "/") for path in files))
            return {"num_dlls": len(files), "num_apis": 0}

        # KB5000001 has the old x64 file, the x64 download of KB5000002 is then not the file of Winbindex
        self.network.files[symbol_url(0x65000000, 0x5000)] = DATA_OLD_X64
        os.makedirs(os.path.join(self.out, "SysWOW64"))
        with open(os.path.join(self.out, "SysWOW64", "other.dll"), "wb") as f_out:
            f_out.write(b"MZ other")
        with unittest.mock.patch.object(self.D, "build_db", build_db):
            code, out, _ = self.run_main("--windows", "11-24H2", "--update", "KB5000001")
            self.assertEqual(0, code)
            self.assertIn("Left out of the DB, not verified as files of KB5000001: SysWOW64/other.dll.", out)
            self.network.files[symbol_url(0x66000001, 0x5000)] = DATA_X64[:-1] + b"!"
            code, out, _ = self.run_main("--windows", "11-24H2", "--update", "KB5000002")
        self.assertEqual(0, code)
        self.assertIn("1 rejected", out)
        self.assertEqual([["System32/foo.dll"], ["SysWOW64/foo.dll"]], built)
        self.assertIn("files of KB5000002: System32/foo.dll, SysWOW64/other.dll.", out)

    def test_db_is_built_from_the_given_files_only(self):
        sys.path.insert(0, os.path.join(THIS_DIR, "..", "apiscout", "db_builder"))
        self.addCleanup(sys.path.remove, sys.path[0])
        import DatabaseBuilder

        for folder in ("System32", "SysWOW64"):
            os.makedirs(os.path.join(self.out, folder))
            with open(os.path.join(self.out, folder, NAME), "wb") as f_out:
                f_out.write(b"MZ")
        keep = os.path.join(self.out, "SysWOW64", NAME)
        seen = []
        builder = DatabaseBuilder.DatabaseBuilder()
        with unittest.mock.patch.object(builder, "_extractPeExports", side_effect=lambda path: seen.append(path)):
            builder.extractRecursively([self.out], False, "W", "1", only_files={os.path.abspath(keep)})
        self.assertEqual([os.path.join(self.out, "SysWOW64") + os.sep + NAME], seen)

    def test_files_are_matched_in_the_case_of_the_file_system(self):
        """on Windows, a verified kernelbase.dll that is there as KernelBase.dll is the file of the index"""
        sys.path.insert(0, os.path.join(THIS_DIR, "..", "apiscout", "db_builder"))
        self.addCleanup(sys.path.remove, sys.path[0])
        import DatabaseBuilder

        os.makedirs(os.path.join(self.out, "System32"))
        with open(os.path.join(self.out, "System32", "KernelBase.dll"), "wb") as f_out:
            f_out.write(b"MZ")
        verified = [os.path.join(self.out, "System32", "kernelbase.dll")]
        seen = []
        builder = DatabaseBuilder.DatabaseBuilder()

        def build():
            seen.clear()
            with unittest.mock.patch.object(builder, "_extractPeExports", side_effect=seen.append):
                builder.extractRecursively([self.out], False, "W", "1", only_files=verified)
            return seen

        # a file system that is case sensitive has two files
        self.assertEqual([], build())
        self.assertEqual(["System32/KernelBase.dll"], self.D.other_files(self.out, verified))
        # os.path.normcase is the case of the platform, on Windows it is lower case
        with unittest.mock.patch("os.path.normcase", str.lower):
            self.assertEqual([os.path.join(self.out, "System32") + os.sep + "KernelBase.dll"], build())
            self.assertEqual([], self.D.other_files(self.out, verified))

    def test_failure_is_reported_and_db_is_built_from_the_rest(self):
        real = self.network.__call__

        def flaky(url, max_bytes):
            if url.endswith("/foo.dll") and "5000/" in url and "66000002" in url:
                raise self.D.DownloaderError("connection reset (gave up after 5 attempts)")
            return real(url, max_bytes)

        self.fetch = flaky
        with unittest.mock.patch.object(self.D, "build_db", return_value={"num_dlls": 1, "num_apis": 1}):
            code, out, _ = self.run_main("--windows", "11-24H2", "--update", "KB5000002")
        self.assertEqual(1, code)
        self.assertIn("1 failed", out)
        self.assertIn("Failed: foo.dll", out)
        self.assertIn("1 DLLs, 1 APIs", out)

    def test_ctrl_c_does_not_wait_for_the_downloads(self):
        """a download under way gives up when the run is interrupted, and the run does not wait for it: the attempts of a download
        with the pauses between them take minutes"""
        D = self.D
        self.addCleanup(D.INTERRUPTED.clear)
        downloading, gave_up = threading.Event(), threading.Event()
        real = self.network.__call__

        def fetch(url, max_bytes):
            if "msdl.microsoft.com" not in url:
                return real(url, max_bytes)
            # as http_get in a pause between its attempts
            downloading.set()
            if not D.INTERRUPTED.wait(20):
                return real(url, max_bytes)
            gave_up.set()
            raise D.Interrupted("interrupted")

        class Terminal:
            """Ctrl-C when the first DLL is done, which is bar.dll that is not in Winbindex, while foo.dll is downloaded"""

            def write(self, text):
                if text.startswith("["):
                    assert downloading.wait(10)
                    raise KeyboardInterrupt

            def flush(self):
                pass

        err = io.StringIO()
        started = time.monotonic()
        with (
            unittest.mock.patch.object(D, "http_get", fetch),
            unittest.mock.patch.object(sys, "stdout", Terminal()),
            contextlib.redirect_stderr(err),
        ):
            code = D.main(
                ["--out", self.out, "--windows", "11-24H2", "--update", "KB5000002", "--dlls", "bar.dll", "foo.dll"]
            )
        self.assertEqual(130, code)
        self.assertIn("interrupted", err.getvalue())
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(gave_up.wait(5))
        # nothing is left running
        for thread in threading.enumerate():
            if thread.name.startswith("ThreadPoolExecutor"):
                thread.join(5)
                self.assertFalse(thread.is_alive())

    def test_listing(self):
        code, out, _ = self.run_main("--list", NAME)
        self.assertEqual(0, code)
        self.assertRegex(out, r"11-24H2\s+3 updates")
        self.assertRegex(out, r"11-25H2\s+1 updates")
        code, out, _ = self.run_main("--list", NAME, "--windows", "11-24H2")
        self.assertEqual(0, code)
        self.assertRegex(out, r"KB5000001\s+2024-10-01\s+26100\.1000\s+x64\n")
        self.assertRegex(out, r"KB5000002\s+2024-11-12\s+26100\.2000\s+x64 x86\n")
        code, _, err = self.run_main("--list", NAME, "--windows", "1607")
        self.assertEqual(1, code)
        self.assertIn("no Windows version '1607'", err)

    def test_usage_errors(self):
        code, _, err = self.run_main("--windows", "11-24H2")
        self.assertEqual(1, code)
        self.assertIn("--update and --out are required", err)
        code, _, err = self.run_main("--update", "latest")
        self.assertEqual(1, code)
        self.assertIn("neither an update", err)
        code, _, err = self.run_main("--update", "KB5000009", "--windows", "11-24H2")
        self.assertEqual(1, code)
        self.assertIn("no update 'KB5000009' for 11-24H2", err)
        code, _, err = self.run_main("--list", "foo.dll\n")
        self.assertEqual(1, code)
        self.assertIn("is not a file name", err)
        self.assertEqual([], self.network.downloads())

    def test_partial_files_of_an_interrupted_run_are_removed(self):
        os.makedirs(os.path.join(self.out, "System32"))
        part = os.path.join(self.out, "System32", "x.dll.part")
        with open(part, "wb") as f_out:
            f_out.write(b"MZ")
        self.run_main("--windows", "11-24H2", "--update", "KB5000002", "--download-only")
        self.assertFalse(os.path.exists(part))


if __name__ == "__main__":
    unittest.main()
