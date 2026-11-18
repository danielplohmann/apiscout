import logging
import os
import re
import shutil
import tempfile

from apiscout.ApiScout import ApiScout
from apiscout.DumpScan import configure_placement, infer_base_address, recover_pointers
from apiscout.LoadAddresses import DllPlacer
from apiscout.Minidump import Minidump
from apiscout.utility import paused_garbage_collection, read_json

LOG = logging.getLogger(__name__)


class FingerprintCrawler:
    def __init__(
        self,
        db_paths,
        winapi1024_path,
        root_path,
        filter_size=0,
        ignore_aslr_offsets=True,
        api_dbs=None,
        min_confidence=0,
        refresh=False,
    ):
        # api_dbs: {path: content} of API DBs that the caller has read already (readApiDb), so they are not parsed again
        # ignore_aslr_offsets=True (default, previous behaviour) addresses all DLLs at their file ImageBase,
        # which is only meaningful for dumps from systems without ASLR and ambiguous for DBs in which
        # many DLLs share one ImageBase (e.g. 64bit Windows 10: 0x180000000).
        self._ignore_aslr_offsets = ignore_aslr_offsets
        api_dbs = api_dbs or {}
        self._api_dbs = {path: api_dbs[path] if path in api_dbs else self.readApiDb(path) for path in db_paths}
        self._winapi1024_path = winapi1024_path
        self._scout = self._initScout()
        self._min_confidence = min_confidence
        self._refresh = refresh
        self._filter_size = filter_size
        self._root_path = root_path
        self._ignore_files = {}
        self._empty_fingerprint = self.getEmptyFingerprint()

    def _initScout(self, placer=None):
        scout = ApiScout()
        # optionally override potential ASLR offsets that are stored in the API DB files.
        scout.ignoreAslrOffsets(self._ignore_aslr_offsets)
        # load DB file
        for db_path, document in self._api_dbs.items():
            scout.loadDbFile(db_path, placer.forDb(db_path) if placer else None, api_db=document)
        # load WinApi1024 vector
        scout.loadWinApi1024(self._winapi1024_path)
        return scout

    @staticmethod
    def readApiDb(db_path):
        """the content of an API DB file, for apiDbHasAslrOffsets() and the api_dbs of the constructor"""
        with paused_garbage_collection():
            return read_json(db_path)

    @staticmethod
    def dbHasAslrOffsets(db_path):
        """check if an API DB file carries per-module ASLR offsets, i.e. is bound to the boot it was built in"""
        return FingerprintCrawler.apiDbHasAslrOffsets(FingerprintCrawler.readApiDb(db_path))

    @staticmethod
    def apiDbHasAslrOffsets(api_db):
        """dbHasAslrOffsets() for the content of an API DB"""
        if api_db.get("aslr_offsets", False):
            return True
        return any(dll.get("aslr_offset", 0) for dll in api_db.get("dlls", {}).values())

    def _getFamilyAndPath(self, path_to_binary):
        sub_path = path_to_binary[len(self._root_path) :]
        # collections are shared between systems, paths in them are separated by / on every OS
        separators = "".join(re.escape(separator) for separator in {os.sep, os.altsep or os.sep})
        path_parts = [part for part in re.split(f"[{separators}]", sub_path) if part]
        family = "-"
        path = ""
        if len(path_parts) > 1:
            family = path_parts[0]
            path = "/".join(path_parts[1:])
        else:
            path = path_parts[0]

        # the fields of a fingerprint are separated by semicolons
        def sanitize(value):
            return re.sub(r"[;\r\n]", "_", value)

        return sanitize(family), sanitize(path)

    def validateSamplePaths(self, paths):
        ids = {}
        for path in paths:
            key = self._getFamilyAndPath(path)
            if key in ids:
                raise ValueError(f"Same collection ID for {ids[key]!r} and {path!r}.")
            ids[key] = path

    def isCached(self, path):
        return self._isIgnorableBinary(*self._getFamilyAndPath(path))

    def getEmptyFingerprint(self):
        results = self._scout.crawl(b"\x00" * 0x100)
        filtered_results = self._scout.filter(results, 0, 0, self._filter_size)
        api_vectors = self._scout.getWinApi1024Vectors(filtered_results)
        apiscout_db_name, primary_vector = self._scout.getPrimaryVector(api_vectors)
        return primary_vector["vector"]

    def getFingerprint(self, path_to_binary):
        family, path = self._getFamilyAndPath(path_to_binary)
        if self._isIgnorableBinary(family, path):
            return self._ignore_files[(family, path)]
        # scout the binary
        try:
            with open(path_to_binary, "rb") as f_binary:
                binary = f_binary.read()
            minidump = Minidump(binary) if Minidump.isMinidump(binary) else None
            base = infer_base_address(path_to_binary, minidump=minidump)
            placer = DllPlacer()
            placer.ignore_aslr_offsets = self._ignore_aslr_offsets
            regions = configure_placement(placer, binary, base, minidump)
            scout = self._scout if placer.isEmpty() else self._initScout(placer)
            scout.setBaseAddress(base)
            results, _, _ = recover_pointers(scout, binary, regions, minidump, placer)
            confidences = scout.getConfidences(results) if self._min_confidence else None
            filtered = scout.filter(results, 0, 0, self._filter_size, own_image=False)
            if confidences is not None:
                filtered = scout.filterByConfidence(filtered, self._min_confidence, confidences)
            api_vectors = scout.getWinApi1024Vectors(filtered)
            _, primary_vector = scout.getPrimaryVector(api_vectors)
            return (
                family,
                path,
                primary_vector["in_api_vector"],
                primary_vector["num_unique_apis"],
                primary_vector["vector"],
            )
        except Exception as exc:
            LOG.warning(
                "Could not create a fingerprint for %s (%s), using the empty fingerprint instead.", path_to_binary, exc
            )
            return (family, path, 0, 0, self._empty_fingerprint)

    def loadIgnoreList(self, path_to_list):
        self._ignore_files = {}
        if os.path.isfile(path_to_list):
            with open(path_to_list, encoding="utf-8", errors="surrogateescape") as infile:
                for line in infile.readlines():
                    fields = tuple(line.strip().split(";"))
                    if len(fields) != 5:
                        if line.strip():
                            LOG.warning("Skipping malformed fingerprint line: %s", line.strip())
                        continue
                    key = fields[0], fields[1]
                    if key in self._ignore_files:
                        raise ValueError(f"Duplicate sample {key[0]}/{key[1]} in {path_to_list}.")
                    self._ignore_files[key] = fields

    def getNumberOfCrawlableFiles(self, file_list):
        return len(file_list) - self.getNumberOfIgnorableFiles(file_list)

    def getNumberOfIgnorableFiles(self, file_list):
        num_ignorable = 0
        for path_to_binary in file_list:
            family, path = self._getFamilyAndPath(path_to_binary)
            if self._isIgnorableBinary(family, path):
                num_ignorable += 1
        return num_ignorable

    def _isIgnorableBinary(self, family, path):
        return not self._refresh and (family, path) in self._ignore_files

    def mergeWithIgnoreList(self, fingerprint_list):
        """fingerprints of the loaded list that were not part of this crawl, followed by the given fingerprints"""
        crawled = {(entry[0], entry[1]) for entry in fingerprint_list}
        kept = [entry for key, entry in self._ignore_files.items() if key not in crawled]
        return kept + list(fingerprint_list)

    def persistFingerprintsToFile(self, fingerprint_list, dest_path):
        lines = ["{};{};{};{};{}\n".format(*entry) for entry in fingerprint_list]
        if os.path.exists(dest_path) and not os.path.isfile(dest_path):
            with open(dest_path, "w", encoding="utf-8", errors="surrogateescape") as f_destination:
                f_destination.writelines(lines)
            return
        # an existing file is only replaced once all fingerprints are written, links are followed
        dest_path = os.path.realpath(dest_path)
        file_descriptor, temp_path = tempfile.mkstemp(dir=os.path.dirname(dest_path), suffix=".tmp")
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8", errors="surrogateescape") as f_destination:
                f_destination.writelines(lines)
            # the temporary file is private, the result gets the mode of the file it replaces or of a new file
            if os.path.exists(dest_path):
                shutil.copymode(dest_path, temp_path)
            else:
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(temp_path, 0o666 & ~umask)
            os.replace(temp_path, dest_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
