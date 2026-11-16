import os
import json
from multiprocessing import Pool, cpu_count

from apiscout.ApiScout import ApiScout


class FingerprintCrawler():

    def __init__(self, db_paths, winapi1024_path, root_path, filter_size=0, ignore_aslr_offsets=True):
        # ignore_aslr_offsets=True (default, previous behaviour) addresses all DLLs at their file ImageBase,
        # which is only meaningful for dumps from systems without ASLR and ambiguous for DBs in which
        # many DLLs share one ImageBase (e.g. 64bit Windows 10: 0x180000000).
        self._ignore_aslr_offsets = ignore_aslr_offsets
        self._scout = self._initScout(db_paths, winapi1024_path)
        self._filter_size = filter_size
        self._root_path = root_path
        self._ignore_files = {}
        self._empty_fingerprint = self.getEmptyFingerprint()
        
    def _initScout(self, db_paths, winapi1024_path):
        scout = ApiScout()
        # optionally override potential ASLR offsets that are stored in the API DB files.
        scout.ignoreAslrOffsets(self._ignore_aslr_offsets)
        # load DB file
        for db_path in db_paths:
            scout.loadDbFile(db_path)
        # load WinApi1024 vector
        scout.loadWinApi1024(winapi1024_path)
        return scout
        
    @staticmethod
    def dbHasAslrOffsets(db_path):
        """ check if an API DB carries per-module ASLR offsets, i.e. is bound to the boot it was built in """
        with open(db_path, "r") as f_json:
            api_db = json.loads(f_json.read())
        if api_db.get("aslr_offsets", False):
            return True
        return any(dll.get("aslr_offset", 0) for dll in api_db.get("dlls", {}).values())

    def _getFamilyAndPath(self, path_to_binary):
        sub_path = path_to_binary[len(self._root_path):]
        path_parts = [part for part in sub_path.split(os.sep) if part]
        family = "-"
        path = ""
        if len(path_parts) > 1:
            family = path_parts[0]
            path = os.sep.join(path_parts[1:])
        else:
            path = path_parts[0]
        return family, path
        
    def getEmptyFingerprint(self):
        results = self._scout.crawl(b"\x00" * 0x100)
        filtered_results = self._scout.filter(results, 0, 0, self._filter_size)
        api_vectors = self._scout.getWinApi1024Vectors(filtered_results)
        apiscout_db_name, primary_vector = self._scout.getPrimaryVector(api_vectors)
        return primary_vector["vector"]
        
    def getFingerprint(self, path_to_binary):
        family, path = self._getFamilyAndPath(path_to_binary)
        if self._isIgnorableBinary(family, path):
            return self._ignore_files[family + "_" + path]
        if os.path.isfile(path_to_binary):
            with open(path_to_binary, "rb") as f_binary:
                binary = f_binary.read()
        # scout the binary
        try:
            results = self._scout.crawl(binary)
            filtered_results = self._scout.filter(results, 0, 0, self._filter_size)
            api_vectors = self._scout.getWinApi1024Vectors(filtered_results)
            apiscout_db_name, primary_vector = self._scout.getPrimaryVector(api_vectors)
            return (family, path, primary_vector["in_api_vector"], primary_vector["num_unique_apis"], primary_vector["vector"])
        except:
            return (family, path, 0, 0, self._empty_fingerprint)
        
    def loadIgnoreList(self, path_to_list):
        self._ignore_files = {}
        if os.path.isfile(path_to_list):
            with open(path_to_list, "r") as infile:
                for line in infile.readlines():
                    line = line.strip()
                    if line:
                        family = line.split(";")[0]
                        binary_path = line.split(";")[1]
                        self._ignore_files[family + "_" + binary_path] = tuple(line.split(";"))
                        
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
        return family + "_" + path in self._ignore_files
        
    def persistFingerprintsToFile(self, fingerprint_list, dest_path):
        with open(dest_path, "w") as f_destination:
            for entry in fingerprint_list:
                f_destination.write("%s;%s;%s;%s;%s\n" % entry)

