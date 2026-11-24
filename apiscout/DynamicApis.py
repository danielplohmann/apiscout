"""
APIs that a program resolves at run time and therefore never stores as pointers: hashes of export names and export names as strings.

Hashes: shellcode and loaders walk the export table of a DLL and compare a hash of each name with a constant. For every export name
of an API DB, the hashes of six common algorithms are computed once (with numpy) and searched in the dump as 32bit little endian
constants at any offset:

    ror13      ROR13 of the name, the "ror13AddHash32" of Mandiant FLARE's shellcode_hashes
    block_api  Metasploit's block_api: ROR13 of the upper case UTF-16 module name (with its terminator) plus ROR13 of the name with its
               terminator, "ror13AddHash32AddDll" in shellcode_hashes
    crc32      CRC-32 (zlib) of the name
    djb2       hash * 33 + c from 5381, "add1505Shl5Hash32" in shellcode_hashes
    fnv1a      32bit FNV-1a
    sdbm       hash * 65599 + c from 0, the sdbm of http://www.cse.yorku.ca/~oz/hash.html

Sources of the definitions and the values the tests check: tests/testDynamicApis.py. Other variants (other seeds, case folding, ...)
are not searched.

Keyed hashes: malware often combines the hash with a constant that is chosen for each sample, XOR (hash ^ key) or ADD (hash + key),
so that the hashes of the DB do not match. The key is found in the dump itself, for every algorithm but block_api (whose module hash
already is an added constant). PROBE_APIS are APIs that loaders almost always resolve; their hashes combined with every 32bit value of
the dump (at any offset) give the candidate keys value ^ hash and value - hash, and the real key is the one that many different probe
APIs agree on. To keep it cheap, only the first KEY_ANCHORS probes propose candidates (KEY_ANCHOR_HITS of them have to agree), the
others are looked up for those. A key needs min_apis different probe APIs, so many that the dump is expected to hold less than
MAX_CHANCE_KEYS keys by chance, see getMinimumKeyApis(). The dump is searched in windows of KEY_WINDOW bytes (the hashes of a sample
are not farther apart). Values with a zero byte are left out (a hash has none in 98.4% of the cases, text, small numbers and pointers
do), and so are blocks of RANDOM_BLOCK_SIZE bytes of uniformly distributed bytes (compressed or encrypted data, nothing to be found).
With an accepted key, all export names are searched in the dump with it, like the other hashes but in regions with a larger gap,
KEYED_REGION_GAP: the hashes of a resolver are constants in its code, not a table. The findings say the key, as in sdbm^0x1e5c48de
(XOR) and crc32+0x218fe95b (ADD). A constant is the hash of one API, so keys compete for the hits (see DynamicApiFinder._findHits):
the hashes of the names that end with A and W differ by the same value for CRC-32 and for the hashes that add the last character,
which makes a key at that difference from the real one agree with many probe APIs.

One constant matches one of many hashes by chance: a DB with n distinct hashes of an algorithm makes every offset of a dump a hit with
probability n / 2**32, some 24 hits per MB for 100,000 names. So hits are only reported in a region, a chain of hits of the same
algorithm that follow each other within REGION_GAP bytes, with at least min_hits distinct constants. min_hits is at least
MIN_REGION_HITS and is raised until a dump of this size is expected to hold less than MAX_CHANCE_REGIONS regions by chance, see
getMinimumHits().

Strings: export names that occur as complete, NUL terminated ASCII or UTF-16LE strings, e.g. the argument of GetProcAddress. Only names
of the API DB with at least a minimum length count, and the string has to start behind a byte (UTF-16: word) that is not printable.
Names that are ordinary words (socket, system, select) are everywhere, so a string only counts in a run of at least MIN_STRING_RUN
different names of one encoding that follow each other within STRING_RUN_GAP bytes, like the names passed to GetProcAddress or an
import name table do.
"""

import concurrent.futures
import functools
import itertools
import math
import os
import re
import zlib
from typing import NamedTuple

import numpy as np

HASH_ALGORITHMS = ("ror13", "block_api", "crc32", "djb2", "fnv1a", "sdbm")
# the algorithms with which hashes combined with a key are searched: all but block_api
KEYED_ALGORITHMS = ("ror13", "crc32", "djb2", "fnv1a", "sdbm")
# a key is combined with the hash of the API by XOR (value = hash ^ key) or ADD (value = hash + key), 32bit
KEY_MODES = ("xor", "add")
KEY_SYMBOLS = {"xor": "^", "add": "+"}
# the APIs that loaders, droppers and injectors almost always resolve, hashed to find the key of a sample: the first KEY_ANCHORS ones
# are the most common ones, they propose the keys
PROBE_APIS = (
    "LoadLibraryA",
    "GetProcAddress",
    "VirtualAlloc",
    "LoadLibraryW",
    "ExitProcess",
    "CloseHandle",
    "VirtualProtect",
    "CreateFileW",
    "CreateFileA",
    "ReadFile",
    "WriteFile",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "CreateProcessA",
    "CreateProcessW",
    "CreateThread",
    "WaitForSingleObject",
    "Sleep",
    "VirtualFree",
    "OpenProcess",
    "GetCurrentProcess",
    "GetLastError",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "GetTickCount",
    "FreeLibrary",
    "TerminateProcess",
    "WinExec",
    "HeapAlloc",
    "GetModuleFileNameW",
    "LocalFree",
)
NUM_PROBE_APIS = len(PROBE_APIS)
KEY_ANCHORS = 4
# a candidate key is looked up with all probes if this many anchors agree on it
KEY_ANCHOR_HITS = 2
# fewest different probe APIs that make a key, whatever the size of the dump
MIN_KEY_APIS = 3
# keys that chance may form in a dump (expected number) at most, more probe APIs are demanded above
MAX_CHANCE_KEYS = 0.01
# the dump is searched for keys in windows of this many bytes, overlapping by a quarter
KEY_WINDOW = 1 << 20
# a block of this many bytes of the dump is left out of the search for keys if its bytes are uniformly distributed (the entropy is at
# most this many bits, plus what the size of a random sample explains, below the 8 of random bytes): compressed or encrypted data
RANDOM_BLOCK_SIZE = 1 << 16
RANDOM_ENTROPY_DEFICIT = 0.01
# numpy sorts and searches without the GIL: the work on a dump is split over this many threads at most, if the dump is at least
# MIN_PARALLEL_SIZE bytes (smaller ones are searched by the calling thread)
MAX_THREADS = 8
MIN_PARALLEL_SIZE = 1 << 20
# the constants of two searches of a binary of at least this many bytes are searched in one pass
MIN_SINGLE_SEARCH_SIZE = 1 << 22
# the keys of at least this many different values are searched by several threads (whatever the size of the dump)
MIN_PARALLEL_VALUES = 1 << 15
# the windows are searched together, and their keys checked one by one afterwards, until they hold this many different values (see
# SAMPLE_BITS) or this many values together; the search for keys is not linear in the number of values
KEY_GROUP_DIFFERENT = 1 << 21
KEY_GROUP_VALUES = 1 << 25
# the number of different values of windows is estimated from the values of which a hash has this many zero bits on top
SAMPLE_BITS = 5
# hits of a keyed hash are a region if each one is at most this many bytes behind the previous one
KEYED_REGION_GAP = 4096

# hits of one algorithm are a region if each one is at most this many bytes behind the previous one
REGION_GAP = 128
# fewest distinct constants of one algorithm in a region, whatever the size of the dump
MIN_REGION_HITS = 3
# regions that chance may form in a dump of the given size at most (expected number), more hits are demanded above
MAX_CHANCE_REGIONS = 0.01
# a constant found more often than this in a dump is a pattern of filler data, not an API hash
MAX_CONSTANT_REPEATS = 256
# export names shorter than this are not searched as strings, they are too often ordinary words (send, free, Sleep)
DEFAULT_MIN_STRING_LENGTH = 6
# a string counts when it is in a run of at least this many different names of the same encoding ...
MIN_STRING_RUN = 3
# ... of which each one starts at most this many bytes after the end of the previous one (with its terminator)
STRING_RUN_GAP = 64
# number of 32bit values compared at once, bounds the memory use of the search to some 100 MB
SEARCH_CHUNK_SIZE = 1 << 22
# the part of such a chunk that is compared by one task of a thread, small enough for the table of constants to stay in the cache
SEARCH_PIECE_SIZE = 1 << 18
# the number of printable units before a NUL that are looked at for the whole chunk of a string search at once, at most
MAX_STRING_PREFILTER = 3

_MASK = 0xFFFFFFFF
_DLL_SUFFIX = re.compile(r"_0x[0-9a-fA-F]+$")


@functools.cache
def _getThreads():
    try:
        cpus = len(os.sched_getaffinity(0))
    except AttributeError:  # pragma: no cover - not on every platform
        cpus = os.cpu_count() or 1
    return max(1, min(cpus, MAX_THREADS))


@functools.cache
def _getPool():
    return concurrent.futures.ThreadPoolExecutor(_getThreads(), thread_name_prefix="apiscout")


if hasattr(os, "register_at_fork"):
    # a forked child has none of the threads of the pool it inherits, a full pool would never start new ones and every
    # _map() of the child would wait for them forever: the child starts a pool of its own, for the CPUs it may use
    def _resetPoolInChild():
        _getThreads.cache_clear()
        _getPool.cache_clear()

    os.register_at_fork(after_in_child=_resetPoolInChild)


def _map(function, items, parallel=True):
    """the results of the function for the items in order, computed by the threads of a pool if parallel; the function must not call
    _map() itself, its threads would wait for each other"""
    items = list(items)
    if not parallel or len(items) < 2 or _getThreads() < 2:
        return [function(item) for item in items]
    return list(_getPool().map(function, items))


class DynamicApi(NamedTuple):
    """an API found by one of its hashes (kind "hash", algorithm one of HASH_ALGORITHMS, value the constant; with a key of the sample
    it is the algorithm, ^ for XOR or + for ADD, and the key, e.g. "sdbm^0x1e5c48de") or by its name (kind "string", algorithm "ascii"
    or "utf16le"). offset is the position in the dump; dlls are all DLLs of the API DB that export the name (the one that was hashed,
    for block_api)."""

    offset: int
    kind: str
    algorithm: str
    value: int | None
    api: str
    dlls: tuple[str, ...]


def hashRor13(name):
    """ROR13 of the bytes of a name: rotate right by 13, then add the byte"""
    value = 0
    for char in name:
        value = (((value >> 13) | (value << 19)) & _MASK) + char & _MASK
    return value


def _hashModule(module):
    """ROR13 of the upper case UTF-16LE name of a module including its terminator"""
    return hashRor13(module.upper().encode("utf-16-le") + b"\x00\x00")


def hashBlockApi(module, name):
    """the hash of Metasploit's block_api for a module name and an API name"""
    return hashRor13(name + b"\x00") + _hashModule(module) & _MASK


def hashCrc32(name):
    return zlib.crc32(name)


def hashDjb2(name):
    value = 5381
    for char in name:
        value = (value * 33 + char) & _MASK
    return value


def hashFnv1a(name):
    value = 0x811C9DC5
    for char in name:
        value = ((value ^ char) * 0x01000193) & _MASK
    return value


def hashSdbm(name):
    """hash * 65599 + c from 0 (65599 is 2**6 + 2**16 - 1, the shifts of the sdbm function)"""
    value = 0
    for char in name:
        value = (value * 65599 + char) & _MASK
    return value


HASH_FUNCTIONS = {"ror13": hashRor13, "crc32": hashCrc32, "djb2": hashDjb2, "fnv1a": hashFnv1a, "sdbm": hashSdbm}


def getKeyedLabel(algorithm, mode, key):
    return f"{algorithm}{KEY_SYMBOLS[mode]}0x{key:08x}"


def getMinimumHits(num_hashes, size, gap=REGION_GAP, floor=MIN_REGION_HITS, budget=MAX_CHANCE_REGIONS):
    """the fewest hits of one algorithm that make a region in a dump of the given size

    A hit at a given offset happens by chance with probability p = num_hashes / 2**32, and the next one follows within gap bytes with
    probability p * gap. So a dump of this size holds fewer than size * p * (p * gap) ** (hits - 1) regions of that many hits by chance."""
    probability = num_hashes / 2**32
    hits = floor
    while hits < 64 and size * probability * (probability * gap) ** (hits - 1) > budget:
        hits += 1
    return hits


def getMinimumKeyApis(num_values, trials=1, num_probes=NUM_PROBE_APIS, floor=MIN_KEY_APIS, budget=MAX_CHANCE_KEYS):
    """the fewest different probe APIs that make a key, when num_values different values are searched in each of trials searches

    A probe hash plus key (or xor key) is one of the num_values values by chance with probability q = num_values / 2**32, so a given
    key is made by at least that many of the num_probes probes with probability tail(q), and of the 2**32 keys there are
    trials * 2**32 * tail(q) by chance. More than num_probes is returned if even all probes would not do."""
    probability = num_values / 2**32
    needed = floor
    while needed <= num_probes:
        tail = sum(
            math.comb(num_probes, hits) * probability**hits * (1 - probability) ** (num_probes - hits)
            for hits in range(needed, num_probes + 1)
        )
        if trials * 2**32 * tail <= budget:
            break
        needed += 1
    return needed


def getExpectedChanceHits(num_hashes, size):
    """expected number of offsets of a dump of this size that equal one of num_hashes distinct 32bit constants by chance"""
    return size * num_hashes / 2**32


def _hashNames(flat, lengths):
    """the hashes of ror13, djb2, fnv1a and sdbm of byte strings, as {algorithm: array of uint32 in the order of the strings}; the
    strings follow each other in flat (bytes) and have the given lengths (array). One numpy operation per character position
    instead of one Python operation per character."""
    count = len(lengths)
    values = {
        "ror13": np.zeros(count, dtype=np.uint32),
        "djb2": np.full(count, 5381, dtype=np.uint32),
        "fnv1a": np.full(count, 0x811C9DC5, dtype=np.uint32),
        "sdbm": np.zeros(count, dtype=np.uint32),
    }
    if not count:
        return values
    data = np.frombuffer(flat, dtype=np.uint8)
    starts = np.cumsum(lengths) - lengths
    # longest strings first, so that the strings that reach a position are the first ones
    order = np.argsort(-lengths, kind="stable")
    starts, lengths = starts[order], lengths[order]
    reaching = np.searchsorted(-lengths, -np.arange(int(lengths[0])), side="left")
    ror13, djb2, fnv1a, sdbm = values["ror13"], values["djb2"], values["fnv1a"], values["sdbm"]
    for position, active in enumerate(reaching.tolist()):
        chars = data[starts[:active] + position].astype(np.uint32)
        rotated = ror13[:active]
        ror13[:active] = ((rotated >> 13) | (rotated << 19)) + chars
        djb2[:active] = djb2[:active] * np.uint32(33) + chars
        fnv1a[:active] = (fnv1a[:active] ^ chars) * np.uint32(0x01000193)
        sdbm[:active] = sdbm[:active] * np.uint32(65599) + chars
    for algorithm, hashes in values.items():
        in_order = np.empty(count, dtype=np.uint32)
        in_order[order] = hashes
        values[algorithm] = in_order
    return values


def _hashModules(modules):
    """_hashModule() of the module names (a list), as an array of uint32"""
    encoded = [module.upper().encode("utf-16-le") + b"\x00\x00" for module in modules]
    lengths = np.fromiter(map(len, encoded), dtype=np.int64, count=len(encoded))
    return _hashNames(b"".join(encoded), lengths)["ror13"]


class _HashTable(NamedTuple):
    """the hashes of one algorithm in ascending order, and for each of them its entry: a name, for block_api a name of a module"""

    hashes: np.ndarray
    entries: np.ndarray
    modules: np.ndarray | None


class ApiNameIndex:
    """the export names of an API DB, and their hashes, which are computed once when asked for"""

    def __init__(self, exports):
        """exports: (DLL, API name, ...) of every export of an API DB; the load address behind a DLL name is dropped"""
        dlls_by_name = {}
        forms = {}
        for entry in exports:
            name = entry[1]
            # exports by ordinal only are named None<ordinal> in the map, they have no name that could be hashed
            if not name or name.startswith("None<") or not name.isascii():
                continue
            # (lower case, name of the DLL) for each of the DLLs of the entries, of which there are far fewer than of entries
            form = forms.get(entry[0])
            if form is None:
                dll = _DLL_SUFFIX.sub("", entry[0])
                form = forms[entry[0]] = (dll.lower(), dll)
            dlls = dlls_by_name.get(name)
            if dlls is None:
                dlls_by_name[name] = {form[0]: form[1]}
            else:
                dlls.setdefault(*form)
        self.names = sorted(dlls_by_name)
        self.dlls = [
            tuple(dlls.values()) if len(dlls) == 1 else tuple(sorted(dlls.values(), key=str.lower))
            for dlls in map(dlls_by_name.__getitem__, self.names)
        ]
        self.max_name_length = max(map(len, self.names), default=0)
        self._tables = {}
        self._num_hashes = {}
        self._long_names = {}
        self._hashes = None

    def getTable(self, algorithm):
        if algorithm not in self._tables:
            self._tables[algorithm] = self._buildTable(algorithm)
        return self._tables[algorithm]

    def getKeyedTable(self, algorithm, mode, key):
        """the table of an algorithm with every hash combined with a key (mode "xor" or "add"); the unchanged table without a mode"""
        table = self.getTable(algorithm)
        if mode is None:
            return table
        hashes = table.hashes ^ np.uint32(key) if mode == "xor" else table.hashes + np.uint32(key)
        return self._sortTable(hashes, table.entries, table.modules)

    def getNumHashes(self, algorithm):
        """number of distinct hashes of an algorithm"""
        if algorithm not in self._num_hashes:
            hashes = self.getTable(algorithm).hashes
            self._num_hashes[algorithm] = int(np.count_nonzero(hashes[1:] != hashes[:-1])) + 1 if len(hashes) else 0
        return self._num_hashes[algorithm]

    def getNamesWithMinLength(self, min_length):
        """{name: DLLs} of the names with at least min_length characters"""
        if min_length not in self._long_names:
            self._long_names[min_length] = {
                name: dlls for name, dlls in zip(self.names, self.dlls, strict=True) if len(name) >= min_length
            }
        return self._long_names[min_length]

    def resolve(self, algorithm, row, table=None):
        """the API name and DLLs of a row of the table of an algorithm (the table of getKeyedTable(), if it is given)"""
        return self.resolveRows(algorithm, range(row, row + 1), table)[0]

    def resolveRows(self, algorithm, rows, table=None):
        """the API names and DLLs of the rows (a range) of the table of an algorithm (the table of getKeyedTable(), if it is given)"""
        table = table or self.getTable(algorithm)
        entries = table.entries[rows.start : rows.stop].tolist()
        if table.modules is None:
            return [(self.names[entry], self.dlls[entry]) for entry in entries]
        modules = table.modules[rows.start : rows.stop].tolist()
        return [
            (self.names[entry], (self.dlls[entry][module],)) for entry, module in zip(entries, modules, strict=True)
        ]

    def _getHashes(self):
        """ror13, djb2, fnv1a and sdbm of all names"""
        if self._hashes is None:
            lengths = np.fromiter(map(len, self.names), dtype=np.int64, count=len(self.names))
            self._hashes = _hashNames("".join(self.names).encode("ascii"), lengths)
        return self._hashes

    def _buildTable(self, algorithm):
        modules = None
        if algorithm == "crc32":
            names = (name.encode("ascii") for name in self.names)
            hashes = np.fromiter(map(zlib.crc32, names), dtype=np.uint32, count=len(self.names))
        elif algorithm in ("ror13", "djb2", "fnv1a", "sdbm"):
            hashes = self._getHashes()[algorithm]
        elif algorithm == "block_api":
            # the terminator of the name is one more rotation by 13, adding 0
            ror13 = self._getHashes()["ror13"]
            name_hashes = (ror13 >> 13) | (ror13 << 19)
            counts = np.fromiter(map(len, self.dlls), dtype=np.int64, count=len(self.names))
            entries = np.repeat(np.arange(len(self.names), dtype=np.int64), counts)
            modules = np.arange(len(entries), dtype=np.int64) - np.repeat(np.cumsum(counts) - counts, counts)
            dlls = list(itertools.chain.from_iterable(self.dlls))
            different = list(dict.fromkeys(dlls))
            module_hashes = dict(zip(different, _hashModules(different).tolist(), strict=True))
            added = np.fromiter(map(module_hashes.__getitem__, dlls), dtype=np.uint32, count=len(entries))
            return self._sortTable(name_hashes[entries] + added, entries, modules)
        else:
            raise ValueError(f"Unknown hash algorithm: {algorithm}")
        return self._sortTable(hashes, np.arange(len(self.names), dtype=np.int64), modules)

    @staticmethod
    def _sortTable(hashes, entries, modules):
        # the order of the rows with equal hashes is that of the rows given: a stable argsort, here faster as a sort of the hashes
        # with their positions below them
        packed = (hashes.astype(np.uint64) << np.uint64(32)) | np.arange(len(hashes), dtype=np.uint64)
        packed.sort()
        order = (packed & np.uint64(_MASK)).astype(np.int64)
        return _HashTable(
            (packed >> np.uint64(32)).astype(np.uint32), entries[order], None if modules is None else modules[order]
        )


class _ConstantSet:
    """32bit constants that are searched together, with a table that rules out most other values with one lookup"""

    def __init__(self, values):
        self.values = _getDifferent(np.array(values, dtype=np.uint32))
        # about 30 bits of table for every constant keep the share of values that need a closer look at some 3%
        bits = min(26, max(16, len(self.values).bit_length() + 5))
        self.mask = np.uint32((1 << bits) - 1)
        self.table = np.zeros(1 << bits, dtype=np.bool_)
        self.table[self.values & self.mask] = True

    def select(self, offsets, values):
        """the offsets and values (as found by find() of a set that has more constants) of the hits that are one of the constants"""
        if not len(self.values):
            return offsets[:0], values[:0]
        member = self.values[np.minimum(np.searchsorted(self.values, values), len(self.values) - 1)] == values
        return offsets[member], values[member]

    def find(self, binary, chunk_size=None, parallel=False):
        """offsets (ascending) and values of all DWORDs of the binary at any offset that are one of the constants; parallel: by several
        threads"""
        chunk_size = chunk_size or SEARCH_CHUNK_SIZE
        if not len(self.values):
            return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.uint32)
        piece_size = min(chunk_size, SEARCH_PIECE_SIZE)
        # (alignment, first DWORD, number of DWORDs) of the chunks, and of the pieces of them that are compared by one task
        chunks = []
        for alignment in range(4):
            count = (len(binary) - alignment) // 4
            chunks.extend(
                (alignment, start, min(chunk_size, count - start)) for start in range(0, max(count, 0), chunk_size)
            )
        pieces = [
            (alignment, first, min(piece_size, start + size - first))
            for alignment, start, size in chunks
            for first in range(start, start + size, piece_size)
        ]
        found_in_pieces = iter(_map(lambda piece: self._findInPiece(binary, *piece), pieces, parallel))
        offsets, found = [], []
        flood = set()
        for alignment, _, size in chunks:
            parts = [next(found_in_pieces) for _ in range(-(-size // piece_size))]
            indices = np.concatenate([part[0] for part in parts])
            candidates = np.concatenate([part[1] for part in parts])
            if not len(indices):
                continue
            # a constant that is found too often in a chunk is dropped from it and the chunks after it
            if len(candidates) > MAX_CONSTANT_REPEATS:
                flood.update(_getRepeated(candidates).tolist())
            if flood and len(candidates):
                keep = ~np.isin(candidates, np.fromiter(flood, dtype=np.uint32, count=len(flood)))
                indices, candidates = indices[keep], candidates[keep]
            offsets.append(alignment + indices * 4)
            found.append(candidates)
        if not offsets:
            return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.uint32)
        offsets, found = np.concatenate(offsets), np.concatenate(found)
        # a pattern that was repeated often only over several chunks
        flood = _getRepeated(found)
        if len(flood):
            keep = ~np.isin(found, flood)
            offsets, found = offsets[keep], found[keep]
        order = np.argsort(offsets, kind="stable")
        return offsets[order], found[order]

    def _findInPiece(self, binary, alignment, first, count):
        """the indices (in DWORDs of that alignment) and the values of the constants in count DWORDs from the first one on"""
        words = np.frombuffer(binary, dtype="<u4", count=count, offset=alignment + first * 4)
        indices = np.flatnonzero(self.table[words & self.mask])
        candidates = words[indices]
        positions = np.minimum(np.searchsorted(self.values, candidates), len(self.values) - 1)
        member = self.values[positions] == candidates
        return first + indices[member], candidates[member]


def _getRepeated(values):
    unique, counts = np.unique(values, return_counts=True)
    return unique[counts > MAX_CONSTANT_REPEATS]


def getRegions(hits, min_hits, gap=REGION_GAP):
    """the hits ((offset, value) in ascending order of the offsets) that are in a chain of at least min_hits distinct values, in which
    each hit is at most gap bytes behind the previous one; a hit that overlaps the previous one is skipped, constants do not overlap"""
    offsets = np.array([offset for offset, _ in hits], dtype=np.int64)
    values = np.array([value for _, value in hits], dtype=np.int64)
    return [hits[index] for index in _getRegionIndices(offsets, values, min_hits, gap).tolist()]


def _getRegionIndices(offsets, values, min_hits, gap=REGION_GAP):
    """the indices of the hits that getRegions() keeps, for the arrays of the offsets (ascending) and values of the hits; the
    search for hashes finds its regions with this"""
    indices = np.arange(len(offsets))
    if len(offsets) > 1 and (np.diff(offsets) < 4).any():
        # hits that overlap the previous hit are skipped
        kept, last = [], None
        for index, offset in enumerate(offsets.tolist()):
            if last is None or offset >= last + 4:
                kept.append(index)
                last = offset
        indices = np.array(kept, dtype=np.int64)
        offsets, values = offsets[indices], values[indices]
    if len(offsets) < min_hits:
        return indices[:0]
    starts = np.concatenate(([0], np.flatnonzero(np.diff(offsets) > gap) + 1))
    ends = np.concatenate((starts[1:], [len(offsets)]))
    # chains that are shorter than min_hits cannot have that many distinct values
    chains = np.flatnonzero(ends - starts >= min_hits)
    kept = [
        indices[starts[chain] : ends[chain]]
        for chain in chains.tolist()
        if len(set(values[starts[chain] : ends[chain]].tolist())) >= min_hits
    ]
    return np.concatenate(kept) if kept else indices[:0]


def getStringRuns(strings, unit_size, min_run=MIN_STRING_RUN, gap=STRING_RUN_GAP):
    """the strings ((offset, name) in ascending order of the offsets, of one encoding) that are in a run of at least min_run different
    names, each starting at most gap bytes behind the end of the previous one, including its terminator. Lists of names, like the
    names to resolve with GetProcAddress or an import name table, come in runs; an isolated word that is an export name does not."""
    kept = []
    run = []
    end = None

    def close():
        if len({name for _, name in run}) >= min_run:
            kept.extend(run)
        run.clear()

    for offset, name in strings:
        if run and offset - end > gap:
            close()
        run.append((offset, name))
        end = max(end or 0, offset + (len(name) + 1) * unit_size)
    close()
    return kept


def _findStrings(binary, names, unit_size, min_length, max_length, chunk_size=None, parallel=False):
    """(offset, name) of the strings in the binary that are a name of the dict, terminated by a NUL and not preceded by a printable
    character; ASCII for unit_size 1 and UTF-16LE (with the ASCII characters only) for 2, found at any offset"""
    chunk_size = chunk_size or SEARCH_CHUNK_SIZE
    chunks = []
    for alignment in range(unit_size):
        count = (len(binary) - alignment) // unit_size
        chunks.extend(
            (alignment, start, min(start + chunk_size, count)) for start in range(0, max(count, 0), chunk_size)
        )
    found = _map(
        lambda chunk: _findStringsInChunk(binary, names, unit_size, min_length, max_length, *chunk), chunks, parallel
    )
    return sorted(itertools.chain.from_iterable(found))


def _findStringsInChunk(binary, names, unit_size, min_length, max_length, alignment, start, end):
    """(offset, name) of the strings that end in the units from start to end of the binary, in units of unit_size bytes from
    alignment on"""
    dtype = np.dtype("u1") if unit_size == 1 else np.dtype("<u2")
    found = []
    # the units before the chunk are read as well, to see where a string that ends in the chunk begins
    first = max(0, start - (max_length + 2))
    units = np.frombuffer(binary, dtype=dtype, count=end - first, offset=alignment + first * unit_size)
    # a string ends at a NUL behind at least min_length printable characters, of which these are looked at first (for all units
    # of the chunk at once, which is cheaper than for the NULs); the first units of the binary have fewer before them
    depth = max(1, min(min_length, MAX_STRING_PREFILTER))
    begin = max(start - first, depth)
    is_printable = _isPrintable(units)
    behind = is_printable[begin - 1 : -1].copy()
    for distance in range(2, depth + 1):
        behind &= is_printable[begin - distance : max(len(units) - distance, 0)]
    nuls = np.flatnonzero((units[begin:] == 0) & behind) + begin
    length = depth
    while len(nuls) and length <= max_length:
        before = nuls - (length + 1)
        # the units that were read before the chunk are enough to see where any string of it starts, but at the start of the binary
        printable = _isPrintable(units[before]) if first else (before >= 0) & _isPrintable(units[np.maximum(before, 0)])
        # the string starts here (at the start of what was read, if it is the start of the binary)
        complete = ~printable
        if length >= min_length:
            for nul in nuls[complete].tolist():
                offset = alignment + (first + nul - length) * unit_size
                text = bytes(binary[offset : offset + length * unit_size])
                name = (text if unit_size == 1 else text[::2]).decode("ascii")
                if name in names:
                    found.append((offset, name))
        nuls = nuls[printable]
        length += 1
    return found


def _isPrintable(units):
    # (a unit below 0x20 wraps around to a large number)
    return (units - units.dtype.type(0x20)) <= units.dtype.type(0x5E)


@functools.cache
def _getProbeHashes(algorithm):
    """the different hashes of PROBE_APIS of an algorithm, and those of the first KEY_ANCHORS ones, as numpy arrays"""
    hashes = list(dict.fromkeys(HASH_FUNCTIONS[algorithm](name.encode("ascii")) for name in PROBE_APIS))
    return np.array(sorted(hashes), dtype=np.uint32), np.array(hashes[:KEY_ANCHORS], dtype=np.uint32)


def _getKeyWindows(size, window):
    """(start, end) of the windows over a dump of the given size, each one overlapping the previous one by a quarter"""
    if size <= window:
        return [(0, size)]
    starts = list(range(0, size - window + 1, window * 3 // 4))
    if starts[-1] + window < size:
        starts.append(size - window)
    return [(start, start + window) for start in starts]


def _isRandom(binary, start, end):
    """whether the bytes are uniformly distributed, as in compressed or encrypted data; there is nothing to find in it, no table of
    hashes can be told from the rest. Less than a block of bytes is never random, the entropy of a sample of random bytes is lower."""
    size = end - start
    if size < RANDOM_BLOCK_SIZE:
        return False
    data = np.frombuffer(binary, dtype=np.uint8, count=size, offset=start)
    limit = RANDOM_ENTROPY_DEFICIT + 255 / (2 * size * math.log(2))
    # the most entropy that bytes with this many zeros can have is when all other values are equally frequent: no histogram is
    # needed to tell that a block with many zeros (code, data, text) is not random
    zero_share = np.count_nonzero(data == 0) / size
    if 0 < zero_share < 1:
        most = -zero_share * math.log2(zero_share) - (1 - zero_share) * math.log2((1 - zero_share) / 255)
        if 8 - most > limit + 1e-9:
            return False
    # (the histogram is made by a radix sort, which does not hold the GIL like np.bincount does)
    counts = np.diff(np.searchsorted(np.sort(data, kind="stable"), np.arange(257)))
    probabilities = counts[counts > 0] / size
    entropy = -(probabilities * np.log2(probabilities)).sum()
    return bool(8 - entropy <= limit)


def _getRandomBlocks(binary, parallel=False):
    """for every block of RANDOM_BLOCK_SIZE bytes of the dump (the last one is smaller) whether its bytes are uniformly distributed"""
    starts = range(0, len(binary), RANDOM_BLOCK_SIZE)
    # many blocks per task
    groups = [starts[first : first + 16] for first in range(0, len(starts), 16)]
    return [
        random
        for group in _map(
            lambda starts: [_isRandom(binary, start, min(start + RANDOM_BLOCK_SIZE, len(binary))) for start in starts],
            groups,
            parallel,
        )
        for random in group
    ]


def _getSpans(start, end, random_blocks):
    """(start, end) of the parts of a window that are not in a random block"""
    if random_blocks is None:
        return [(start, end)]
    spans = []
    for block in range(start // RANDOM_BLOCK_SIZE, (end - 1) // RANDOM_BLOCK_SIZE + 1):
        if not random_blocks[block]:
            first, last = max(start, block * RANDOM_BLOCK_SIZE), min(end, (block + 1) * RANDOM_BLOCK_SIZE)
            if spans and spans[-1][1] == first:
                spans[-1] = (spans[-1][0], last)
            else:
                spans.append((first, last))
    return spans


def _getKeyCandidates(binary, start, end, random_blocks=None):
    """the different 32bit values (at any offset) of a window, in ascending order, without those that have a zero byte and those in
    random blocks (see _getRandomBlocks)"""
    values = []
    for first, last in _getSpans(start, end, random_blocks):
        if last - first < 4:
            continue
        data = np.frombuffer(binary, dtype=np.uint8, count=last - first, offset=first)
        # the values at all offsets in one view, those without a zero byte are selected by the bytes of the span
        zero = data == 0
        without_zero = ~(zero[:-3] | zero[1:-2] | zero[2:-1] | zero[3:])
        words = np.ndarray(shape=(len(data) - 3,), dtype="<u4", buffer=binary, offset=first, strides=(1,))
        values.append(words[without_zero])
    if not values:
        return np.zeros(0, dtype=np.uint32)
    return _getDifferent(values[0] if len(values) == 1 else np.concatenate(values))


def _getDifferent(values):
    """the different values in ascending order (a sort and a comparison, np.unique is slower); the array is sorted in place"""
    values.sort()
    if len(values) > 1:
        different = np.empty(len(values), dtype=np.bool_)
        different[0] = True
        np.not_equal(values[1:], values[:-1], out=different[1:])
        values = values[different]
    return values


def _getLookup(values):
    """a table that rules out most 32bit values that are not one of the values with one lookup (as _ConstantSet does)"""
    bits = min(24, max(16, len(values).bit_length() + 3))
    mask = np.uint32((1 << bits) - 1)
    table = np.zeros(1 << bits, dtype=np.bool_)
    table[values & mask] = True
    return table, mask


def _findKeysInWindow(values, algorithm, mode, min_apis, lookup=None, buffer=None):
    """the keys of one mode and algorithm that at least min_apis different probe APIs agree on in the sorted different values"""
    probes, anchors = _getProbeHashes(algorithm)
    combine = np.bitwise_xor if mode == "xor" else np.subtract
    # the buffer of a window is used for all algorithms and modes
    if buffer is None:
        buffer = np.empty(len(values) * len(anchors), dtype=np.uint32)
    proposed = buffer[: len(values) * len(anchors)]
    for index, anchor in enumerate(anchors):
        combine(values, anchor, out=proposed[index * len(values) : (index + 1) * len(values)])
    proposed.sort()
    # at least KEY_ANCHOR_HITS (two) different anchors agree on a key: it is there more than once (different anchors always give
    # different keys for the same value, and different values always different keys for the same anchor)
    agreed = proposed[KEY_ANCHOR_HITS - 1 :] == proposed[: len(proposed) - KEY_ANCHOR_HITS + 1]
    candidates = _getDifferent(proposed[: len(proposed) - KEY_ANCHOR_HITS + 1][agreed])
    # the key 0 means the hashes themselves, which are searched anyway
    candidates = candidates[candidates != 0]
    if not len(candidates):
        return []
    wanted = (combine if mode == "xor" else np.add).outer(candidates, probes).ravel()
    table, mask = lookup or _getLookup(values)
    # the wanted values that may be one of the values are looked up, the others are not
    maybe = np.flatnonzero(table[wanted & mask])
    present = wanted[maybe]
    present = values[np.minimum(np.searchsorted(values, present), len(values) - 1)] == present
    found = np.bincount(maybe[present] // len(probes), minlength=len(candidates))
    return candidates[found >= min_apis].tolist()


def _confirmKeys(values, algorithm, mode, keys, min_apis):
    """the keys of one mode and algorithm (of those that are keys in a superset of the sorted different values) that two anchors and
    at least min_apis different probe APIs agree on in the values; the same keys as _findKeysInWindow() finds in them"""
    probes, anchors = _getProbeHashes(algorithm)
    combine = np.bitwise_xor if mode == "xor" else np.add
    keys = np.array(keys, dtype=np.uint32)

    def count(hashes):
        wanted = combine.outer(keys, hashes)
        present = values[np.minimum(np.searchsorted(values, wanted), len(values) - 1)] == wanted
        return present.sum(axis=1)

    return keys[(count(anchors) >= KEY_ANCHOR_HITS) & (count(probes) >= min_apis)].tolist()


def _getSample(values):
    """a part of the different values that is about 1 / SAMPLE_RATIO of them, the same for the same values in every window"""
    return values[(values * np.uint32(2654435761)) >> np.uint32(32 - SAMPLE_BITS) == 0]


def _getUnion(sets, parallel):
    """the different values of several sorted arrays of different values, in ascending order; each part of the value range is sorted
    by a thread of its own"""
    if len(sets) == 1:
        return sets[0]
    parts = 2 * _getThreads() if parallel else 1
    # parts of about the same number of values, by the values of the largest set
    largest = sets[int(np.argmax([len(values) for values in sets]))]
    splitters = largest[np.linspace(0, len(largest) - 1, parts + 1)[1:-1].astype(np.int64)]
    cuts = [np.concatenate(([0], np.searchsorted(values, splitters), [len(values)])) for values in sets]
    return np.concatenate(
        _map(
            lambda part: _getDifferent(
                np.concatenate([values[cut[part] : cut[part + 1]] for values, cut in zip(sets, cuts, strict=True)])
            ),
            range(parts),
            parallel,
        )
    )


def _findKeysInGroup(window_values, min_apis, trials, variants, parallel):
    """the keys, as {(algorithm, mode): set of keys}, that the probe APIs agree on in at least one of the windows, whose different
    values (ascending) are given, for a number of trials of searches (see getMinimumKeyApis())

    The keys are looked for in the different values of all windows together first, which is a superset of those of each window; many
    windows of a dump hold the same values, so there are much fewer of them than of all windows. The few keys that it finds are checked
    for each window."""
    if parallel is None:
        parallel = sum(map(len, window_values)) >= MIN_PARALLEL_VALUES
    needed = [min_apis or getMinimumKeyApis(len(values), trials) for values in window_values]
    live = [index for index, values in enumerate(window_values) if needed[index] <= NUM_PROBE_APIS and len(values)]
    found = {}
    if not live:
        return found
    together = _getUnion([window_values[index] for index in live], parallel)
    fewest = min(needed[index] for index in live)
    lookup = _getLookup(together)

    def findKeysInValues(variant):
        buffer = np.empty(len(together) * KEY_ANCHORS, dtype=np.uint32)
        return _findKeysInWindow(together, *variant, fewest, lookup, buffer)

    for variant, keys in zip(variants, _map(findKeysInValues, variants, parallel), strict=True):
        if keys and len(live) > 1:
            keys = [key for index in live for key in _confirmKeys(window_values[index], *variant, keys, needed[index])]
        if keys:
            found.setdefault(variant, set()).update(keys)
    return found


def findKeys(binary, algorithms=None, min_apis=None, window=None, skip_random=True, parallel=None):
    """the keys that a program combines with the hashes of an algorithm, as {(algorithm, mode): [keys]}, mode "xor" (the value is
    hash ^ key) or "add" (hash + key)

    A key is found if at least min_apis (default: getMinimumKeyApis()) different PROBE_APIS have their value hash ^ key (hash + key) in
    the same window of the dump, see the module description. algorithms: of KEYED_ALGORITHMS, by default all. window: size of the
    windows in bytes (default: KEY_WINDOW). skip_random: leave out blocks of uniformly distributed bytes. parallel: by several threads (by
    default, the windows if the dump has at least MIN_PARALLEL_SIZE bytes, the many values of windows)."""
    algorithms = tuple(algorithm for algorithm in KEYED_ALGORITHMS if algorithms is None or algorithm in algorithms)
    found = {}
    if not algorithms or len(binary) < 4:
        return found
    windows = _getKeyWindows(len(binary), window or KEY_WINDOW)
    variants = [(algorithm, mode) for algorithm in algorithms for mode in KEY_MODES]
    trials = len(windows) * len(variants)
    # by default, the windows of a large dump and the many values of a window are searched by several threads
    parallel_windows = len(binary) >= MIN_PARALLEL_SIZE if parallel is None else parallel
    random_blocks = _getRandomBlocks(binary, parallel_windows) if skip_random else None

    def getValues(span):
        values = _getKeyCandidates(binary, *span, random_blocks)
        return values, _getSample(values)

    group, sample, size = [], np.zeros(0, dtype=np.uint32), 0

    def searchGroup(windows_values):
        for variant, keys in _findKeysInGroup(windows_values, min_apis, trials, variants, parallel).items():
            found.setdefault(variant, set()).update(keys)

    batch_size = 2 * _getThreads() if parallel_windows else 1
    for first in range(0, len(windows), batch_size):
        for values, part in _map(getValues, windows[first : first + batch_size], parallel_windows):
            joined = _getDifferent(np.concatenate((sample, part)))
            # the windows are searched together until they have many different values (as many as the sample suggests), or hold many
            # values: a window that would take the group over a limit starts the next group (the search for keys takes memory for
            # every different value, so the limits are checked for each window and not for each batch)
            if group and (size + len(values) > KEY_GROUP_VALUES or len(joined) << SAMPLE_BITS > KEY_GROUP_DIFFERENT):
                searchGroup(group)
                group, size, joined = [], 0, part
            group.append(values)
            size += len(values)
            sample = joined
    if group:
        searchGroup(group)
    return {variant: sorted(keys) for variant, keys in found.items()}


class DynamicApiFinder:
    """finds the APIs of API DBs by hashes and strings; the DBs are given as ApiNameIndex by the name of their API map"""

    def __init__(self, indexes):
        self.indexes = indexes
        self._constants = {}

    def _getConstants(self, algorithms):
        """all hashes of the algorithms and DBs as one set of constants"""
        key = tuple(algorithms)
        if key not in self._constants:
            self._constants[key] = _ConstantSet(
                np.concatenate(
                    [index.getTable(algorithm).hashes for index in self.indexes.values() for algorithm in key]
                )
                if self.indexes and key
                else np.zeros(0, dtype=np.uint32)
            )
        return self._constants[key]

    def findKeys(self, binary, algorithms=None, min_apis=None, window=None, skip_random=True):
        """the keys of the algorithms in the binary, see findKeys()"""
        return findKeys(binary, algorithms, min_apis, window, skip_random)

    def findHashes(self, binary, algorithms=None, min_hits=None, load_offset=0, keyed=True, min_key_apis=None):
        """APIs of which the hash is in the binary, in regions of hits that chance is unlikely to form, as {API map name: [DynamicApi]}

        min_hits: the fewest distinct constants of one algorithm in a region; given, it replaces the number that depends on the size of
        the binary and the number of hashes (getMinimumHits). keyed: also look for the hashes combined with a key that the binary holds
        (findKeys(), min_key_apis), in regions with a larger gap."""
        results = {name: [] for name in self.indexes}
        algorithms = tuple(
            algorithm
            for algorithm in HASH_ALGORITHMS
            if algorithm in (HASH_ALGORITHMS if algorithms is None else algorithms)
        )
        if not algorithms or not len(binary):
            return results
        parallel = len(binary) >= MIN_PARALLEL_SIZE
        constants = self._getConstants(algorithms)
        keyed_variants = []
        if keyed and self.indexes:
            keyed_variants = [
                (getKeyedLabel(algorithm, mode, key), algorithm, mode, key)
                for (algorithm, mode), keys in findKeys(binary, algorithms, min_key_apis).items()
                for key in keys
            ]
        keyed_constants = None
        # the tables of the keys of this call, which are made (combined with the key and sorted) once for the constants and the hits
        tables = {}

        def getTable(name, variant):
            entry = (name, *variant[1:])
            if entry not in tables:
                tables[entry] = self.indexes[name].getKeyedTable(*variant[1:])
            return tables[entry]

        if keyed_variants:
            # the hashes without a key of these algorithms take part, they may be the real ones
            keyed_variants += [
                (algorithm, algorithm, None, 0) for algorithm in dict.fromkeys(v[1] for v in keyed_variants)
            ]
            keyed_constants = _ConstantSet(
                np.concatenate([getTable(name, variant).hashes for name in self.indexes for variant in keyed_variants])
            )
        # the binary is searched once for the constants of both searches (if it is large: for a small one, the table of the constants
        # of both takes longer to build than a second search)
        if keyed_constants is not None and len(binary) >= MIN_SINGLE_SEARCH_SIZE:
            offsets, values = _ConstantSet(np.concatenate((constants.values, keyed_constants.values))).find(
                binary, parallel=parallel
            )
            hits = constants.select(offsets, values)
            keyed_hits = keyed_constants.select(offsets, values)
        else:
            hits = constants.find(binary, parallel=parallel)
            keyed_hits = keyed_constants.find(binary, parallel=parallel) if keyed_constants is not None else None
        # offsets of the hits that are reported so far, for each API map
        taken = {name: set() for name in self.indexes}
        variants = [(algorithm, algorithm, None, 0) for algorithm in algorithms]
        self._findHits(results, *hits, variants, binary, min_hits, REGION_GAP, load_offset, taken, getTable)
        if keyed_hits is not None:
            self._findHits(
                results,
                *keyed_hits,
                keyed_variants,
                binary,
                min_hits,
                KEYED_REGION_GAP,
                load_offset,
                taken,
                getTable,
                compete=True,
            )
        for found in results.values():
            found.sort(key=lambda hit: (hit.offset, hit.algorithm, hit.api))
        return results

    def _findHits(
        self, results, offsets, values, variants, binary, min_hits, gap, load_offset, taken, getTable, compete=False
    ):
        """adds the APIs of which the hashes (variants: (label, algorithm, mode, key)) are in regions of the binary to the results;
        offsets and values are the hits of the binary that are one of the hashes, getTable(API map name, variant) is the table of a
        variant (see ApiNameIndex.getKeyedTable)

        compete: a constant is the hash of one API, so the variants that have it take turns, the one with the most hits first, and a
        variant does not get the hits at the offsets that earlier variants, or the hashes searched before (taken), have. This is what
        happens to a key that is a real key combined with the difference of the hashes of two names: CRC-32 (XOR) and the hashes that
        add the last character (ADD) have the same difference for all names that end with A and W, so the two keys have many probe
        APIs and many hits in common; the real key has more of both. The hashes without a key, the variant without a mode, take
        part like the others but are not reported again, they were searched before (with the gap of unkeyed hashes)."""
        if not len(offsets):
            return
        for name, index in self.indexes.items():
            found = []
            for variant in variants:
                table = getTable(name, variant)
                if not len(table.hashes):
                    continue
                first = np.searchsorted(table.hashes, values, side="left")
                member = np.flatnonzero(table.hashes[np.minimum(first, len(table.hashes) - 1)] == values)
                if len(member):
                    found.append((variant, table, member, first[member]))
            if compete:
                found.sort(key=lambda entry: -len(entry[2]))
            for (label, algorithm, mode, _), table, member, first in found:
                hit_offsets, hit_values = offsets[member], values[member]
                if compete:
                    free = np.fromiter(
                        (offset not in taken[name] for offset in hit_offsets.tolist()), np.bool_, len(member)
                    )
                    hit_offsets, hit_values, first = hit_offsets[free], hit_values[free], first[free]
                # the hashes without key of a competition were reported before
                report = mode is not None or not compete
                needed = min_hits or getMinimumHits(index.getNumHashes(algorithm), len(binary), gap)
                regions = _getRegionIndices(hit_offsets, hit_values, needed, gap)
                if not len(regions):
                    continue
                taken[name].update(hit_offsets[regions].tolist())
                if report:
                    last = np.searchsorted(table.hashes, hit_values[regions], side="right")
                    for offset, value, rows in zip(
                        hit_offsets[regions].tolist(),
                        hit_values[regions].tolist(),
                        map(range, first[regions].tolist(), last.tolist()),
                        strict=True,
                    ):
                        for api, dlls in index.resolveRows(algorithm, rows, table):
                            results[name].append(DynamicApi(offset + load_offset, "hash", label, value, api, dlls))

    def findStrings(self, binary, min_length=None, load_offset=0, min_run=None, gap=STRING_RUN_GAP):
        """APIs of which the name is a string in the binary, in runs of at least min_run different names (see getStringRuns), as
        {API map name: [DynamicApi]}"""
        results = {}
        min_length = min_length or DEFAULT_MIN_STRING_LENGTH
        min_run = min_run or MIN_STRING_RUN
        for name, index in self.indexes.items():
            names = index.getNamesWithMinLength(min_length)
            hits = []
            if names and len(binary):
                for unit_size, encoding in ((1, "ascii"), (2, "utf16le")):
                    found = _findStrings(
                        binary,
                        names,
                        unit_size,
                        min_length,
                        index.max_name_length,
                        parallel=len(binary) >= MIN_PARALLEL_SIZE,
                    )
                    for offset, api in getStringRuns(found, unit_size, min_run, gap):
                        hits.append(DynamicApi(offset + load_offset, "string", encoding, None, api, names[api]))
            hits.sort(key=lambda hit: (hit.offset, hit.algorithm, hit.api))
            results[name] = hits
        return results
