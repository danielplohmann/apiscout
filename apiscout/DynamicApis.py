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
# the windows are searched by this many threads at most
MAX_KEY_THREADS = 8
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

_MASK = 0xFFFFFFFF
_DLL_SUFFIX = re.compile(r"_0x[0-9a-fA-F]+$")


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


def _stepRor13(values, chars):
    return ((values >> 13) | (values << 19)) + chars


def _stepDjb2(values, chars):
    return values * np.uint32(33) + chars


def _stepFnv1a(values, chars):
    return (values ^ chars) * np.uint32(0x01000193)


def _stepSdbm(values, chars):
    return values * np.uint32(65599) + chars


def _hashNames(names, step, initial):
    """hashes of byte strings with one numpy operation per character position instead of one Python operation per character"""
    count = len(names)
    values = np.full(count, initial, dtype=np.uint32)
    if not count:
        return values
    lengths = np.fromiter(map(len, names), dtype=np.int64, count=count)
    # longest names first, so that the names that reach a position are the first ones
    order = np.argsort(-lengths, kind="stable")
    lengths = lengths[order]
    flat = np.frombuffer(b"".join([names[i] for i in order]), dtype=np.uint8)
    starts = np.cumsum(lengths) - lengths
    for position in range(int(lengths[0])):
        active = int(np.searchsorted(-lengths, -position, side="left"))
        values[:active] = step(values[:active], flat[starts[:active] + position].astype(np.uint32))
    result = np.empty(count, dtype=np.uint32)
    result[order] = values
    return result


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
        for entry in exports:
            name = entry[1]
            # exports by ordinal only are named None<ordinal> in the map, they have no name that could be hashed
            if not name or name.startswith("None<") or not name.isascii():
                continue
            dlls = dlls_by_name.setdefault(name, {})
            dll = _DLL_SUFFIX.sub("", entry[0])
            dlls.setdefault(dll.lower(), dll)
        self.names = sorted(dlls_by_name)
        self.dlls = [tuple(sorted(dlls_by_name[name].values(), key=str.lower)) for name in self.names]
        self.max_name_length = max(map(len, self.names), default=0)
        self._tables = {}
        self._num_hashes = {}
        self._name_bytes = None
        self._ror13 = None

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
            self._num_hashes[algorithm] = len(np.unique(self.getTable(algorithm).hashes))
        return self._num_hashes[algorithm]

    def getNamesWithMinLength(self, min_length):
        return {name: dlls for name, dlls in zip(self.names, self.dlls, strict=True) if len(name) >= min_length}

    def resolve(self, algorithm, row, table=None):
        """the API name and DLLs of a row of the table of an algorithm (the table of getKeyedTable(), if it is given)"""
        table = table or self.getTable(algorithm)
        entry = int(table.entries[row])
        if table.modules is None:
            return self.names[entry], self.dlls[entry]
        return self.names[entry], (self.dlls[entry][int(table.modules[row])],)

    def _getNameBytes(self):
        if self._name_bytes is None:
            self._name_bytes = [name.encode("ascii") for name in self.names]
        return self._name_bytes

    def _getRor13(self):
        if self._ror13 is None:
            self._ror13 = _hashNames(self._getNameBytes(), _stepRor13, 0)
        return self._ror13

    def _buildTable(self, algorithm):
        modules = None
        if algorithm == "ror13":
            hashes = self._getRor13()
        elif algorithm == "crc32":
            hashes = np.fromiter(map(zlib.crc32, self._getNameBytes()), dtype=np.uint32, count=len(self.names))
        elif algorithm == "djb2":
            hashes = _hashNames(self._getNameBytes(), _stepDjb2, 5381)
        elif algorithm == "fnv1a":
            hashes = _hashNames(self._getNameBytes(), _stepFnv1a, 0x811C9DC5)
        elif algorithm == "sdbm":
            hashes = _hashNames(self._getNameBytes(), _stepSdbm, 0)
        elif algorithm == "block_api":
            # the terminator of the name is one more rotation by 13, adding 0
            ror13 = self._getRor13()
            name_hashes = (ror13 >> 13) | (ror13 << 19)
            counts = np.fromiter(map(len, self.dlls), dtype=np.int64, count=len(self.names))
            entries = np.repeat(np.arange(len(self.names), dtype=np.int64), counts)
            modules = np.fromiter(
                (index for dlls in self.dlls for index in range(len(dlls))), dtype=np.int64, count=len(entries)
            )
            module_hashes = {}
            for dlls in self.dlls:
                for dll in dlls:
                    if dll not in module_hashes:
                        module_hashes[dll] = _hashModule(dll)
            added = np.fromiter(
                (module_hashes[dll] for dlls in self.dlls for dll in dlls), dtype=np.uint32, count=len(entries)
            )
            return self._sortTable(name_hashes[entries] + added, entries, modules)
        else:
            raise ValueError(f"Unknown hash algorithm: {algorithm}")
        return self._sortTable(hashes, np.arange(len(self.names), dtype=np.int64), modules)

    @staticmethod
    def _sortTable(hashes, entries, modules):
        order = np.argsort(hashes, kind="stable")
        return _HashTable(hashes[order], entries[order], None if modules is None else modules[order])


class _ConstantSet:
    """32bit constants that are searched together, with a table that rules out most other values with one lookup"""

    def __init__(self, values):
        self.values = np.unique(values)
        # about 30 bits of table for every constant keep the share of values that need a closer look at some 3%
        bits = min(26, max(16, len(self.values).bit_length() + 5))
        self.mask = np.uint32((1 << bits) - 1)
        self.table = np.zeros(1 << bits, dtype=np.bool_)
        self.table[self.values & self.mask] = True

    def find(self, binary, chunk_size=None):
        """offsets (ascending) and values of all DWORDs of the binary at any offset that are one of the constants"""
        chunk_size = chunk_size or SEARCH_CHUNK_SIZE
        if not len(self.values):
            return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.uint32)
        offsets, found = [], []
        flood = set()
        for alignment in range(4):
            count = (len(binary) - alignment) // 4
            for start in range(0, max(count, 0), chunk_size):
                words = np.frombuffer(
                    binary, dtype="<u4", count=min(chunk_size, count - start), offset=alignment + start * 4
                )
                indices = np.flatnonzero(self.table[words & self.mask])
                if not len(indices):
                    continue
                candidates = words[indices]
                positions = np.minimum(np.searchsorted(self.values, candidates), len(self.values) - 1)
                member = self.values[positions] == candidates
                indices, candidates = indices[member], candidates[member]
                if len(candidates) > MAX_CONSTANT_REPEATS:
                    flood.update(_getRepeated(candidates).tolist())
                if flood and len(candidates):
                    keep = ~np.isin(candidates, np.fromiter(flood, dtype=np.uint32, count=len(flood)))
                    indices, candidates = indices[keep], candidates[keep]
                offsets.append(alignment + (start + indices) * 4)
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


def _getRepeated(values):
    unique, counts = np.unique(values, return_counts=True)
    return unique[counts > MAX_CONSTANT_REPEATS]


def getRegions(hits, min_hits, gap=REGION_GAP):
    """the hits ((offset, value) in ascending order of the offsets) that are in a chain of at least min_hits distinct values, in which
    each hit is at most gap bytes behind the previous one; a hit that overlaps the previous one is skipped, constants do not overlap"""
    regions = []
    chain = []

    def close():
        if len({value for _, value in chain}) >= min_hits:
            regions.extend(chain)
        chain.clear()

    for offset, value in hits:
        if chain:
            if offset < chain[-1][0] + 4:
                continue
            if offset - chain[-1][0] > gap:
                close()
        chain.append((offset, value))
    close()
    return regions


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


def _findStrings(binary, names, unit_size, min_length, max_length, chunk_size=None):
    """(offset, name) of the strings in the binary that are a name of the dict, terminated by a NUL and not preceded by a printable
    character; ASCII for unit_size 1 and UTF-16LE (with the ASCII characters only) for 2, found at any offset"""
    chunk_size = chunk_size or SEARCH_CHUNK_SIZE
    dtype = np.dtype("u1") if unit_size == 1 else np.dtype("<u2")
    found = []
    # the units before a chunk are read as well, to see where a string that ends in the chunk begins
    context = max_length + 2
    for alignment in range(unit_size):
        count = (len(binary) - alignment) // unit_size
        for start in range(0, max(count, 0), chunk_size):
            end = min(start + chunk_size, count)
            first = max(0, start - context)
            units = np.frombuffer(binary, dtype=dtype, count=end - first, offset=alignment + first * unit_size)
            # a string ends at a NUL behind a printable character
            nuls = np.flatnonzero(units[start - first :] == 0) + (start - first)
            nuls = nuls[nuls > 0]
            nuls = nuls[_isPrintable(units[nuls - 1])]
            length = 1
            while len(nuls) and length <= max_length:
                before = nuls - (length + 1)
                at_start = before < 0
                printable = ~at_start & _isPrintable(units[np.maximum(before, 0)])
                # the string starts here, unless it reaches the start of what was read and there is more before it
                complete = ~printable & (~at_start | (first == 0))
                if length >= min_length:
                    for nul in nuls[complete].tolist():
                        offset = alignment + (first + nul - length) * unit_size
                        text = bytes(binary[offset : offset + length * unit_size])
                        name = (text if unit_size == 1 else text[::2]).decode("ascii")
                        if name in names:
                            found.append((offset, name))
                nuls = nuls[printable]
                length += 1
    return sorted(found)


def _isPrintable(units):
    return (units >= 0x20) & (units <= 0x7E)


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
    counts = np.bincount(np.frombuffer(binary, dtype=np.uint8, count=size, offset=start), minlength=256)
    probabilities = counts[counts > 0] / size
    entropy = -(probabilities * np.log2(probabilities)).sum()
    return bool(8 - entropy <= RANDOM_ENTROPY_DEFICIT + 255 / (2 * size * math.log(2)))


def _getRandomBlocks(binary):
    """for every block of RANDOM_BLOCK_SIZE bytes of the dump (the last one is smaller) whether its bytes are uniformly distributed"""
    return [
        _isRandom(binary, start, min(start + RANDOM_BLOCK_SIZE, len(binary)))
        for start in range(0, len(binary), RANDOM_BLOCK_SIZE)
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
        for alignment in range(4):
            count = (last - first - alignment) // 4
            if count > 0:
                values.append(np.frombuffer(binary, dtype="<u4", count=count, offset=first + alignment))
    if not values:
        return np.zeros(0, dtype=np.uint32)
    values = np.concatenate(values)
    # a byte of a value is zero if the bit 7 is set in (value - 0x01010101) & ~value
    values = values[((values - np.uint32(0x01010101)) & ~values & np.uint32(0x80808080)) == 0]
    return _getDifferent(values)


def _getDifferent(values):
    """the different values in ascending order (a sort and a comparison, np.unique is slower)"""
    values = np.sort(values)
    if len(values) > 1:
        values = values[np.concatenate(([True], values[1:] != values[:-1]))]
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


def findKeys(binary, algorithms=None, min_apis=None, window=None, skip_random=True):
    """the keys that a program combines with the hashes of an algorithm, as {(algorithm, mode): [keys]}, mode "xor" (the value is
    hash ^ key) or "add" (hash + key)

    A key is found if at least min_apis (default: getMinimumKeyApis()) different PROBE_APIS have their value hash ^ key (hash + key) in
    the same window of the dump, see the module description. algorithms: of KEYED_ALGORITHMS, by default all. window: size of the
    windows in bytes (default: KEY_WINDOW). skip_random: leave out blocks of uniformly distributed bytes."""
    algorithms = tuple(algorithm for algorithm in KEYED_ALGORITHMS if algorithms is None or algorithm in algorithms)
    found = {}
    if not algorithms or len(binary) < 4:
        return found
    windows = _getKeyWindows(len(binary), window or KEY_WINDOW)
    trials = len(windows) * len(algorithms) * len(KEY_MODES)
    random_blocks = _getRandomBlocks(binary) if skip_random else None

    def findKeysInWindow(window):
        start, end = window
        values = _getKeyCandidates(binary, start, end, random_blocks)
        needed = min_apis or getMinimumKeyApis(len(values), trials)
        if needed > NUM_PROBE_APIS or not len(values):
            return []
        lookup = _getLookup(values)
        buffer = np.empty(len(values) * KEY_ANCHORS, dtype=np.uint32)
        return [
            ((algorithm, mode), key)
            for algorithm in algorithms
            for mode in KEY_MODES
            for key in _findKeysInWindow(values, algorithm, mode, needed, lookup, buffer)
        ]

    # the windows are independent, and numpy sorts and searches without the GIL
    workers = min(len(windows), os.cpu_count() or 1, MAX_KEY_THREADS)
    if workers > 1:
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            parts = list(pool.map(findKeysInWindow, windows))
    else:
        parts = [findKeysInWindow(window) for window in windows]
    for part in parts:
        for variant, key in part:
            found.setdefault(variant, set()).add(key)
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
        # offsets of the hits that are reported so far, for each API map
        taken = {name: set() for name in self.indexes}
        constants = self._getConstants(algorithms)
        if len(constants.values):
            variants = [(algorithm, algorithm, None, 0) for algorithm in algorithms]
            self._findHits(results, constants, variants, binary, min_hits, REGION_GAP, load_offset, taken)
        if keyed and self.indexes:
            variants = [
                (getKeyedLabel(algorithm, mode, key), algorithm, mode, key)
                for (algorithm, mode), keys in self.findKeys(binary, algorithms, min_key_apis).items()
                for key in keys
            ]
            if variants:
                # the hashes without a key of these algorithms take part, they may be the real ones
                variants += [(algorithm, algorithm, None, 0) for algorithm in dict.fromkeys(v[1] for v in variants)]
                hashes = [
                    index.getKeyedTable(algorithm, mode, key).hashes
                    for index in self.indexes.values()
                    for _, algorithm, mode, key in variants
                ]
                constants = _ConstantSet(np.concatenate(hashes))
                self._findHits(
                    results, constants, variants, binary, min_hits, KEYED_REGION_GAP, load_offset, taken, compete=True
                )
        for hits in results.values():
            hits.sort(key=lambda hit: (hit.offset, hit.algorithm, hit.api))
        return results

    def _findHits(self, results, constants, variants, binary, min_hits, gap, load_offset, taken, compete=False):
        """adds the APIs of which the hashes (variants: (label, algorithm, mode, key)) are in regions of the binary to the results

        compete: a constant is the hash of one API, so the variants that have it take turns, the one with the most hits first, and a
        variant does not get the hits at the offsets that earlier variants, or the hashes searched before (taken), have. This is what
        happens to a key that is a real key combined with the difference of the hashes of two names: CRC-32 (XOR) and the hashes that
        add the last character (ADD) have the same difference for all names that end with A and W, so the two keys have many probe
        APIs and many hits in common; the real key has more of both. The hashes without a key, the variant without a mode, take
        part like the others but are not reported again, they were searched before (with the gap of unkeyed hashes)."""
        offsets, values = constants.find(binary)
        if not len(offsets):
            return
        for name, index in self.indexes.items():
            found = []
            for variant in variants:
                table = index.getKeyedTable(variant[1], variant[2], variant[3])
                left = np.searchsorted(table.hashes, values, side="left")
                right = np.searchsorted(table.hashes, values, side="right")
                member = np.flatnonzero(right > left)
                if len(member):
                    hits = list(zip(offsets[member].tolist(), values[member].tolist(), strict=True))
                    found.append((variant, table, hits))
            if compete:
                found.sort(key=lambda entry: -len(entry[2]))
            for (label, algorithm, mode, _), table, hits in found:
                if compete:
                    hits = [hit for hit in hits if hit[0] not in taken[name]]
                # the hashes without key of a competition were reported before
                report = mode is not None or not compete
                needed = min_hits or getMinimumHits(index.getNumHashes(algorithm), len(binary), gap)
                for offset, value in getRegions(hits, needed, gap):
                    first = int(np.searchsorted(table.hashes, value, side="left"))
                    last = int(np.searchsorted(table.hashes, value, side="right"))
                    taken[name].add(offset)
                    for row in range(first, last if report else first):
                        api, dlls = index.resolve(algorithm, row, table)
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
                    found = _findStrings(binary, names, unit_size, min_length, index.max_name_length)
                    for offset, api in getStringRuns(found, unit_size, min_run, gap):
                        hits.append(DynamicApi(offset + load_offset, "string", encoding, None, api, names[api]))
            hits.sort(key=lambda hit: (hit.offset, hit.algorithm, hit.api))
            results[name] = hits
        return results
