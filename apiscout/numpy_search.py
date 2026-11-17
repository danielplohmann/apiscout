"""The searches of a buffer that make ApiScout.crawl() fast, with numpy: the DWORDs and QWORDs that are addresses of
APIs (AddressSearch), and the calls and jumps through pointers that refer to given offsets (find_code_references).
ApiScout does the same with plain loops where numpy is missing, just much slower."""

import os
from concurrent.futures import ThreadPoolExecutor

import numpy as np

# a buffer is searched in up to this many threads: numpy does not hold the GIL during its passes over an array
MAX_THREADS = min(os.cpu_count() or 1, 4)
# offsets searched at once by a thread, which bounds the memory use to some 10 MB per thread
CHUNK_SIZE = 1 << 20
# offsets searched at once for the flags of a pass: small enough to stay in the cache of the CPU
BLOCK_SIZE = 1 << 16


def _search_chunks(search_chunk, size):
    """[search_chunk(first, last)] for the consecutive chunks of range(size), in order, in threads if there are several"""
    chunks = [(first, min(first + CHUNK_SIZE, size)) for first in range(0, size, CHUNK_SIZE)]
    if len(chunks) < 2 or MAX_THREADS < 2:
        return [search_chunk(*chunk) for chunk in chunks]
    with ThreadPoolExecutor(MAX_THREADS) as pool:
        return list(pool.map(lambda chunk: search_chunk(*chunk), chunks))


def _find_flagged(get_flags, first, last):
    """the offsets from first up to last for which get_flags(first, last) has a flag, which looks at blocks of them"""
    blocks = range(first, last, BLOCK_SIZE)
    return np.concatenate([np.flatnonzero(get_flags(block, min(block + BLOCK_SIZE, last))) + block for block in blocks])


class AddressSearch:
    """The DWORDs and QWORDs of a buffer that are addresses of API maps.

    The 16 bits above the lowest 16 of an address are one of few of the 65536 possible values (some hundred for the
    addresses of a Windows), so the buffer is first searched for these at every offset: about 2% of the offsets of a
    dump are left. The values at these offsets are then looked up by their hash in a table of flags, and only those
    that are in it are compared with the addresses. What takes the time are the passes over the whole buffer, so they
    go over blocks that fit in the cache of the CPU."""

    # the table of flags has this many bits, one in ten is set for the addresses of a Windows
    HASH_BITS = 20

    def __init__(self, addresses):
        """addresses: {(API map name, width): sorted array of the addresses to find as DWORDs (width 4, uint32) or
        QWORDs (width 8, uint64)}"""
        self._tables = {}
        self._key_flags = {}
        for (name, width), values in addresses.items():
            if len(values):
                flags = np.zeros(1 << self.HASH_BITS, dtype=bool)
                flags[self._getSlots(values)] = True
                self._tables[name, width] = (values, flags)
                key_flags = self._key_flags.setdefault(width, np.zeros(1 << 16, dtype=bool))
                key_flags[(values >> values.dtype.type(16)) & 0xFFFF] = True
        self._searched = {}

    @classmethod
    def fromApiMaps(cls, api_maps, other_bitness_maps):
        """a search for the APIs of API maps, {name: {address: (DLL, API, bitness)}}. A 32bit and a 64bit export at the
        same address are both there, the second one in other_bitness_maps."""
        addresses = {}
        for name, api_map in api_maps.items():
            keys = np.fromiter(api_map, dtype=np.uint64, count=len(api_map))
            for width in (4, 8):
                bits = width * 8
                is_api = np.fromiter((entry[2] == bits for entry in api_map.values()), dtype=bool, count=len(api_map))
                other = [address for address, entry in other_bitness_maps.get(name, {}).items() if entry[2] == bits]
                values = np.sort(np.append(keys[is_api], np.array(other, dtype=np.uint64)))
                addresses[name, width] = values.astype("<u4") if width == 4 else values
        return cls(addresses)

    @classmethod
    def _getSlots(cls, values):
        """the slots in a table of flags of values, an array of unsigned integers, by multiplicative hashing"""
        bits = values.dtype.itemsize * 8
        multiplier = values.dtype.type(0x9E3779B97F4A7C15 & ((1 << bits) - 1))
        return (values * multiplier) >> values.dtype.type(bits - cls.HASH_BITS)

    def find(self, binary, widths):
        """the offsets (ascending) and values of the DWORDs (width 4) and QWORDs (width 8) of the binary that are
        addresses, as {(API map name, width): [(offset, value)]}, without the maps and widths that have no address"""
        widths = tuple(width for width in widths if width in self._key_flags)
        count = len(binary) - 3
        if not widths or count <= 0:
            return {}
        if widths not in self._searched:
            key_flags = np.any([self._key_flags[width] for width in widths], axis=0)
            self._searched[widths] = (key_flags, [item for item in self._tables.items() if item[0][1] in widths])
        key_flags, tables = self._searched[widths]
        # one view of the binary has the 16 bits at each offset, the others the values of each width
        keys = np.ndarray(count, dtype="<u2", buffer=binary, offset=2, strides=(1,))
        words = {
            width: np.ndarray(max(len(binary) - width + 1, 0), dtype=f"<u{width}", buffer=binary, strides=(1,))
            for width in widths
        }

        def search_chunk(first, last):
            near = _find_flagged(lambda block, end: np.take(key_flags, keys[block:end], mode="clip"), first, last)
            hits = {}
            values_at = {}
            for (name, width), (addresses, flags) in tables:
                if width not in values_at:
                    offsets = near[: np.searchsorted(near, len(binary) - width, side="right")]
                    values = words[width][offsets]
                    values_at[width] = (offsets, values, self._getSlots(values))
                offsets, values, slots = values_at[width]
                likely = np.flatnonzero(flags[slots])
                candidates = values[likely]
                positions = np.minimum(np.searchsorted(addresses, candidates), len(addresses) - 1)
                is_address = addresses[positions] == candidates
                hits[name, width] = (offsets[likely[is_address]], candidates[is_address])
            return hits

        chunk_hits = _search_chunks(search_chunk, count)
        return {
            key: list(
                zip(
                    np.concatenate([hits[key][0] for hits in chunk_hits]).tolist(),
                    np.concatenate([hits[key][1] for hits in chunk_hits]).tolist(),
                    strict=True,
                )
            )
            for key, _ in tables
        }


def _find_branches(binary):
    """offsets of the instructions FF 15 and FF 25 (call and jmp through a pointer) that have the four bytes of their
    operand behind them"""
    data = np.frombuffer(binary, dtype=np.uint8)

    def get_flags(first, last):
        second = data[first + 1 : last + 1]
        return (data[first:last] == 0xFF) & ((second == 0x15) | (second == 0x25))

    return _find_flagged(get_flags, 0, len(data) - 5) if len(data) > 5 else np.empty(0, dtype=np.int64)


def find_code_references(binary, targets, base_address):
    """references by calls and jumps through pointers to the given offsets (any iterable of integers) of the binary, as
    {bitness: {offset: {offsets of the instructions}}}. A 32bit instruction has the address of its target, base_address
    plus the offset, a 64bit instruction the distance from its end to the target (RIP-relative)."""
    references = {32: {}, 64: {}}
    targets = np.unique(np.fromiter(targets, dtype=np.int64))
    branches = _find_branches(binary) if len(targets) else np.empty(0, dtype=np.int64)
    if not len(branches):
        return references
    # the operand of the instructions, as an unsigned number for a 32bit reference and as a signed one for a 64bit one
    operands = np.ndarray(len(binary) - 3, dtype="<u4", buffer=binary, strides=(1,))[branches + 2].astype(np.int64)
    referenced = {64: np.where(operands >= 1 << 31, operands - (1 << 32), operands) + branches + 6}
    if -len(binary) < base_address < 1 << 32:
        referenced[32] = operands - base_address
    for bitness, offsets in referenced.items():
        inside = (offsets > 0) & (offsets < len(binary))
        is_target = np.isin(offsets[inside], targets)
        for offset, branch in zip(
            offsets[inside][is_target].tolist(), branches[inside][is_target].tolist(), strict=True
        ):
            references[bitness].setdefault(offset, set()).add(branch)
    return references
