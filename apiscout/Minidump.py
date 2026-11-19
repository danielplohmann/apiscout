########################################################################
# Copyright (c) 2026
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

"""Reader for Windows minidumps (MDMP), as far as ApiScout needs them: the memory ranges and the module list.

Structures after minidumpapiset.h (all little endian):

    MINIDUMP_HEADER          32 bytes: Signature "MDMP", Version, NumberOfStreams, StreamDirectoryRva (u32 each),
                             CheckSum, TimeDateStamp (u32 each), Flags (u64)
    MINIDUMP_DIRECTORY       12 bytes: StreamType, then a MINIDUMP_LOCATION_DESCRIPTOR (DataSize, Rva; u32 each)
    MINIDUMP_MEMORY_LIST     NumberOfMemoryRanges (u32), then MINIDUMP_MEMORY_DESCRIPTORs of 16 bytes:
                             StartOfMemoryRange (u64), DataSize (u32), Rva (u32)
    MINIDUMP_MEMORY64_LIST   NumberOfMemoryRanges (u64), BaseRva (u64), then MINIDUMP_MEMORY_DESCRIPTOR64s of
                             16 bytes: StartOfMemoryRange (u64), DataSize (u64). The data of all ranges follows
                             one after another from BaseRva.
    MINIDUMP_MODULE_LIST     NumberOfModules (u32), then MINIDUMP_MODULEs of 108 bytes: BaseOfImage (u64),
                             SizeOfImage, CheckSum, TimeDateStamp, ModuleNameRva (u32 each), VersionInfo (52 bytes),
                             CvRecord, MiscRecord (8 bytes each), Reserved0, Reserved1 (u64 each)
    MINIDUMP_STRING          Length in bytes without terminator (u32), then UTF-16 text
    MINIDUMP_SYSTEM_INFO     starts with ProcessorArchitecture (u16)

Nothing of the file is trusted: counts and sizes are checked against the file before they are used, ranges are
kept as views of the file and never take more memory than the file itself.
"""

import struct
from dataclasses import dataclass

SIGNATURE = b"MDMP"
HEADER_SIZE = 32
DIRECTORY_ENTRY_SIZE = 12
MEMORY_DESCRIPTOR_SIZE = 16
MODULE_SIZE = 108
# MINIDUMP_STREAM_TYPE
MODULE_LIST_STREAM = 4
MEMORY_LIST_STREAM = 5
SYSTEM_INFO_STREAM = 7
MEMORY64_LIST_STREAM = 9
# PROCESSOR_ARCHITECTURE_*
ARCHITECTURE_INTEL = 0
ARCHITECTURE_IA64 = 6
ARCHITECTURE_AMD64 = 9
ARCHITECTURE_ARM64 = 12
# paths are at most 32767 characters
MAX_NAME_BYTES = 0xFFFE
MAX_ADDRESS = 1 << 64


class MinidumpError(ValueError):
    """The file is no minidump, or too damaged to be read."""


@dataclass(frozen=True)
class MinidumpModule:
    name: str
    base_address: int
    size: int
    timestamp: int
    checksum: int

    @property
    def end_address(self):
        return self.base_address + self.size


class Minidump:
    def __init__(self, data):
        self._data = memoryview(data)
        self.warnings = []
        self.architecture = None
        self.modules = []
        # (start address, offset in the file, size)
        self._ranges = []
        self._claimed_bytes = 0
        self._parse()

    @staticmethod
    def isMinidump(data):
        return len(data) >= 4 and bytes(data[:4]) == SIGNATURE

    @property
    def bitness(self):
        """32 or 64 by the processor architecture of the system, None if it is unknown."""
        if self.architecture == ARCHITECTURE_INTEL:
            return 32
        if self.architecture in (ARCHITECTURE_AMD64, ARCHITECTURE_ARM64, ARCHITECTURE_IA64):
            return 64
        return None

    def _warn(self, message):
        self.warnings.append(message)

    def _unpack(self, fmt, offset):
        return struct.unpack_from(fmt, self._data, offset)

    def _fits(self, offset, size):
        return offset >= 0 and size >= 0 and offset + size <= len(self._data)

    def _parse(self):
        if not self.isMinidump(self._data):
            raise MinidumpError("no MDMP signature")
        if len(self._data) < HEADER_SIZE:
            raise MinidumpError("truncated minidump header")
        number_of_streams, directory_rva = self._unpack("<II", 8)
        if not self._fits(directory_rva, number_of_streams * DIRECTORY_ENTRY_SIZE):
            raise MinidumpError(
                f"the stream directory ({number_of_streams} streams at 0x{directory_rva:x}) is outside of the file, "
                "which is truncated or damaged"
            )
        streams = {}
        for index in range(number_of_streams):
            stream_type, size, rva = self._unpack("<III", directory_rva + index * DIRECTORY_ENTRY_SIZE)
            streams.setdefault(stream_type, (rva, size))
        if SYSTEM_INFO_STREAM in streams:
            self._parseSystemInfo(*streams[SYSTEM_INFO_STREAM])
        if MEMORY64_LIST_STREAM in streams:
            self._parseMemory64List(*streams[MEMORY64_LIST_STREAM])
        if MEMORY_LIST_STREAM in streams:
            self._parseMemoryList(*streams[MEMORY_LIST_STREAM])
        if MODULE_LIST_STREAM in streams:
            self._parseModuleList(*streams[MODULE_LIST_STREAM])
        if not self._ranges:
            raise MinidumpError("no memory ranges (a dump of the process memory is needed, not only thread data)")

    def _parseSystemInfo(self, rva, size):
        if size >= 2 and self._fits(rva, 2):
            self.architecture = self._unpack("<H", rva)[0]

    def _addRange(self, start, offset, size):
        """Keep a range of memory, as far as the file holds its data.

        The sizes of all ranges together stay within the size of the file, so a damaged file can not make ApiScout work
        through more data than the file has.
        """
        if size <= 0 or start + size > MAX_ADDRESS or offset >= len(self._data):
            return
        if offset + size > len(self._data):
            self._warn(f"the data of the range at 0x{start:x} is cut off by the end of the file")
            size = len(self._data) - offset
        if self._claimed_bytes + size > len(self._data):
            size = len(self._data) - self._claimed_bytes
            self._warn("the memory ranges claim more data than the file holds, the rest is ignored")
            if size <= 0:
                return
        self._claimed_bytes += size
        self._ranges.append((start, offset, size))

    def _parseMemory64List(self, rva, size):
        if not self._fits(rva, 16):
            self._warn("the memory list is outside of the file")
            return
        count, offset = self._unpack("<QQ", rva)
        available = (len(self._data) - rva - 16) // MEMORY_DESCRIPTOR_SIZE
        if count > available:
            self._warn(f"the memory list names {count} ranges, but the file only has room for {available}")
            count = available
        for index in range(count):
            start, data_size = self._unpack("<QQ", rva + 16 + index * MEMORY_DESCRIPTOR_SIZE)
            self._addRange(start, offset, data_size)
            # the data of all ranges follows one after another, also the data of a range that is not kept
            offset += data_size
            if offset >= len(self._data):
                break

    def _parseMemoryList(self, rva, size):
        if not self._fits(rva, 4):
            self._warn("the memory list is outside of the file")
            return
        count = self._unpack("<I", rva)[0]
        available = (len(self._data) - rva - 4) // MEMORY_DESCRIPTOR_SIZE
        if count > available:
            self._warn(f"the memory list names {count} ranges, but the file only has room for {available}")
            count = available
        for index in range(count):
            start, data_size, data_rva = self._unpack("<QII", rva + 4 + index * MEMORY_DESCRIPTOR_SIZE)
            self._addRange(start, data_rva, data_size)

    def _readString(self, rva):
        """A MINIDUMP_STRING, empty if it is damaged."""
        if not self._fits(rva, 4):
            return ""
        length = min(self._unpack("<I", rva)[0], MAX_NAME_BYTES, len(self._data) - rva - 4)
        return bytes(self._data[rva + 4 : rva + 4 + length // 2 * 2]).decode("utf-16-le", errors="replace")

    def _parseModuleList(self, rva, size):
        if not self._fits(rva, 4):
            self._warn("the module list is outside of the file")
            return
        count = self._unpack("<I", rva)[0]
        available = (min(size, len(self._data) - rva) - 4) // MODULE_SIZE
        if count > available:
            self._warn(f"the module list names {count} modules, but the file only has room for {max(available, 0)}")
            count = max(available, 0)
        for index in range(count):
            offset = rva + 4 + index * MODULE_SIZE
            base_address, image_size, checksum, timestamp, name_rva = self._unpack("<QIIII", offset)
            self.modules.append(
                MinidumpModule(self._readString(name_rva), base_address, image_size, timestamp, checksum)
            )

    def getRanges(self):
        """Memory ranges as (start address, bytes) sorted by address, adjacent ranges joined.

        Overlaps are cut off, the data of the range with the lower address wins.
        """
        merged = []
        for start, offset, size in sorted(self._ranges):
            if merged:
                first_start, last_end, pieces = merged[-1]
                if start < last_end:
                    overlap = last_end - start
                    if overlap >= size:
                        continue
                    start, offset, size = last_end, offset + overlap, size - overlap
                if start == last_end:
                    pieces.append((offset, size))
                    merged[-1] = (first_start, start + size, pieces)
                    continue
            merged.append((start, start + size, [(offset, size)]))
        return [(start, self._join(pieces)) for start, _, pieces in merged]

    def _join(self, pieces):
        """The data of the pieces as one buffer: a view of the file where they follow each other in it, else a copy.

        The pieces together are not larger than the file, so a copy is not either.
        """
        joined = []
        for offset, size in pieces:
            if joined and joined[-1][0] + joined[-1][1] == offset:
                joined[-1] = (joined[-1][0], joined[-1][1] + size)
            else:
                joined.append((offset, size))
        if len(joined) == 1:
            return self._data[joined[0][0] : joined[0][0] + joined[0][1]]
        return b"".join(self._data[offset : offset + size] for offset, size in joined)

    def getModules(self):
        return list(self.modules)
