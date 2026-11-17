import logging
import struct

from .utility import get_dword, get_qword, get_word

LOG = logging.getLogger(__name__)


class PeTools:
    BITNESS_MAP = {0x14C: 32, 0x8664: 64}
    # images beyond this size, or this multiple of the file size, are not mapped as their section table is most likely corrupt
    MAX_MAPPED_SIZE = 0x10000000
    MAX_MAPPED_RATIO = 256

    @staticmethod
    def mapBinary(binary):
        """map a PE file as it would be laid out in memory (sections moved to their virtual offsets), returns empty bytes if this is not possible"""
        mapped_binary = bytearray([])
        pe_offset = PeTools.getPeOffset(binary)
        num_sections = 0
        section_infos = []
        if pe_offset and len(binary) >= pe_offset + 0x18:
            num_sections = get_word(binary, pe_offset + 0x6)
            # the section table starts behind the optional header, whose size is given in the file header
            section_table_offset = pe_offset + 0x18 + get_word(binary, pe_offset + 0x14)
            if num_sections and len(binary) >= section_table_offset + num_sections * 0x28:
                for section_index in range(num_sections):
                    virt_size, virt_offset, raw_size, raw_offset = struct.unpack_from(
                        "<IIII", binary, section_table_offset + section_index * 0x28 + 0x8
                    )
                    section_infos.append(
                        {
                            "section_index": section_index,
                            "virt_size": virt_size,
                            "virt_offset": virt_offset,
                            "raw_size": raw_size,
                            "raw_offset": raw_offset,
                        }
                    )
        max_virt_section_offset = 0
        header_size = len(binary)
        for section_info in section_infos:
            max_virt_section_offset = max(
                max_virt_section_offset, section_info["virt_size"] + section_info["virt_offset"]
            )
            max_virt_section_offset = max(
                max_virt_section_offset, section_info["raw_size"] + section_info["virt_offset"]
            )
            # the headers reach up to the raw data of the first section, and are not allowed to overlap any mapped section
            if section_info["raw_size"] and section_info["raw_offset"]:
                header_size = min(header_size, section_info["raw_offset"])
            header_size = min(header_size, section_info["virt_offset"])
        if max_virt_section_offset > min(PeTools.MAX_MAPPED_SIZE, PeTools.MAX_MAPPED_RATIO * max(len(binary), 0x1000)):
            # mostly uninitialized memory (or a corrupt size), which is cut off behind the data the file provides
            max_virt_section_offset = max(
                section_info["virt_offset"]
                + max(0, min(section_info["raw_size"], len(binary) - section_info["raw_offset"]))
                for section_info in section_infos
            )
        if max_virt_section_offset > PeTools.MAX_MAPPED_SIZE:
            LOG.warning(
                "Section table describes an image of 0x%x bytes, which is treated as corrupt - not mapping this binary.",
                max_virt_section_offset,
            )
            return bytes(mapped_binary)
        if max_virt_section_offset:
            mapped_binary = bytearray(max_virt_section_offset)
            mapped_binary[0:header_size] = binary[0:header_size]
            # Sections sharing their raw data would multiply the content of a crafted file: data that an earlier
            # section mapped already is only mapped again up to the size of the file, and the work spent on
            # sections is limited as well. Files whose sections do not overlap are not affected.
            covered = bytearray(len(binary))
            repeated_bytes_left = len(binary)
            work_left = 16 * len(binary)
            is_reported = False
            for section_info in section_infos:
                # the file may be truncated, so only map what is actually there
                raw_start = min(section_info["raw_offset"], len(binary))
                space = max(0, len(mapped_binary) - section_info["virt_offset"])
                raw_end = min(raw_start + section_info["raw_size"], len(binary), raw_start + space)
                if raw_end <= raw_start:
                    continue
                if raw_end - raw_start > work_left:
                    if not is_reported:
                        LOG.warning("Sections share their data excessively, not all of them are mapped.")
                    is_reported = True
                    continue
                work_left -= raw_end - raw_start
                repeated = covered.count(1, raw_start, raw_end)
                if repeated <= repeated_bytes_left:
                    repeated_bytes_left -= repeated
                    parts = [(raw_start, raw_end)]
                else:
                    parts = PeTools._getUncoveredParts(covered, raw_start, raw_end)
                for start, end in parts:
                    target = section_info["virt_offset"] + start - raw_start
                    mapped_binary[target : target + end - start] = binary[start:end]
                    covered[start:end] = b"\x01" * (end - start)
                LOG.debug(
                    "Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)",
                    section_info["section_index"],
                    section_info["raw_offset"],
                    section_info["raw_size"],
                    section_info["virt_offset"],
                    section_info["virt_size"],
                )
        LOG.debug(
            "Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes",
            len(binary),
            num_sections,
            len(mapped_binary),
        )
        return bytes(mapped_binary)

    @staticmethod
    def _getUncoveredParts(covered, start, end):
        parts = []
        while start < end:
            start = covered.find(0, start, end)
            if start < 0:
                break
            part_end = covered.find(1, start, end)
            part_end = end if part_end < 0 else part_end
            parts.append((start, part_end))
            start = part_end
        return parts

    @staticmethod
    def getBitness(binary):
        bitness_id = 0
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset and pe_offset and len(binary) >= pe_offset + 0x6:
            bitness_id = struct.unpack("<H", binary[pe_offset + 0x4 : pe_offset + 0x6])[0]
        return PeTools.BITNESS_MAP.get(bitness_id, 0)

    @staticmethod
    def getBaseAddressFromPeHeader(binary):
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 0x38:
            if get_word(binary, pe_offset + 0x18) == 0x20B:
                # PE32+: ImageBase is a QWORD at offset 0x18 of the optional header
                base_addr = get_qword(binary, pe_offset + 0x30)
            else:
                base_addr = get_dword(binary, pe_offset + 0x34)
            LOG.debug("Using base address 0x%x from PE header for inference of reference counts", base_addr)
            return base_addr
        return 0

    @staticmethod
    def getPeOffset(binary):
        if len(binary) >= 0x40:
            pe_offset = get_dword(binary, 0x3C)
            if pe_offset < len(binary):
                return pe_offset
        return 0

    @staticmethod
    def checkPe(binary):
        pe_offset = PeTools.getPeOffset(binary)
        if binary[:2] == b"MZ" and pe_offset and binary[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            return PeTools.getBitness(binary) != 0
        return False
