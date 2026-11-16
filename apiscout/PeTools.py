import logging
import struct

from .utility import get_word

if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)

class PeTools(object):

    BITNESS_MAP = {0x14c: 32, 0x8664: 64}
    # images beyond this size are not mapped, as their section table is most likely corrupt
    MAX_MAPPED_SIZE = 0x40000000

    @staticmethod
    def mapBinary(binary):
        """ map a PE file as it would be laid out in memory (sections moved to their virtual offsets), returns empty bytes if this is not possible """
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
                    virt_size, virt_offset, raw_size, raw_offset = struct.unpack_from("<IIII", binary, section_table_offset + section_index * 0x28 + 0x8)
                    section_infos.append({
                        "section_index": section_index,
                        "virt_size": virt_size,
                        "virt_offset": virt_offset,
                        "raw_size": raw_size,
                        "raw_offset": raw_offset,
                    })
        max_virt_section_offset = 0
        header_size = len(binary)
        for section_info in section_infos:
            max_virt_section_offset = max(max_virt_section_offset, section_info["virt_size"] + section_info["virt_offset"])
            max_virt_section_offset = max(max_virt_section_offset, section_info["raw_size"] + section_info["virt_offset"])
            # the headers reach up to the raw data of the first section, and are not allowed to overlap any mapped section
            if section_info["raw_size"] and section_info["raw_offset"]:
                header_size = min(header_size, section_info["raw_offset"])
            header_size = min(header_size, section_info["virt_offset"])
        if max_virt_section_offset > PeTools.MAX_MAPPED_SIZE:
            LOG.warning("Section table describes an image of 0x%x bytes, which is treated as corrupt - not mapping this binary.", max_virt_section_offset)
            return bytes(mapped_binary)
        if max_virt_section_offset:
            mapped_binary = bytearray(max_virt_section_offset)
            mapped_binary[0:header_size] = binary[0:header_size]
            for section_info in section_infos:
                # the file may be truncated, so only map what is actually there
                section_data = binary[section_info["raw_offset"]:section_info["raw_offset"] + section_info["raw_size"]]
                mapped_binary[section_info["virt_offset"]:section_info["virt_offset"] + len(section_data)] = section_data
                LOG.debug("Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)", section_info["section_index"], section_info["raw_offset"], section_info["raw_size"], section_info["virt_offset"], section_info["virt_size"])
        LOG.debug("Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes", len(binary), num_sections, len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        bitness_id = 0
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset:
            if pe_offset and len(binary) >= pe_offset + 0x6:
                bitness_id = struct.unpack("<H", binary[pe_offset + 0x4:pe_offset + 0x6])[0]
        return PeTools.BITNESS_MAP.get(bitness_id, 0)

    @staticmethod
    def getBaseAddressFromPeHeader(binary):
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset:
            if pe_offset and len(binary) >= pe_offset + 0x38:
                if get_word(binary, pe_offset + 0x18) == 0x20b:
                    # PE32+: ImageBase is a QWORD at offset 0x18 of the optional header
                    base_addr = struct.unpack("<Q", binary[pe_offset + 0x30:pe_offset + 0x38])[0]
                else:
                    base_addr = struct.unpack("<I", binary[pe_offset + 0x34:pe_offset + 0x38])[0]
                LOG.debug("Changing base address from 0 to: 0x%x for inference of reference counts (based on PE header)", base_addr)
                return base_addr
        return 0

    @staticmethod
    def getPeOffset(binary):
        if len(binary) >= 0x40:
            pe_offset = get_word(binary, 0x3c)
            return pe_offset
        return 0

    @staticmethod
    def checkPe(binary):
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset and len(binary) >= pe_offset + 6:
            bitness = get_word(binary, pe_offset + 4)
            return bitness in PeTools.BITNESS_MAP
        return False

