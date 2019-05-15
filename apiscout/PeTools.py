import logging
import struct

from .utility import get_word

if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)

class PeTools(object):

    BITNESS_MAP = {0x14c: 32, 0x8664: 64}

    @staticmethod
    def mapBinary(binary):
        # This is a pretty rough implementation but does the job for now
        mapped_binary = bytearray([])
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset:
            num_sections = 0
            bitness = 0
            section_infos = []
            optional_header_size = 0xF8
            if pe_offset and len(binary) >= pe_offset + 0x8:
                num_sections = struct.unpack("H", binary[pe_offset + 0x6:pe_offset + 0x8])[0]
                bitness = PeTools.getBitness(binary)
                if bitness == 64:
                    optional_header_size = 0x108
            if pe_offset and num_sections and len(binary) >= pe_offset + optional_header_size + num_sections * 0x28:
                for section_index in range(num_sections):
                    section_offset = section_index * 0x28
                    slice_start = pe_offset + optional_header_size + section_offset + 0x8
                    slice_end = pe_offset + optional_header_size + section_offset + 0x8 + 0x10
                    virt_size, virt_offset, raw_size, raw_offset = struct.unpack("IIII", binary[slice_start:slice_end])
                    section_info = {
                        "section_index": section_index,
                        "virt_size": virt_size,
                        "virt_offset": virt_offset,
                        "raw_size": raw_size,
                        "raw_offset": raw_offset,
                    }
                    section_infos.append(section_info)
            max_virt_section_offset = 0
            min_raw_section_offset = 0xFFFFFFFF
            if section_infos:
                for section_info in section_infos:
                    max_virt_section_offset = max(max_virt_section_offset, section_info["virt_size"] + section_info["virt_offset"])
                    max_virt_section_offset = max(max_virt_section_offset, section_info["raw_size"] + section_info["virt_offset"])
                    if section_info["raw_offset"] > 0x200:
                        min_raw_section_offset = min(min_raw_section_offset, section_info["raw_offset"])
            if max_virt_section_offset:
                mapped_binary = bytearray([0] * max_virt_section_offset)
                mapped_binary[0:min_raw_section_offset] = binary[0:min_raw_section_offset]
            for section_info in section_infos:
                mapped_binary[section_info["virt_offset"]:section_info["virt_offset"] + section_info["raw_size"]] = binary[section_info["raw_offset"]:section_info["raw_offset"] + section_info["raw_size"]]
                LOG.debug("Mapping %d: raw 0x%x (0x%x bytes) -> virtual 0x%x (0x%x bytes)", section_info["section_index"], section_info["raw_offset"], section_info["raw_size"], section_info["virt_offset"], section_info["virt_size"])
        LOG.debug("Mapped binary of size %d bytes (%d sections) to memory view of size %d bytes", len(binary), num_sections, len(mapped_binary))
        return bytes(mapped_binary)

    @staticmethod
    def getBitness(binary):
        bitness_id = 0
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset:
            if pe_offset and len(binary) >= pe_offset + 0x6:
                bitness_id = struct.unpack("H", binary[pe_offset + 0x4:pe_offset + 0x6])[0]
        return PeTools.BITNESS_MAP.get(bitness_id, 0)

    @staticmethod
    def getBaseAddressFromPeHeader(binary):
        pe_offset = PeTools.getPeOffset(binary)
        if pe_offset:
            if pe_offset and len(binary) >= pe_offset + 0x38:
                base_addr = struct.unpack("I", binary[pe_offset + 0x34:pe_offset + 0x38])[0]
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

