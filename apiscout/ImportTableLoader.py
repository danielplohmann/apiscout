import struct
import os
import json
import operator
import logging
import hashlib

from .utility import get_string, get_word, get_dword, get_qword
from .PeTools import PeTools
from .OrdinalHelper import OrdinalHelper

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class ImportDescriptor:

    def __init__(self, load_table_offset, name_table_offset, lib_name, is_64bit):
        self.load_table_offset = load_table_offset
        self.name_table_offset = name_table_offset
        self.imports = {}
        self.lib_name = lib_name
        self._is_64bit = is_64bit

    def parse(self, buf):
        self.imports = {}
        imp_offset = 0
        if self._is_64bit:
            imp = get_qword(buf, self.name_table_offset + imp_offset)
        else:
            imp = get_dword(buf, self.name_table_offset + imp_offset)
        # there is no length indicated for the array of imports, so we simply continue parsing until we hit zero.
        while imp != 0:
            thunk = self.load_table_offset + imp_offset
            self.imports[thunk] = self._parse_import(buf, self.name_table_offset + imp_offset)
            imp_offset += 8 if self._is_64bit else 4
            if self._is_64bit:
                imp = get_qword(buf, self.name_table_offset + imp_offset)
            else:
                imp = get_dword(buf, self.name_table_offset + imp_offset)

    def _parse_import(self, buf, offset):
        import_offset = get_dword(buf, offset)
        # import by ordinal
        if import_offset & 0x80000000:
            ordinal = get_word(buf, offset)
            name_by_ordinal = OrdinalHelper.resolveOrdinal(self.lib_name, ordinal)
            return  {"ordinal": ordinal, "name": name_by_ordinal, "dll_name": self.lib_name}
        return {"ordinal": get_word(buf, import_offset), "name": get_string(buf, import_offset + 2), "dll_name": self.lib_name}

    def __str__(self):
        return "{} - 0x{:x} -> 0x{:x} ({})".format(self.lib_name, self.name_table_offset, self.load_table_offset, len(self.imports))


class ImportTableLoader:

    def __init__(self, buf, sample_name=""):
        self._buffer = buf
        self._is_pe = PeTools.checkPe(buf)
        self._is_64bit = self._check_64bit()
        self._sample_name = sample_name

    def _check_64bit(self):
        pe_offset = PeTools.getPeOffset(self._buffer)
        file_characteristics_offset = pe_offset + 0x18
        if len(self._buffer) >= pe_offset + 0x18 + 2:
            file_characteristics = get_word(self._buffer, file_characteristics_offset)
            return True if file_characteristics == 0x20b else False
        return False

    def _get_64bit_bonus_offset(self):
        # in case of a PE32+, we need to adjust the data directory offset by 0x10 bytes.
        return 0x10 if self._is_64bit else 0

    def _parse_descriptor_fields(self, size, values):
        descriptor = None
        # 20b == import descriptor, 32b == delay import descriptor
        if size == 20:
            descriptor = ImportDescriptor(values[4], values[0], get_string(self._buffer, values[3]), self._is_64bit)
        elif size == 32:
            descriptor = ImportDescriptor(values[3], values[4], get_string(self._buffer, values[1]), self._is_64bit)
        return descriptor

    def _parse_descriptor(self, offset, size):
        if not size in [20, 32]:
            raise RuntimeError("Import Descriptors can only be of size 20 / 32 byte.")
        else:
            values = struct.unpack("I" * int(size / 4), self._buffer[offset:offset + size])
            return self._parse_descriptor_fields(size, values)

    def _get_table(self, directory_offset, descriptor_size):
        import_address_table = {}
        if not self._is_pe:
            return import_address_table
        pe_offset = PeTools.getPeOffset(self._buffer)
        import_dd_offset = pe_offset + directory_offset + self. _get_64bit_bonus_offset()
        it_rva = get_dword(self._buffer, import_dd_offset)
        if it_rva:
            it_offset = 0
            try:
                # the number of descriptors is not indicated, so we continue parsing until we hit zero.
                descriptor = self._parse_descriptor(it_rva + it_offset, descriptor_size)
                while descriptor.load_table_offset:
                    descriptor.parse(self._buffer)
                    import_address_table.update(descriptor.imports)
                    it_offset += descriptor_size
                    descriptor = self._parse_descriptor(it_rva + it_offset, descriptor_size)
            except IndexError:
                self._sample_name = self._sample_name if self._sample_name != "" else hashlib.sha256(self._buffer).hexdigest()
                LOG.warn("Import Table parsing was incomplete on file (%s), due to IndexError. Continuing with %d extracted imports...", self._sample_name, len(import_address_table.items()))
                return import_address_table
            except struct.error:
                self._sample_name = self._sample_name if self._sample_name != "" else hashlib.sha256(self._buffer).hexdigest()
                LOG.warn("Import Table parsing was incomplete on file (%s), due to struct.error. Continuing  with %d extracted imports...", self._sample_name, len(import_address_table.items()))
                return import_address_table
        return import_address_table

    def get_import_table(self):
        return self._get_table(0x80, 20)

    def get_delay_import_table(self):
        return self._get_table(0xE0, 32)

    def __str__(self):
        return "ImportTableLoader - buffer size: {} bytes, PE: {}, 64bit: {}".format(len(self._buffer), self._is_pe, self._is_64bit)
