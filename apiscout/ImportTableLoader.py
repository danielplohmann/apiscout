import hashlib
import logging
import struct

from .OrdinalHelper import OrdinalHelper
from .PeTools import PeTools
from .utility import get_dword, get_qword, get_string, get_word

LOG = logging.getLogger(__name__)


class ImportDescriptor:
    def __init__(self, load_table_offset, name_table_offset, lib_name, is_64bit):
        self.load_table_offset = load_table_offset
        self.name_table_offset = name_table_offset
        self.imports = {}
        self.lib_name = lib_name
        self._is_64bit = is_64bit

    def parse(self, buf, max_imports=None):
        self.imports = {}
        imp_offset = 0
        # some linkers and most packers leave the import name table (OriginalFirstThunk) empty.
        # In this case, the import address table still carries the name references as long as the file was not loaded.
        name_table_offset = self.name_table_offset if self.name_table_offset else self.load_table_offset
        if self._is_64bit:
            imp = get_qword(buf, name_table_offset + imp_offset)
        else:
            imp = get_dword(buf, name_table_offset + imp_offset)
        # there is no length indicated for the array of imports, so we simply continue parsing until we hit zero.
        # thunks of a crafted table can all name the same import, which is parsed once
        parsed = {}
        while imp != 0 and (max_imports is None or len(self.imports) < max_imports):
            thunk = self.load_table_offset + imp_offset
            if imp not in parsed:
                parsed[imp] = self._parse_import(buf, name_table_offset + imp_offset)
            self.imports[thunk] = parsed[imp]
            imp_offset += 8 if self._is_64bit else 4
            if self._is_64bit:
                imp = get_qword(buf, name_table_offset + imp_offset)
            else:
                imp = get_dword(buf, name_table_offset + imp_offset)

    def _parse_import(self, buf, offset):
        import_offset = get_dword(buf, offset)
        # import by ordinal: flagged in the highest bit of the thunk, which is a QWORD for PE32+
        if self._is_64bit:
            is_ordinal_import = get_qword(buf, offset) & 0x8000000000000000
        else:
            is_ordinal_import = import_offset & 0x80000000
        if is_ordinal_import:
            ordinal = get_word(buf, offset)
            name_by_ordinal = OrdinalHelper.resolveOrdinal(self.lib_name, ordinal, 64 if self._is_64bit else 32)
            return {"ordinal": ordinal, "name": name_by_ordinal, "dll_name": self.lib_name}
        return {
            "ordinal": get_word(buf, import_offset),
            "name": get_string(buf, import_offset + 2),
            "dll_name": self.lib_name,
        }

    def __str__(self):
        return f"{self.lib_name} - 0x{self.name_table_offset:x} -> 0x{self.load_table_offset:x} ({len(self.imports)})"


class ImportTableLoader:
    def __init__(self, buf, sample_name="", max_thunks=None):
        self._buffer = buf
        self._max_thunks = max_thunks
        self._is_pe = PeTools.checkPe(buf)
        self._is_64bit = self._check_64bit()
        self._sample_name = sample_name

    def _check_64bit(self):
        pe_offset = PeTools.getPeOffset(self._buffer)
        file_characteristics_offset = pe_offset + 0x18
        if len(self._buffer) >= pe_offset + 0x18 + 2:
            file_characteristics = get_word(self._buffer, file_characteristics_offset)
            return file_characteristics == 0x20B
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
        if size not in [20, 32]:
            raise RuntimeError("Import Descriptors can only be of size 20 / 32 byte.")
        else:
            values = struct.unpack("<" + "I" * int(size / 4), self._buffer[offset : offset + size])
            return self._parse_descriptor_fields(size, values)

    def _get_table(self, directory_offset, descriptor_size):
        import_address_table = {}
        if not self._is_pe:
            return import_address_table
        pe_offset = PeTools.getPeOffset(self._buffer)
        import_dd_offset = pe_offset + directory_offset + self._get_64bit_bonus_offset()
        if len(self._buffer) < import_dd_offset + 4:
            return import_address_table
        it_rva = get_dword(self._buffer, import_dd_offset)
        if it_rva:
            it_offset = 0
            # a buffer can not hold more thunks than pointers, crafted tables referencing each other are cut off here
            thunks_left = len(self._buffer) // (8 if self._is_64bit else 4)
            if self._max_thunks is not None:
                thunks_left = min(thunks_left, self._max_thunks)
            try:
                # the number of descriptors is not indicated, so we continue parsing until we hit zero.
                descriptor = self._parse_descriptor(it_rva + it_offset, descriptor_size)
                while descriptor.load_table_offset and thunks_left > 0:
                    descriptor.parse(self._buffer, thunks_left)
                    thunks_left -= len(descriptor.imports) + 1
                    import_address_table.update(descriptor.imports)
                    it_offset += descriptor_size
                    descriptor = self._parse_descriptor(it_rva + it_offset, descriptor_size)
            except IndexError:
                self._sample_name = (
                    self._sample_name if self._sample_name != "" else hashlib.sha256(self._buffer).hexdigest()
                )
                LOG.warning(
                    "Import Table parsing was incomplete on file (%s), due to IndexError. Continuing with %d extracted imports...",
                    self._sample_name,
                    len(import_address_table.items()),
                )
                return import_address_table
            except struct.error:
                self._sample_name = (
                    self._sample_name if self._sample_name != "" else hashlib.sha256(self._buffer).hexdigest()
                )
                LOG.warning(
                    "Import Table parsing was incomplete on file (%s), due to struct.error. Continuing  with %d extracted imports...",
                    self._sample_name,
                    len(import_address_table.items()),
                )
                return import_address_table
        return import_address_table

    def get_import_table(self):
        return self._get_table(0x80, 20)

    def get_delay_import_table(self):
        return self._get_table(0xE0, 32)

    def __str__(self):
        return f"ImportTableLoader - buffer size: {len(self._buffer)} bytes, PE: {self._is_pe}, 64bit: {self._is_64bit}"
