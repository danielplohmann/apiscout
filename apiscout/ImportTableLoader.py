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
        while imp != 0 and (max_imports is None or len(self.imports) < max_imports):
            thunk = self.load_table_offset + imp_offset
            self.imports[thunk] = self._parse_import(buf, name_table_offset + imp_offset)
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

    @staticmethod
    def fileExceedsThunkBudget(binary, max_thunks):
        """
        counts the thunks of the import and delay import descriptors of a PE file the way a parser of the file
        layout may read them: through every section covering an RVA, for both thunk lists and past descriptors
        without address table. The work spent on counting is limited as well.
        """
        if not PeTools.checkPe(binary):
            return False
        pe_offset = PeTools.getPeOffset(binary)
        optional_header_offset = pe_offset + 0x18
        if len(binary) < optional_header_offset + 0x20:
            return False
        is_64bit = get_word(binary, optional_header_offset) == 0x20B
        thunk_size = 8 if is_64bit else 4
        if is_64bit:
            image_base = get_qword(binary, optional_header_offset + 0x18)
        else:
            image_base = get_dword(binary, optional_header_offset + 0x1C)
        sections = []
        section_offset = optional_header_offset + get_word(binary, pe_offset + 0x14)
        for _ in range(get_word(binary, pe_offset + 6)):
            if len(binary) < section_offset + 0x28:
                break
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", binary, section_offset + 8
            )
            sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))
            section_offset += 0x28

        def file_offsets(rva):
            offsets = {raw_offset + rva - start for start, size, raw_offset in sections if 0 <= rva - start < size}
            # outside of all sections, an RVA is read as offset into the headers
            return offsets or {rva}

        budget = {"steps": 4 * max_thunks + 0x400}
        thunk_counts = {}

        def count_thunks(rva):
            if rva not in thunk_counts:
                longest = 0
                for offset in file_offsets(rva) if rva else ():
                    start = offset
                    while budget["steps"] > 0 and any(binary[offset : offset + thunk_size]):
                        offset += thunk_size
                        budget["steps"] -= 1
                    budget["steps"] -= 1
                    longest = max(longest, (offset - start) // thunk_size)
                thunk_counts[rva] = longest
            return thunk_counts[rva]

        num_thunks = 0
        # import directory and delay import directory: (offset of the data directory, descriptor size, thunk list fields)
        for directory_offset, descriptor_size, thunk_fields in ((0x80, 20, (0, 4)), (0xE0, 32, (3, 4))):
            directory_offset += pe_offset + (0x10 if is_64bit else 0)
            if len(binary) < directory_offset + 4 or not get_dword(binary, directory_offset):
                continue
            for table_offset in file_offsets(get_dword(binary, directory_offset)):
                while table_offset + descriptor_size <= len(binary):
                    values = struct.unpack_from("<" + "I" * (descriptor_size // 4), binary, table_offset)
                    if not any(values):
                        break
                    # delay import descriptors of old linkers hold virtual addresses instead of RVAs
                    rvas = {values[field] for field in thunk_fields}
                    rvas.update(
                        rva - image_base for rva in list(rvas) if descriptor_size == 32 and rva >= image_base > 0
                    )
                    num_thunks += max(count_thunks(rva) for rva in rvas)
                    budget["steps"] -= 1
                    if num_thunks > max_thunks or budget["steps"] <= 0:
                        return True
                    table_offset += descriptor_size
        return False

    def get_import_table(self):
        return self._get_table(0x80, 20)

    def get_delay_import_table(self):
        return self._get_table(0xE0, 32)

    def __str__(self):
        return f"ImportTableLoader - buffer size: {len(self._buffer)} bytes, PE: {self._is_pe}, 64bit: {self._is_64bit}"
