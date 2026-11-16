########################################################################
# Copyright (c) 2020
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout
#
#  apiscout is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_name
import ida_segment
import ida_typeinf
import ida_xref
import idautils


class IdaProxy:
    # segments are read in chunks of this size
    CHUNK_SIZE = 0x100000
    """Thin wrapper around the IDA API (IDA 9)"""

    def is64bit(self):
        return ida_ida.inf_is_64bit()

    def isLoaded(self, ea):
        return ida_segment.getseg(ea) is not None

    def getLoadedRanges(self, ea, size):
        """the parts of a range that have a value in the database as list of (address, bytes)"""
        ranges = []
        for chunk_start in range(ea, ea + size, self.CHUNK_SIZE):
            chunk_size = min(self.CHUNK_SIZE, ea + size - chunk_start)
            result = ida_bytes.get_bytes_and_mask(chunk_start, chunk_size)
            if not result:
                continue
            content, mask = result
            if not any(mask):
                continue
            if mask.count(b"\xff") == len(mask) and chunk_size % 8 == 0:
                loaded = [(0, chunk_size)]
            else:
                loaded = []
                start = None
                for index in range(chunk_size + 1):
                    is_loaded = index < chunk_size and (mask[index >> 3] >> (index & 7)) & 1
                    if is_loaded and start is None:
                        start = index
                    elif not is_loaded and start is not None:
                        loaded.append((start, index))
                        start = None
            for start, end in loaded:
                if ranges and ranges[-1][0] + len(ranges[-1][1]) == chunk_start + start:
                    ranges[-1] = (ranges[-1][0], ranges[-1][1] + content[start:end])
                else:
                    ranges.append((chunk_start + start, content[start:end]))
        return ranges

    def getNumReferences(self, ea):
        # without the ordinary flow from the preceding instruction
        return sum(1 for _ in idautils.XrefsTo(ea, ida_xref.XREF_FAR))

    def getBytes(self, ea, size):
        return ida_bytes.get_bytes(ea, size)

    def getSegEnd(self, ea):
        return ida_segment.getseg(ea).end_ea

    def getBlockingItem(self, ea, size, in_table):
        """
        describes the item that must not be replaced by a pointer at this location, None if there is no such item.
        Code of a function is always kept. Other code is only given up for a location that is referenced as data
        or lies in a table of API addresses, which IDA may have disassembled. Structures are kept as a whole.
        """
        is_pointer_location = in_table or any(True for _ in idautils.DataRefsTo(ea))
        for address in range(ea, ea + size):
            head = ida_bytes.get_item_head(address)
            flags = ida_bytes.get_full_flags(head)
            if ida_bytes.is_code(flags) and (ida_funcs.get_func(address) or not is_pointer_location):
                return "an instruction"
            if ida_bytes.is_struct(flags):
                return "a structure"
        return None

    def makeSegmentWritable(self, ea):
        """
        The decompiler treats the content of a segment that is not writable as constant and shows calls through
        API pointers as calls to numbers. Segments of a dump loaded as binary file carry no permissions at all
        and get all of them, other segments (e.g. .rdata) become writable in addition.
        """
        segment = ida_segment.getseg(ea)
        if segment is None or segment.perm & ida_segment.SEGPERM_WRITE:
            return False
        if segment.perm == 0:
            segment.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
        else:
            segment.perm |= ida_segment.SEGPERM_WRITE
        return segment.update()

    def undefine(self, ea, size):
        # also releases an item that starts in front of ea and reaches into the range
        ida_bytes.del_items(ida_bytes.get_item_head(ea), ida_bytes.DELIT_SIMPLE)
        return ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)

    def isData(self, ea, size):
        flags = ida_bytes.get_full_flags(ea)
        return ida_bytes.is_head(flags) and ida_bytes.is_data(flags) and ida_bytes.get_item_size(ea) == size

    def hasIndexRegister(self, instruction, operand):
        """x86: a memory operand with SIB byte whose index field (extended by REX.X) names a register"""
        index = (operand.specflag2 >> 3) & 7
        if (instruction.insnpref & 0x42) == 0x42:
            index |= 8
        return bool(operand.specflag1) and index != 4

    def MakeDWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)

    def MakeQWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)

    def MakeName(self, ea, name):
        # an API referenced from several locations gets a numbered name at the further ones
        return ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)

    def addTil(self, lib_name):
        return ida_typeinf.add_til(lib_name, ida_typeinf.ADDTIL_DEFAULT)
