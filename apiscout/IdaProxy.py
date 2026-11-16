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
import idautils


class IdaProxy:
    """Thin wrapper around the IDA API (IDA 7.4 and later, including IDA 9)"""

    def is64bit(self):
        return ida_ida.inf_is_64bit()

    def isLoaded(self, ea):
        return ida_segment.getseg(ea) is not None

    def hasBytes(self, ea):
        return ida_bytes.is_loaded(ea)

    def getNumReferences(self, ea):
        return sum(1 for _ in idautils.XrefsTo(ea))

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

    def grantUnknownPermissions(self, ea):
        """
        Segments of a dump loaded as binary file carry no permissions. The decompiler treats their content as
        constant then and shows calls through API pointers as calls to numbers, so such a segment gets all permissions.
        """
        segment = ida_segment.getseg(ea)
        if segment is None or segment.perm != 0:
            return False
        segment.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
        return segment.update()

    def undefine(self, ea, size):
        # also releases an item that starts in front of ea and reaches into the range
        ida_bytes.del_items(ida_bytes.get_item_head(ea), ida_bytes.DELIT_SIMPLE)
        return ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)

    def isData(self, ea, size):
        flags = ida_bytes.get_full_flags(ea)
        return ida_bytes.is_head(flags) and ida_bytes.is_data(flags) and ida_bytes.get_item_size(ea) == size

    def hasIndexRegister(self, operand):
        """x86: a memory operand with SIB byte whose index field names a register"""
        return bool(operand.specflag1) and ((operand.specflag2 >> 3) & 7) != 4

    def MakeDWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)

    def MakeQWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)

    def MakeName(self, ea, name):
        # an API referenced from several locations gets a numbered name at the further ones
        return ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_FORCE)

    def addTil(self, lib_name):
        return ida_typeinf.add_til(lib_name, ida_typeinf.ADDTIL_DEFAULT)
