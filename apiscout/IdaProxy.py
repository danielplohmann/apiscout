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


class IdaProxy:
    """Thin wrapper around the IDA API (IDA 7.4 and later, including IDA 9)"""

    def is64bit(self):
        return ida_ida.inf_is_64bit()

    def getBytes(self, ea, size):
        return ida_bytes.get_bytes(ea, size)

    def getSegEnd(self, ea):
        return ida_segment.getseg(ea).end_ea

    def isPartOfFunctionCode(self, ea, size):
        for address in range(ea, ea + size):
            if ida_bytes.is_code(ida_bytes.get_full_flags(ida_bytes.get_item_head(address))) and ida_funcs.get_func(
                address
            ):
                return True
        return False

    def undefine(self, ea, size):
        # also releases an item that starts in front of ea and reaches into the range
        ida_bytes.del_items(ida_bytes.get_item_head(ea), ida_bytes.DELIT_SIMPLE)
        return ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)

    def isData(self, ea, size):
        flags = ida_bytes.get_full_flags(ea)
        return ida_bytes.is_head(flags) and ida_bytes.is_data(flags) and ida_bytes.get_item_size(ea) == size

    def MakeDWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)

    def MakeQWord(self, ea):
        return ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, ida_idaapi.BADADDR)

    def MakeName(self, ea, name):
        return ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)

    def addTil(self, lib_name):
        return ida_typeinf.add_til(lib_name, ida_typeinf.ADDTIL_DEFAULT)
