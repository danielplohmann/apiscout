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

import logging

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")

try:
    from idaapi import *
    import idc
    import idautils
    import idaapi
    if idaapi.IDA_SDK_VERSION >= 700:
        import ida_bytes
except:
    print("could not import IDA python packages - probably being used externally")
    raise



class IdaProxy(object):

    def getByte(self, ea):
        if idaapi.IDA_SDK_VERSION < 700:
            return idc.Byte(ea)
        else:
            return idc.get_wide_byte(ea)

    def getSegEnd(self, ea):
        if idaapi.IDA_SDK_VERSION < 700:
            return idc.SegEnd(ea)
        else:
            return idc.get_segm_end(ea)

    def MakeDWord(self, ea):
        if idaapi.IDA_SDK_VERSION < 700:
            return idc.MakeDword(ea)
        else:
            return ida_bytes.create_data(ea, FF_DWORD, 4, idaapi.BADADDR)

    def MakeQWord(self, ea):
        if idaapi.IDA_SDK_VERSION < 700:
            return idc.MakeQword(ea)
        else:
            return ida_bytes.create_data(ea, FF_QWORD, 8, idaapi.BADADDR)

    def MakeName(self, ea, name):
        if idaapi.IDA_SDK_VERSION < 700:
            return idc.MakeNameEx(ea, name, 256)
        else:
            return idc.set_name(ea, name, 256)

    def addTil(self, lib_name):
        if idaapi.IDA_SDK_VERSION < 700:
            return add_til(lib_name)
        else:
            return add_til(lib_name, idaapi.ADDTIL_DEFAULT)
