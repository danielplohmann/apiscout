########################################################################
# Copyright (c) 2017
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
import operator
import os
import re
import sys

from apiscout.IdaForm import IdaApiScoutOptionsForm, IdaApiScoutResultsForm

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")

try:
    from idaapi import *
    import idc
    import idautils
    import idaapi
    import ida_bytes
    if idaapi.IDA_SDK_VERSION < 700:
        from idaapi import set_op_tinfo2 as set_op_tinfo
    else:
        from ida_nalt import set_op_tinfo
except:
    LOG.error("could not import IDA python packages - probably being used externally")



def lrange(num1, num2=None, step=1):
    """
    Allows iteration over arbitrary numbers instead of dword long numbers.
    Credits go to:
    http://stackoverflow.com/questions/2187135/range-and-xrange-for-13-digit-numbers-in-python
    http://stackoverflow.com/users/263162/ricardo-cardenes
    """
    op = operator.__lt__

    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2

    while op(num1, num2):
        yield num1
        num1 += step


class IdaTools(object):

    def getAllMemoryFromIda(self):
        result = {}
        seg_start = [ea for ea in idautils.Segments()][0]
        current_start = seg_start
        seg_end = idc.get_segm_end(current_start)
        current_buffer = ""
        for index, current_start in enumerate(idautils.Segments()):
            # get current buffer content
            current_buffer = ""
            for ea in lrange(current_start, idc.get_segm_end(current_start)):
                current_buffer += chr(idc.get_wide_byte(ea))
            # first buffer is only saved
            if index == 0:
                result[seg_start] = current_buffer
                continue
            # otherwise decide if the buffers are consecutive and either save or update contents
            if current_start != seg_end:
                seg_start = current_start
                result[seg_start] = current_buffer
            else:
                result[seg_start] += current_buffer
            seg_end = idc.get_segm_end(current_start)
        # convert to bytes
        if sys.version_info > (3,):
            for segment_offset, data in result.items():
                if isinstance(data, str):
                    result[segment_offset] = bytes([ord(c) for c in data])
        return result

    def getBaseAddress(self):
        return [ea for ea in idautils.Segments()][0]

    def getLastAddress(self):
        return idc.get_segm_end([ea for ea in idautils.Segments()][-1]) - 1

    def makeDQWord(self, api):
        match = re.search(r"\((?P<bitness>..)bit\)", api[2])
        if match:
            bitness = int(match.group("bitness"))
        if bitness == 32:
            ida_bytes.create_data(api[0], FF_DWORD, 4, idaapi.BADADDR)
        elif bitness == 64:
            ida_bytes.create_data(api[0], FF_QWORD, 8, idaapi.BADADDR)

    def makeNameAndStructure(self, api, suffix=None):
        if suffix is not None:
            named = idc.set_name(api[0], str(api[3] + "_{}".format(suffix)), 256)
        else:
            named = idc.set_name(api[0], str(api[3]), 256)
        self.makeDQWord(api)
        return named

    def importTypeLibraries(self):
        if add_til("wdk8_um", idaapi.ADDTIL_DEFAULT) != 1 or add_til("mssdk_win7", idaapi.ADDTIL_DEFAULT) != 1:
            return False
        return True

    def helper_getTinfoOfFuncName(self, funcName):
        try:
            sym = til_symbol_t()
            sym.til = cvar.idati
            sym.name = funcName
            tinfo = idaapi.tinfo_t()
            namedType = get_named_type(sym.til, sym.name, 0)
            if namedType == None:
                return tinfo, False
            tinfo.deserialize(sym.til, namedType[1], namedType[2])
            return tinfo, True
        except:
            return None, False

    def setFunctionInformation(self, funcName, callAddress):
        tinfo, success = self.helper_getTinfoOfFuncName(funcName)
        if not success:
            print("Error: Cannot resolve function %s - maybe the correct type library is not yet imported?" % (funcName))
            return False
        errorCode = apply_callee_tinfo(callAddress, tinfo) #in IDA 6.9 this returns <type 'NoneType'>, in IDA 7.1 it is "True"
        success = set_op_tinfo(callAddress, 0, tinfo)
        if errorCode not in [None, True] or not success:
            return False
        return True

    def applyApiNames(self, api_results):
        num_renamed = 0
        num_skipped = 0
        num_xrefs_adapted = 0

        prev_offset = 0
        for api in sorted(api_results):
            if api[0] > prev_offset + 16:
                print("Annotating API Block @0x{:x}.".format(api[0]))
            prev_offset = api[0]
            if str(api[3]) == "None":
                num_skipped += 1
                print("Skipping 0x{:x}: no name provided by API DB (is None).".format(api[0]))
                self.makeDQWord(api)
                continue
            named = self.makeNameAndStructure(api)
            if not named:
                for suffix in range(10):
                    print("naming 0x{:x} to {} failed, trying with suffix \"_{}\".".format(api[0], str(api[3]), suffix))
                    named = self.makeNameAndStructure(api, suffix)
                    if named:
                        break
                    else:
                        print("  naming 0x{:x} to {} failed as well, trying next index...".format(api[0], str(api[3] + "_{}".format(suffix))))
            if named:
                num_renamed += 1
                for xref in idautils.XrefsTo(api[0]):
                    if self.setFunctionInformation(api[3], xref.frm):
                        num_xrefs_adapted += 1
        return num_renamed, num_skipped, num_xrefs_adapted

    def formGetParameters(self):
        parameters = {}
        this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        db_folder = os.path.abspath(os.path.join(this_dir, "..", "dbs"))

        form = IdaApiScoutOptionsForm(db_folder)
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            if form.chosenValues:
                parameters["api_dbs"] = form.chosenValues
            else:
                parameters["api_dbs"] = [form.iFileOpen.value]
            parameters["ignore_aslr_offset"] = form.rAslr.checked
        form.Free()
        return parameters

    def formSelectResults(self, results):
        selected_apis = []

        form = IdaApiScoutResultsForm(results, self.getBaseAddress(), self.getLastAddress())
        form.Compile()
        ok = form.Execute()
        if ok == 1 and form.chosenApis:
            selected_apis = form.chosenApis
        form.Free()
        return selected_apis

