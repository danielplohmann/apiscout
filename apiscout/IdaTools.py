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
import os
import re

import ida_idp
import ida_nalt
import ida_typeinf
import ida_ua
import idautils

from apiscout.IdaForm import IdaApiScoutOptionsForm, IdaApiScoutResultsForm
from apiscout.IdaProxy import IdaProxy

LOG = logging.getLogger(__name__)


class IdaTools:
    TYPE_LIBRARIES = {
        32: ["wdk8_um", "mssdk_win7", "ntapi_win7"],
        64: ["mssdk64_win7", "ntapi64_win7"],
    }

    def __init__(self):
        self.ida_proxy = IdaProxy()

    def getAllMemoryFromIda(self):
        """returns the content of all segments, with adjacent segments merged into one buffer: {start address: bytes}"""
        result = {}
        block_start = None
        block_end = None
        for seg_start in idautils.Segments():
            seg_end = self.ida_proxy.getSegEnd(seg_start)
            content = self.ida_proxy.getBytes(seg_start, seg_end - seg_start) or b""
            if block_start is not None and seg_start == block_end:
                result[block_start] += content
            else:
                block_start = seg_start
                result[block_start] = content
            block_end = seg_end
        return result

    def getBaseAddress(self):
        return [ea for ea in idautils.Segments()][0]

    def getLastAddress(self):
        return self.ida_proxy.getSegEnd([ea for ea in idautils.Segments()][-1]) - 1

    def getBitness(self, api):
        match = re.search(r"\((?P<bitness>\d+)bit\)", api[2])
        return int(match.group("bitness")) if match else 0

    def makeDQWord(self, api):
        """turn the location of an API reference into a pointer sized data item, returns False if this is not possible"""
        bitness = self.getBitness(api)
        if bitness not in (32, 64):
            return False
        size = bitness // 8
        if self.ida_proxy.isData(api[0], size):
            return True
        if self.ida_proxy.isPartOfFunctionCode(api[0], size):
            # an API address within an instruction (e.g. an immediate operand), which must not be destroyed
            return False
        self.ida_proxy.undefine(api[0], size)
        if bitness == 32:
            return self.ida_proxy.MakeDWord(api[0])
        return self.ida_proxy.MakeQWord(api[0])

    def getApiName(self, api):
        match = re.match(r"None<(?P<ordinal>\d+)>$", str(api[3]))
        if match:
            # the API is exported by ordinal only, so the API DB has no name for it
            dll_name = re.sub(r"\W", "_", re.sub(r"(_0x[0-9a-fA-F]+)? \(\d+bit\)$", "", api[2]))
            return "{}_ordinal_{}".format(dll_name, match.group("ordinal"))
        return str(api[3])

    def makeNameAndStructure(self, api, suffix=None):
        name = self.getApiName(api)
        if suffix is not None:
            name += f"_{suffix}"
        return self.ida_proxy.MakeName(api[0], name)

    def importTypeLibraries(self):
        """load the type libraries matching the bitness of the database, returns True if all of them are available"""
        bitness = 64 if self.ida_proxy.is64bit() else 32
        results = [self.ida_proxy.addTil(lib_name) for lib_name in self.TYPE_LIBRARIES[bitness]]
        return all(result == 1 for result in results)

    def helper_getTinfoOfFuncName(self, funcName):
        tinfo = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        named_type = ida_typeinf.get_named_type(til, funcName, ida_typeinf.NTF_SYMM)
        if named_type is None:
            return tinfo, False
        if not tinfo.deserialize(til, named_type[1], named_type[2]) or not tinfo.is_func():
            return tinfo, False
        return tinfo, True

    def setFunctionInformation(self, funcName, callAddress):
        """apply the prototype of the API to a call instruction referencing it"""
        tinfo, success = self.helper_getTinfoOfFuncName(funcName)
        if not success:
            return False
        return self._applyCalleeType(tinfo, callAddress)

    def _applyCalleeType(self, tinfo, address):
        instruction = ida_ua.insn_t()
        if not ida_ua.decode_insn(instruction, address) or not ida_idp.is_call_insn(instruction):
            return False
        ida_typeinf.apply_callee_tinfo(address, tinfo)
        # the operand type makes the decompiler use the prototype for this indirect call
        return bool(ida_nalt.set_op_tinfo(address, 0, tinfo))

    def setPointerType(self, tinfo, address):
        """type the location of the API address as pointer to the API's prototype"""
        pointer_tinfo = ida_typeinf.tinfo_t()
        if not pointer_tinfo.create_ptr(tinfo):
            return False
        return bool(ida_typeinf.apply_tinfo(address, pointer_tinfo, ida_typeinf.TINFO_DEFINITE))

    def applyApiNames(self, api_results):
        num_renamed = 0
        num_skipped = 0
        num_xrefs_adapted = 0
        unresolved_types = set()

        prev_offset = 0
        for api in sorted(api_results):
            if api[0] > prev_offset + 16:
                print(f"Annotating API Block @0x{api[0]:x}.")
            prev_offset = api[0]
            if not self.makeDQWord(api):
                num_skipped += 1
                print(f"Skipping 0x{api[0]:x}: location of {self.getApiName(api)} is part of an instruction.")
                continue
            named = self.makeNameAndStructure(api)
            if not named:
                # the same API may be referenced from several locations
                for suffix in range(10):
                    named = self.makeNameAndStructure(api, suffix)
                    if named:
                        break
            if not named:
                num_skipped += 1
                print(f"Skipping 0x{api[0]:x}: could not set name {self.getApiName(api)}.")
                continue
            num_renamed += 1
            tinfo, success = self.helper_getTinfoOfFuncName(str(api[3]))
            if not success:
                unresolved_types.add(str(api[3]))
                continue
            self.setPointerType(tinfo, api[0])
            for xref in idautils.XrefsTo(api[0]):
                if self._applyCalleeType(tinfo, xref.frm):
                    num_xrefs_adapted += 1
        if unresolved_types:
            print(
                "No type information available for {} APIs: {}".format(
                    len(unresolved_types), ", ".join(sorted(unresolved_types))
                )
            )
        return num_renamed, num_skipped, num_xrefs_adapted

    def formGetParameters(self, db_folder=None):
        parameters = {}
        if db_folder is None:
            this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
            db_folder = os.path.abspath(os.path.join(this_dir, "..", "dbs"))
        form = IdaApiScoutOptionsForm(db_folder)
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            api_dbs = form.chosenValues
            if not api_dbs and os.path.isfile(form.iFileOpen.value):
                api_dbs = [form.iFileOpen.value]
            if api_dbs:
                parameters["api_dbs"] = api_dbs
                parameters["ignore_aslr_offset"] = form.rAslr.checked
            else:
                print("No API DB selected, nothing to do.")
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
