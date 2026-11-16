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

from apiscout.ApiScout import ApiScout
from apiscout.IdaForm import IdaApiScoutOptionsForm
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
            if not self.ida_proxy.hasBytes(seg_start):
                # e.g. the uninitialized part of an image, there is nothing to scan
                block_start = None
                continue
            content = self.ida_proxy.getBytes(seg_start, seg_end - seg_start) or b""
            if block_start is not None and seg_start == block_end:
                result[block_start] += content
            else:
                block_start = seg_start
                result[block_start] = content
            block_end = seg_end
        return result

    def hasSegments(self):
        return any(True for _ in idautils.Segments())

    def getBaseAddress(self):
        return [ea for ea in idautils.Segments()][0]

    def getLastAddress(self):
        return self.ida_proxy.getSegEnd([ea for ea in idautils.Segments()][-1]) - 1

    def getBitness(self, api):
        match = re.search(r"\((?P<bitness>\d+)bit\)", api[2])
        return int(match.group("bitness")) if match else 0

    def makeDQWord(self, api, in_table=False):
        """turn the location of an API reference into a pointer sized data item, returns the reason if this is not possible"""
        bitness = self.getBitness(api)
        if bitness not in (32, 64):
            return "unknown pointer size"
        size = bitness // 8
        if self.ida_proxy.isData(api[0], size):
            return None
        blocking_item = self.ida_proxy.getBlockingItem(api[0], size, in_table)
        if blocking_item:
            return "part of " + blocking_item
        self.ida_proxy.undefine(api[0], size)
        created = self.ida_proxy.MakeDWord(api[0]) if bitness == 32 else self.ida_proxy.MakeQWord(api[0])
        return None if created else "no data item can be created here"

    def getApiName(self, api):
        match = re.match(r"None<(?P<ordinal>\d+)>$", str(api[3]))
        if match:
            # the API is exported by ordinal only, so the API DB has no name for it
            dll_name = re.sub(r"\W", "_", re.sub(r"(_0x[0-9a-fA-F]+)? \(\d+bit\)$", "", api[2]))
            return "{}_ordinal_{}".format(dll_name, match.group("ordinal"))
        return str(api[3])

    def makeNameAndStructure(self, api):
        return self.ida_proxy.MakeName(api[0], self.getApiName(api))

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
        operand = instruction.ops[0]
        if operand.type != ida_ua.o_mem or self.ida_proxy.hasIndexRegister(operand):
            # e.g. call table[reg*4], which only uses the location as start of a table
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

    def getResultRows(self, results):
        """
        unique API references over the results of all API DBs as rows [address, API address, DLL, API, references],
        without pointers into the database itself
        """
        base_address = self.getBaseAddress()
        rows = {}
        for entries in results.values():
            for entry in entries:
                if self.ida_proxy.isLoaded(entry[1]):
                    continue
                key = (base_address + entry[0], entry[1], f"{entry[2]} ({entry[4]}bit)", entry[3])
                rows[key] = max(rows.get(key, 0), entry[6] - 1)
        # the references known to IDA include those from other segments
        return [
            list(key) + [max(references, self.ida_proxy.getNumReferences(key[0]))]
            for key, references in sorted(rows.items())
        ]

    def filterByDistance(self, rows, distance):
        return ApiScout._getFilteredList(distance, rows)

    def applyApiNames(self, api_results, status=None):
        """annotate the given rows, a description of the outcome per address is stored in the optional dict status"""
        if status is None:
            status = {}
        num_renamed = 0
        num_skipped = 0
        num_xrefs_adapted = 0
        unresolved_types = set()

        prev_offset = 0
        locations = {api[0] for api in api_results}
        for api in sorted(api_results):
            if api[0] > prev_offset + 16:
                print(f"Annotating API Block @0x{api[0]:x}.")
            prev_offset = api[0]
            size = self.getBitness(api) // 8
            in_table = bool(size) and (api[0] - size in locations or api[0] + size in locations)
            reason = self.makeDQWord(api, in_table)
            if reason:
                num_skipped += 1
                status[api[0]] = "skipped: " + reason
                print(f"Skipping 0x{api[0]:x}: location of {self.getApiName(api)} is {reason}.")
                continue
            if not self.makeNameAndStructure(api):
                num_skipped += 1
                status[api[0]] = "skipped: name could not be set"
                print(f"Skipping 0x{api[0]:x}: could not set name {self.getApiName(api)}.")
                continue
            num_renamed += 1
            self.ida_proxy.grantUnknownPermissions(api[0])
            tinfo, success = self.helper_getTinfoOfFuncName(str(api[3]))
            if not success:
                status[api[0]] = "annotated (no type information)"
                unresolved_types.add(str(api[3]))
                continue
            status[api[0]] = "annotated"
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
