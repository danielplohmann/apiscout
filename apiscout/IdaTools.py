########################################################################
# Copyright (c) 2020
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import logging
import os
import re

import ida_bytes
import ida_idp
import ida_nalt
import ida_netnode
import ida_typeinf
import ida_ua
import ida_xref
import idautils

from apiscout.ApiScout import ApiScout
from apiscout.IdaForm import IdaApiScoutOptionsForm
from apiscout.IdaProxy import IdaProxy

LOG = logging.getLogger(__name__)


class IdaTools:
    # the names and call types ApiScout set, so that those an analyst sets afterwards or before are kept
    ANNOTATIONS_NODE = "$ apiscout annotations"
    TAG_LOCATION = "L"
    TAG_CALL = "C"
    TYPE_LIBRARIES = {
        32: ["wdk8_um", "mssdk_win7", "ntapi_win7"],
        64: ["mssdk64_win7", "ntapi64_win7"],
    }

    def __init__(self):
        self.ida_proxy = IdaProxy()

    def getAllMemoryFromIda(self):
        """Returns the bytes that have a value in the database, adjacent parts merged into one buffer: {start address: bytes}."""
        result = {}
        block_start = None
        block_end = None
        for seg_start in idautils.Segments():
            seg_end = self.ida_proxy.getSegEnd(seg_start)
            for range_start, content in self.ida_proxy.getLoadedRanges(seg_start, seg_end - seg_start):
                if block_start is not None and range_start == block_end:
                    result[block_start] += content
                else:
                    block_start = range_start
                    result[block_start] = content
                block_end = range_start + len(content)
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
        """Turn the location of an API reference into a pointer sized data item, returns the reason if this is not possible."""
        bitness = self.getBitness(api)
        if bitness not in (32, 64):
            return "unknown pointer size"
        size = bitness // 8
        if self.ida_proxy.isData(api[0], size):
            return None
        blocking_item = self.ida_proxy.getBlockingItem(api[0], size, in_table)
        if blocking_item:
            return "part of " + blocking_item
        if self.ida_proxy.getSegEnd(api[0]) < api[0] + size:
            return "at the end of its segment"
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

    def _isApiName(self, name, api):
        """The name of the API, possibly with the numeric suffix IDA adds to a name used several times."""
        return bool(re.fullmatch(re.escape(self.getApiName(api)) + r"(_\d+)?", name or ""))

    def isAnnotated(self, api):
        """The location still carries the name ApiScout gave it for this API."""
        name = self.ida_proxy.getName(api[0])
        recorded = self._recorded(api[0], self.TAG_LOCATION)
        return self._isApiName(name, api) and (recorded is None or name == recorded)

    def makeNameAndStructure(self, api):
        return self.ida_proxy.MakeName(api[0], self.getApiName(api))

    def _annotations(self):
        return ida_netnode.netnode(self.ANNOTATIONS_NODE, 0, True)

    def _recorded(self, address, tag):
        """The name or call type ApiScout set at the address, None if it set none."""
        return self._annotations().supstr(address, tag)

    def _record(self, address, tag, value):
        self._annotations().supset(address, value, tag)

    def _getCallType(self, address):
        tinfo = ida_typeinf.tinfo_t()
        return str(tinfo) if ida_nalt.get_op_tinfo(tinfo, address, 0) else None

    def getAnalystName(self, api):
        """The name an analyst gave the location, None if it has none or it still is the name ApiScout set."""
        if not ida_bytes.has_user_name(ida_bytes.get_flags(api[0])):
            return None
        name = self.ida_proxy.getName(api[0])
        recorded = self._recorded(api[0], self.TAG_LOCATION)
        if recorded is not None:
            # renamed since ApiScout set its name, e.g. by an analyst
            return None if name == recorded else name
        # no name recorded, e.g. annotated by a version that did not record names
        return None if self._isApiName(name, api) else name

    def _hasAnalystCallType(self, address):
        """The call has a type that ApiScout did not set, or changed since, e.g. with "Set call type" of the decompiler."""
        current = self._getCallType(address)
        return current is not None and current != self._recorded(address, self.TAG_CALL)

    def importTypeLibraries(self):
        """Load the type libraries matching the bitness of the database, returns True if all of them are available."""
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
        """Apply the prototype of the API to a call instruction referencing it."""
        tinfo, success = self.helper_getTinfoOfFuncName(funcName)
        if not success:
            return False
        return any(
            self._applyCalleeType(tinfo, callAddress, location) for location in idautils.DataRefsFrom(callAddress)
        )

    def _applyCalleeType(self, tinfo, address, location):
        instruction = ida_ua.insn_t()
        if not ida_ua.decode_insn(instruction, address) or not ida_idp.is_call_insn(instruction):
            return False
        operand = instruction.ops[0]
        # the address of the operand is relative to its segment base, IDA 9.0 needs a data segment register for that
        if operand.type != ida_ua.o_mem or location not in (operand.addr, ida_ua.map_data_ea(instruction, operand)):
            return False
        if self.ida_proxy.hasIndexRegister(instruction, operand):
            # e.g. call table[reg*4], which only uses the location as start of a table
            return False
        if self._hasAnalystCallType(address):
            return False
        ida_typeinf.apply_callee_tinfo(address, tinfo)
        # the operand type makes the decompiler use the prototype for this indirect call
        if not ida_nalt.set_op_tinfo(address, 0, tinfo):
            return False
        self._record(address, self.TAG_CALL, self._getCallType(address))
        return True

    def setPointerType(self, tinfo, address):
        """Type the location of the API address as pointer to the API's prototype."""
        pointer_tinfo = ida_typeinf.tinfo_t()
        if not pointer_tinfo.create_ptr(tinfo):
            return False
        return bool(ida_typeinf.apply_tinfo(address, pointer_tinfo, ida_typeinf.TINFO_DEFINITE))

    def getResultRows(self, results):
        """Unique API references over the results of all API DBs, without pointers into the database itself.

        Rows of [address, API address, DLL, API, references].
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

    def applyApiNames(self, api_results, status=None, known_locations=None):
        """Annotate the given rows, a description of the outcome per row is stored in the optional dict status.

        known_locations are the locations of all API references found, also of those that are not annotated now.
        """
        if status is None:
            status = {}
        num_renamed = 0
        num_skipped = 0
        num_xrefs_adapted = 0
        unresolved_types = set()

        prev_offset = 0
        locations = known_locations if known_locations is not None else {api[0] for api in api_results}
        annotated_locations = {}
        # pointers annotated earlier or in this run as {location: (API name, size)}, which a later row must not cut
        pointers = {
            key[0]: (self.getApiName(key), self.getBitness(key) // 8, key)
            for key, outcome in status.items()
            if outcome.startswith("annotated")
        }
        # of several rows for one location, the one of the database's pointer size is applied
        pointer_bits = 64 if self.ida_proxy.is64bit() else 32
        for api in sorted(api_results, key=lambda api: (api[0], self.getBitness(api) != pointer_bits, api[1:4])):
            if api[0] > prev_offset + 16:
                print(f"Annotating API Block @0x{api[0]:x}.")
            prev_offset = api[0]
            if api[0] in annotated_locations:
                # several API DBs can resolve one location differently, the first one listed is applied
                num_skipped += 1
                status[tuple(api[:4])] = "skipped: location is annotated as " + annotated_locations[api[0]]
                print(f"Skipping 0x{api[0]:x}: location is annotated as {annotated_locations[api[0]]} already.")
                continue
            size = self.getBitness(api) // 8
            in_table = bool(size) and (api[0] - size in locations or api[0] + size in locations)
            overlapped = [
                pointers[location][0]
                for location in range(api[0] - 7, api[0] + size)
                if location != api[0] and location in pointers and location + pointers[location][1] > api[0]
            ]
            analyst_name = self.getAnalystName(api)
            if overlapped:
                reason = "overlapping " + overlapped[0]
            elif analyst_name:
                # the name and type an analyst gave the location are kept
                reason = f"named {analyst_name} by hand"
            else:
                reason = self.makeDQWord(api, in_table)
            if reason:
                num_skipped += 1
                status[tuple(api[:4])] = "skipped: " + reason
                print(f"Skipping 0x{api[0]:x}: location of {self.getApiName(api)} is {reason}.")
                continue
            if not self.makeNameAndStructure(api):
                num_skipped += 1
                status[tuple(api[:4])] = "skipped: name could not be set"
                print(f"Skipping 0x{api[0]:x}: could not set name {self.getApiName(api)}.")
                continue
            num_renamed += 1
            # the name as IDA stored it, which can carry a suffix
            self._record(api[0], self.TAG_LOCATION, self.ida_proxy.getName(api[0]))
            annotated_locations[api[0]] = self.getApiName(api)
            if api[0] in pointers and pointers[api[0]][2] != tuple(api[:4]):
                # another row of this location was annotated before, its name is replaced now
                status[pointers[api[0]][2]] = "skipped: location is annotated as " + self.getApiName(api)
            pointers[api[0]] = (self.getApiName(api), size, tuple(api[:4]))
            self.ida_proxy.makeSegmentWritable(api[0])
            tinfo, success = self.helper_getTinfoOfFuncName(str(api[3]))
            if not success:
                status[tuple(api[:4])] = "annotated (no type information)"
                unresolved_types.add(str(api[3]))
                continue
            status[tuple(api[:4])] = "annotated"
            self.setPointerType(tinfo, api[0])
            for xref in idautils.XrefsTo(api[0], ida_xref.XREF_FAR):
                if self._applyCalleeType(tinfo, xref.frm, api[0]):
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
            api_dbs = list(form.chosenValues)
            other_db = form.iFileOpen.value
            if other_db and os.path.isfile(other_db) and os.path.abspath(other_db) not in map(os.path.abspath, api_dbs):
                api_dbs.append(other_db)
            if api_dbs:
                parameters["api_dbs"] = api_dbs
                parameters["ignore_aslr_offset"] = form.rAslr.checked
                parameters["modules"] = form.iModules.value.strip() or None
            else:
                print("No API DB selected, nothing to do.")
        form.Free()
        return parameters
