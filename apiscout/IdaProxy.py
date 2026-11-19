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

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_offset
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
        """The parts of a range that have a value in the database as list of (address, bytes)."""
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

    def getName(self, ea):
        return ida_name.get_name(ea) or ""

    def getNumReferences(self, ea):
        # without the ordinary flow from the preceding instruction
        return sum(1 for _ in idautils.XrefsTo(ea, ida_xref.XREF_FAR))

    def getBytes(self, ea, size):
        return ida_bytes.get_bytes(ea, size)

    def getSegEnd(self, ea):
        return ida_segment.getseg(ea).end_ea

    def getBlockingItem(self, ea, size, in_table):
        """Describes the item that must not be replaced by a pointer at this location, None if there is no such item.

        Code of a function is always kept. Other code is only given up for a location that is referenced as data or lies
        in a table of API addresses, which IDA may have disassembled. Structures are kept as a whole.
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
        """Make the segment at ea writable, so the decompiler shows calls through its API pointers as API calls.

        The decompiler treats the content of a segment that is not writable as constant and shows calls through API
        pointers as calls to numbers. Segments of a dump loaded as binary file carry no permissions at all and get all
        of them, other segments (e.g. .rdata) become writable in addition. False if there is no segment or it is
        writable already.
        """
        segment = ida_segment.getseg(ea)
        if segment is None or segment.perm & ida_segment.SEGPERM_WRITE:
            return False
        if segment.perm == 0:
            segment.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE | ida_segment.SEGPERM_EXEC
        else:
            segment.perm |= ida_segment.SEGPERM_WRITE
        return segment.update()

    def getSegmentsWithBase(self):
        return [start for start in idautils.Segments() if ida_segment.get_segm_base(ida_segment.getseg(start)) != 0]

    def useFlatAddresses(self):
        """Set the segment base of a binary file loaded with one to 0, returns the affected segments.

        A binary file loaded with a segment base (-b on the command line) has code whose operands are taken relative to
        that base, so its calls do not reference the API pointers. The base is set to 0 as for a flat image. What an
        analysis under the base left behind is repaired.
        """
        changed = []
        old_bases = set()
        # All bases first, the analysis of one segment follows references into the others. For a database that
        # was just created, this is before its first analysis, which is then made for the flat image.
        for start in self.getSegmentsWithBase():
            segment = ida_segment.getseg(start)
            old_base = ida_segment.get_segm_base(segment)
            if ida_segment.set_selector(segment.sel, 0):
                changed.append(start)
                old_bases.add(old_base)
        ida_auto.auto_wait()
        for start in changed:
            end = self.getSegEnd(start)
            # calls that led to no code under the base made their functions end early
            for function_start in idautils.Functions(start, end):
                function = ida_funcs.get_func(function_start)
                if function.flags & ida_funcs.FUNC_NORET:
                    function.flags &= ~ida_funcs.FUNC_NORET
                    ida_funcs.update_func(function)
            # the references of instructions are only taken anew when they are decoded again
            for head in idautils.Heads(start, end):
                if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                    self._rebaseOffsets(head, old_bases)
                    ida_auto.auto_recreate_insn(head)
            ida_auto.plan_range(start, end)
        if changed:
            ida_auto.auto_wait()
            functions = [ea for start in changed for ea in idautils.Functions(start, self.getSegEnd(start))]
            for function_start in functions:
                ida_funcs.reanalyze_function(ida_funcs.get_func(function_start))
            ida_auto.auto_wait()
            for function_start in functions:
                ida_funcs.reanalyze_noret_flag(function_start)
            ida_auto.auto_wait()
            for function_start in functions:
                function = ida_funcs.get_func(function_start)
                if self._hasNoreturnPrototype(function_start) and not function.flags & ida_funcs.FUNC_NORET:
                    function.flags |= ida_funcs.FUNC_NORET
                    ida_funcs.update_func(function)
            # IDA 9.5 creates part of the offsets with the former base again
            for start in changed:
                for head in idautils.Heads(start, self.getSegEnd(start)):
                    if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                        self._rebaseOffsets(head, old_bases)
            ida_auto.auto_wait()
        return changed

    def _hasNoreturnPrototype(self, ea):
        tinfo = ida_typeinf.tinfo_t()
        details = ida_typeinf.func_type_data_t()
        return ida_nalt.get_tinfo(tinfo, ea) and tinfo.get_func_details(details) and details.is_noret()

    def _rebaseOffsets(self, head, bases):
        """Offset operands that were created relative to a segment base would point behind their target."""
        flags = ida_bytes.get_full_flags(head)
        refinfo = ida_nalt.refinfo_t()
        for operand in range(ida_ida.UA_MAXOP):
            is_offset = ida_bytes.is_off(flags, operand) and ida_nalt.get_refinfo(refinfo, head, operand)
            # offsets relative to the image base (e.g. of jump tables) are meant to have that base
            if is_offset and refinfo.base in bases and not refinfo.flags & ida_nalt.REFINFO_NOBASE:
                refinfo.base = 0
                ida_offset.op_offset_ex(head, operand, refinfo)

    def undefine(self, ea, size):
        """Releases the items in the range, arrays reaching into it keep their elements outside of it."""
        arrays = []
        for address in (ea, ea + size - 1):
            head = ida_bytes.get_item_head(address)
            flags = ida_bytes.get_full_flags(head)
            item_end = ida_bytes.get_item_end(head)
            element_size = ida_bytes.get_data_elsize(head, flags) if ida_bytes.is_data(flags) else 0
            if 0 < element_size < item_end - head and not ida_bytes.is_struct(flags):
                string_type = ida_nalt.get_str_type(head) if ida_bytes.is_strlit(flags) else None
                if (head, item_end, flags, element_size, string_type) not in arrays:
                    arrays.append((head, item_end, flags, element_size, string_type))
            ida_bytes.del_items(head, ida_bytes.DELIT_SIMPLE)
        result = ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        for head, item_end, flags, element_size, string_type in arrays:
            for start, end in ((head, min(ea, item_end)), (max(ea + size, head), item_end)):
                start += -(start - head) % element_size
                length = (end - start) // element_size * element_size
                if length <= 0:
                    continue
                if string_type is not None:
                    ida_bytes.create_strlit(start, length, string_type)
                else:
                    ida_bytes.create_data(start, flags & ida_bytes.DT_TYPE, length, ida_idaapi.BADADDR)
        return result

    def isData(self, ea, size):
        flags = ida_bytes.get_full_flags(ea)
        return ida_bytes.is_head(flags) and ida_bytes.is_data(flags) and ida_bytes.get_item_size(ea) == size

    def hasIndexRegister(self, instruction, operand):
        """x86: a memory operand with SIB byte whose index field (extended by REX.X) names a register."""
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
