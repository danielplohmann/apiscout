#!/usr/bin/python
# ########################################################################
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

import os
import sys
import traceback

import ida_auto
import ida_idaapi
import ida_kernwin
import ida_pro
import idc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apiscout.ApiScout import ApiScout  # noqa: E402
from apiscout.IdaForm import ApiResultsAction, ApiResultsChooser, loadIcon  # noqa: E402
from apiscout.IdaTools import IdaTools  # noqa: E402

RESULTS_VIEW = None


def updateResults(results, new_results):
    for key in new_results:
        if key not in results:
            results[key] = new_results[key]
        else:
            merged_results = results[key]
            merged_results.extend(new_results[key])
            results[key] = merged_results


def crawl(tools, api_dbs, ignore_aslr_offsets=False):
    scout = ApiScout()
    scout.ignoreAslrOffsets(ignore_aslr_offsets)
    for path in api_dbs:
        scout.loadDbFile(path)
    bitness_string = "32bit and 64bit" if scout.has_64bit else "32bit"
    base_address = tools.getBaseAddress()
    all_results = {}
    for segment_address, binary in sorted(tools.getAllMemoryFromIda().items()):
        scout.setLoadOffset(segment_address - base_address)
        # code references are resolved relative to the buffer they are found in
        scout.setBaseAddress(segment_address)
        print(f"Scanning {len(binary)} bytes @0x{segment_address:x} in {bitness_string} mode.")
        updateResults(all_results, scout.crawl(binary))
    return tools.getResultRows(all_results)


def askNeighbourhood(chooser, selection):
    distance = ida_kernwin.ask_long(0x800, "Maximum distance in bytes to the next API (0 shows all APIs)")
    if distance is not None:
        chooser.filterByNeighbourhood(distance)


def registerActions(chooser):
    actions = [
        (
            chooser.ACTION_ANNOTATE,
            "Annotate selected APIs",
            "A",
            "annotated",
            lambda view, selection: view.annotate(selection),
        ),
        (
            chooser.ACTION_ANNOTATE_ALL,
            "Annotate all APIs of the view",
            "Shift-A",
            "annotated",
            lambda view, _: view.annotate(range(len(view.rows))),
        ),
        (chooser.ACTION_FILTER, "Filter by neighbourhood...", "F", "filter", askNeighbourhood),
    ]
    for name, label, shortcut, icon, callback in actions:
        ida_kernwin.unregister_action(name)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                name, label, ApiResultsAction(chooser, callback), shortcut, label, loadIcon("icon_" + icon)
            )
        )


def isBatchMode():
    return bool(ida_kernwin.cvar.batch) or not ida_kernwin.is_idaq()


def main(api_dbs=None):
    """
    Interactive: ask for the API DBs and list the API references found in a view, from which they are annotated.
    Batch mode (idat -A -S"ida_scout.py <API DB> ..."): annotate all API references found with the given API DBs.
    """
    tools = IdaTools()
    if not tools.hasSegments():
        print("ApiScout: the database has no segments, nothing to scan.")
        return 1
    if isBatchMode():
        api_dbs = api_dbs or idc.ARGV[1:]
        if not api_dbs:
            print("ApiScout: no API DB given, nothing to do.")
            return 1
        for segment_address in tools.ida_proxy.useFlatAddresses():
            print(f"ApiScout: segment @0x{segment_address:x} had a segment base, which was set to 0.")
        rows = crawl(tools, api_dbs)
        tools.importTypeLibraries()
        num_renamed, num_skipped, num_xrefs_adapted = tools.applyApiNames(rows)
        print(f"Annotated {num_renamed} APIs and adapted {num_xrefs_adapted} Xrefs ({num_skipped} skipped).")
        return 0
    db_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dbs")
    for segment_address in tools.ida_proxy.getSegmentsWithBase():
        print(
            f"ApiScout: segment @0x{segment_address:x} has a segment base, its code does not reference the API "
            "pointers. Load the dump with a loading offset instead (loading segment 0)."
        )
    parameters = tools.formGetParameters(db_folder)
    if not parameters:
        return 0

    def rescan():
        return crawl(tools, parameters["api_dbs"], parameters["ignore_aslr_offset"])

    rows = rescan()
    if not rows:
        print("ApiScout: no API references found.")
        return 0
    # the view is not modal, so it has to outlive this function
    global RESULTS_VIEW
    # IDA would keep showing an open view of an earlier run under the same title, while the actions of the new
    # one apply the selection made there to the new rows
    if RESULTS_VIEW is not None:
        RESULTS_VIEW.Close()
    widget = ida_kernwin.find_widget(ApiResultsChooser.TITLE)
    if widget is not None:
        ida_kernwin.close_widget(widget, 0)
    RESULTS_VIEW = ApiResultsChooser(tools, rows, rescan)
    registerActions(RESULTS_VIEW)
    RESULTS_VIEW.show()
    print(f"ApiScout: {len(rows)} API references found, use the context menu of the ApiScout view to annotate them.")
    return 0


class ApiScoutPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        main()
        return True


class ApiScoutPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Recover Windows API references from memory dumps"
    help = "Lists references to Windows APIs found with an ApiScout API DB and annotates them"
    wanted_name = "ApiScout"
    wanted_hotkey = "Ctrl-Alt-A"

    def init(self):
        return ApiScoutPlugmod()


def PLUGIN_ENTRY():
    return ApiScoutPlugin()


if __name__ == "__main__":
    if isBatchMode() and idc.ARGV[1:]:
        # run with -S and API DBs: IDA 9.0 does not leave on its own and would not save the database
        try:
            exit_code = main()
        except Exception:
            traceback.print_exc()
            exit_code = 1
        ida_auto.auto_wait()
        ida_pro.qexit(exit_code)
    else:
        main()
