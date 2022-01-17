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
########################################################################

import os
import sys

from apiscout.IdaTools import IdaTools
from apiscout.ApiScout import ApiScout


def updateResults(results, new_results):
    for key in new_results:
        if not key in results:
            results[key] = new_results[key]
        else:
            merged_results = results[key]
            merged_results.extend(new_results[key])
            results[key] = merged_results


def main():
    this_file = os.path.abspath(__file__)
    this_dir = os.path.abspath(os.path.join(os.path.dirname(this_file)))
    db_folder = os.path.abspath(os.path.join(this_dir, "dbs"))
    tools = IdaTools()
    parameters = tools.formGetParameters(db_folder)
    if parameters:
        scout = ApiScout()
        scout.ignoreAslrOffsets(parameters["ignore_aslr_offset"])
        for path in parameters["api_dbs"]:
            scout.loadDbFile(path)
        bitness_string = "32bit and 64bit" if scout.has_64bit else "32bit"
        segments = tools.getAllMemoryFromIda()
        base_address = tools.getBaseAddress()
        all_results = {}
        for segment_address, binary in sorted(segments.items()):
            scout.setLoadOffset(segment_address - base_address)
            print("Scanning %d bytes @0x%x in %s mode." % (len(binary), segment_address, bitness_string))
            updateResults(all_results, scout.crawl(binary))
        selected_apis = tools.formSelectResults(all_results)
        if selected_apis:
            tools.importTypeLibraries()
            num_renamed, num_skipped, num_xrefs_adapted = tools.applyApiNames(selected_apis)
            print("Annotated %d APIs and adapted %d Xrefs(%d skipped)." % (num_renamed, num_xrefs_adapted, num_skipped))
        else:
            print("No APIs selected for annotation, closing.")
    return 0


if __name__ == "__main__":
    main()
