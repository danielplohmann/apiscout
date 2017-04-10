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

from apiscout.IdaTools import IdaTools
from apiscout.ApiScout import ApiScout


def main():
    tools = IdaTools()
    parameters = tools.formGetParameters()
    if parameters:
        scout = ApiScout()
        scout.ignoreAslrOffsets(parameters["ignore_aslr_offset"])
        scout.setBaseAddress(tools.getBaseAddress())
        binary = tools.getAllMemoryFromIda()
        for path in parameters["api_dbs"]:
            scout.loadDbFile(path)
        bitness_string = "32bit and 64bit" if scout.has_64bit else "32bit"
        print("Scanning %d bytes in %s mode." % (len(binary), bitness_string))
        results = scout.crawl(binary)
        selected_apis = tools.formSelectResults(results)
        if selected_apis:
            num_renamed, num_skipped = tools.applyApiNames(selected_apis)
            print("Annotated %d APIs (%d skipped)." % (num_renamed, num_skipped))
        else:
            print("No APIs selected for annotation, closing.")

main()
