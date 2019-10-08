#!/usr/bin/python
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

import argparse
import os
import sys
import re
import logging

from apiscout.ApiScout import ApiScout

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


def get_this_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__)))


def get_all_db_files():
    db_dir = get_this_dir() + os.sep + "dbs" + os.sep
    return [db_dir + fn for fn in os.listdir(db_dir) if fn.endswith(".json")]


def get_winapi1024_path():
    return get_this_dir() + os.sep + "apiscout" + os.sep + "data" + os.sep + "winapi1024v1.txt"


def get_base_addr(args):
    if args.base_addr:
        return int(args.base_addr, 16) if args.base_addr.startswith("0x") else int(args.base_addr)
    # try to infer from filename:
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), args.binary_path)
    if baddr_match:
        return int(baddr_match.group("base_addr"), 16)
    return 0


def main():
    parser = argparse.ArgumentParser(description='Demo: Use apiscout with a prepared api database (created using DatabaseBuilder.py) to crawl a dump for imports and render the results.')
    parser.add_argument('-f', '--filter', type=int, default=0, help='Filter out APIs that do not have a neighbour within N bytes (e.g. 32 or 2048).')
    parser.add_argument('-i', '--ignore_aslr', action='store_true', help='Do not apply the per-module ASLR offset potentially contained in a API DB file.')
    parser.add_argument('-c', '--collection_file', type=str, default='', help='Optionally match the output against a WinApi1024 vector collection file.')
    parser.add_argument('-b', '--base_addr', type=str, default='', help='Set base address to given value (int or 0x-hex format).')
    parser.add_argument('-t', '--import_table_only', action='store_true', help='Do not crawl for API references but only parse the import table instead - assumes an unmapped PE file as input.')
    parser.add_argument('binary_path', type=str, default='', help='Path to the memory dump to crawl.')
    parser.add_argument('db_path', type=str, nargs='*', help='Path to the DB(s). If no argument is given, use all files found in "./dbs"')

    args = parser.parse_args()
    if args.binary_path:
        binary = ""
        if os.path.isfile(args.binary_path):
            with open(args.binary_path, "rb") as f_binary:
                binary = f_binary.read()
        scout = ApiScout()
        base_addr = get_base_addr(args)
        print("Using base address 0x{:x} to infer reference counts.".format(base_addr))
        scout.setBaseAddress(base_addr)
        # override potential ASLR offsets that are stored in the API DB files.
        scout.ignoreAslrOffsets(args.ignore_aslr)
        # load DB file
        db_paths = []
        if args.db_path:
            db_paths = args.db_path
        elif not args.import_table_only:
            db_paths = get_all_db_files()
        for db_path in db_paths:
            scout.loadDbFile(db_path)
        # load WinApi1024 vector
        scout.loadWinApi1024(get_winapi1024_path())
        # scout the binary
        results = {}
        if args.import_table_only:
            print("Parsing Import Table for\n  {}.".format(args.binary_path))
            results = scout.evaluateImportTable(binary, is_unmapped=True)
        else:
            print("Using \n  {}\nto analyze\n  {}.".format("\n  ".join(db_paths), args.binary_path))
            num_apis_loaded = scout.getNumApisLoaded()
            filter_info = " - neighbour filter: 0x%x" % args.filter if args.filter else ""
            print("Buffer size is {} bytes, {} APIs loaded{}.\n".format(len(binary), num_apis_loaded, filter_info))
            results = scout.crawl(binary)
        filtered_results = scout.filter(results, 0, 0, args.filter)
        print(scout.render(filtered_results))
        print(scout.renderVectorResults(filtered_results))
        if args.collection_file:
            print(scout.renderResultsVsCollection(filtered_results, args.collection_file))
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())
