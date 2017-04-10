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
import logging

from apiscout.ApiScout import ApiScout

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")


def get_all_db_files():
    this_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    db_dir = this_dir + os.sep + "dbs" + os.sep
    return [db_dir + fn for fn in os.listdir(db_dir)]

def main():
    parser = argparse.ArgumentParser(description='Demo: Use apiscout with a prepared api database (created using DatabaseBuilder.py) to crawl a dump for imports and render the results.')
    parser.add_argument('-f', '--filter', type=int, default=0, help='Filter out APIs that do not have a neighbour within N bytes.')
    parser.add_argument('-i', '--ignore_aslr', action='store_true', help='Do not apply the per-module ASLR offset potentially contained in a API DB file.')
    parser.add_argument('binary_path', type=str, default='', help='Path to the memory dump to crawl.')
    parser.add_argument('db_path', type=str, nargs='*', help='Path to the DB(s). If no argument is given, use all files found in "./dbs"')

    args = parser.parse_args()
    if args.binary_path:
        binary = ""
        if os.path.isfile(args.binary_path):
            with open(args.binary_path, "rb") as f_binary:
                binary = f_binary.read()
        if not args.db_path:
            args.db_path = get_all_db_files()
        scout = ApiScout()
        # override potential ASLR offsets that are stored in the API DB files.
        scout.ignoreAslrOffsets(args.ignore_aslr)
        # load DB file
        for db_path in args.db_path:
            scout.loadDbFile(db_path)
        print("Using '{}' to analyze '{}.".format(args.db_path, args.binary_path))
        num_apis_loaded = scout.getNumApisLoaded()
        filter_info = " - neighbour filter: 0x%x" % args.filter if args.filter else ""
        print("Buffer size is {} bytes, {} APIs loaded{}.\n".format(len(binary), num_apis_loaded, filter_info))
        results = scout.crawl(binary)
        filtered_results = scout.filter(results, 0, 0, args.filter)
        print(scout.render(filtered_results))
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())
