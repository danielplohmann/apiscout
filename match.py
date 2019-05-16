#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# Steffen Enders <steffen<at>enders<dot>nrw>
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
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")


def get_this_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__)))

def get_winapi1024_path():
    return get_this_dir() + os.sep + "apiscout" + os.sep +  "data" + os.sep + "winapi1024v1.txt"


def main():
    parser = argparse.ArgumentParser(description='Demo: Use apiscout to match WinApi1024 vectors.')
    parser.add_argument('vector_a', type=str, default='', help='compressed version of first vector.')
    parser.add_argument('-v', '--vector_b', type=str, default='', help='compressed version of second vector.')
    parser.add_argument('-c', '--collection', type=str, default='', help='Path to a collection of compressed vectors.')
    parser.add_argument('-n', '--max_results', type=int, default=5, help='Maximum number of family results to show.')

    args = parser.parse_args()
    scout = ApiScout()
    # load WinApi1024 vector
    scout.loadWinApi1024(get_winapi1024_path())
    if args.vector_a and args.vector_b:
        score = scout.matchVectors(args.vector_a, args.vector_b)
        print("Result of matching vectors:")
        print("Vector A: {}".format(args.vector_a))
        print("Vector B: {}".format(args.vector_b))
        print("Score: {}".format(score))
    elif args.vector_a and args.collection:
        collection_result = scout.matchVectorCollection(args.vector_a, args.collection)
        print(scout.renderVectorCollectionResults(collection_result, args.max_results))
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())
