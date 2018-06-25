#!/usr/bin/python
########################################################################
# Copyright (c) 2018
# Steffen Enders <steffen<at>enders<dot>nrw>
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

from apiscout.ApiQR import ApiQR

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")


def get_this_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__)))

def get_winapi1024_path():
    return get_this_dir() + os.sep + "data" + os.sep + "winapi1024v1.txt"


def main():
    parser = argparse.ArgumentParser(description='Demo: Use apiscout to visualize WinApi1024 vectors as ApiQR.')
    parser.add_argument('vector', type=str, default='', help='compressed vector to export.')
    parser.add_argument('-w', '--web', type=str, default='', help='Path to output as html to.')
    parser.add_argument('-p', '--png', type=str, default='', help='Path to output as PNG to.')

    args = parser.parse_args()
    apiqr = ApiQR(get_winapi1024_path())
    # load WinApi1024 vector
    if args.vector and (args.web or args.png):
        apiqr.setVector(args.vector)
        if args.web:
            apiqr.exportHtml(args.web, full=True)
        if args.png:
            apiqr.exportPng(args.png)
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())
