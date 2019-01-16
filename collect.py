#!/usr/bin/python
########################################################################
# Copyright (c) 2018
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
import datetime
import os
import sys
import logging
from multiprocessing import Pool, cpu_count

from apiscout.FingerprintCrawler import FingerprintCrawler

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")




def get_this_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__)))


def get_all_db_files():
    db_dir = get_this_dir() + os.sep + "dbs" + os.sep
    return [db_dir + fn for fn in os.listdir(db_dir) if fn.endswith(".json")]


def get_winapi1024_path():
    return get_this_dir() + os.sep + "apiscout" + os.sep + "data" + os.sep + "winapi1024v1.txt"
    

def get_file_list(root_path, required_part):
    file_list = []
    for root, subdir, files in os.walk(root_path):
        for filename in files:
            if required_part and required_part not in filename:
                continue
            file_list.append(os.path.join(root, filename))
    return file_list
    

def main():
    parser = argparse.ArgumentParser(description='Demo: Create a WinApi1024 fingerprint database.')
    parser.add_argument('root_path', type=str, default='', help='Directory to crawl recursively for building the database (malpedia folder structure assumed).')
    parser.add_argument('-f', '--filter_size', type=int, default=32, help='Filter out APIs that do not have a neighbour within N bytes (default: 32).')
    parser.add_argument('-r', '--path_require', type=str, default='', help='A string that files should contain in order to be considered for crawling (e.g. "_dump" for malpedia files).')
    parser.add_argument('-o', '--output_path', type=str, default='', help='Optionally save the fingerprint file to this location (instead of "./dbs/<YYYY-MM-DD>-winapi1024.csv".')
    parser.add_argument('-u', '--update_path', type=str, default='', help='Instead of generating a fingerprint database from scratch, load and update an existing file (add new entries only).')
    parser.add_argument('-i', '--ignore_empty', action='store_true', help='Do not store information for empty fingerprints.')

    args = parser.parse_args()
    if args.root_path and os.path.isdir(args.root_path):
        fingerprints = []
        crawler = FingerprintCrawler(get_all_db_files(), get_winapi1024_path(), args.root_path, args.filter_size)
        if args.update_path and os.path.isfile(args.update_path):
            crawler.loadIgnoreList(args.update_path)
        file_list = get_file_list(args.root_path, args.path_require)
        logging.info("Located {} crawlable files for ApiScout, {}/{} can be ignored.".format(crawler.getNumberOfCrawlableFiles(file_list), crawler.getNumberOfIgnorableFiles(file_list), len(file_list)))
        if sys.version_info >= (3,):
            with Pool(cpu_count()) as pool:
                fingerprints.extend(pool.map(crawler.getFingerprint, file_list))
        else:
            logging.warn("Using Python2 disables support for parallel processing")
            for filepath in file_list:
                fingerprints.append(crawler.getFingerprint(filepath))
        if args.ignore_empty:
            empty_fingerprint = crawler.getEmptyFingerprint()
            fingerprints = [fp for fp in fingerprints if fp[-1] != empty_fingerprint]
        if args.update_path:
            crawler.persistFingerprintsToFile(fingerprints, args.update_path)
        if args.output_path:
            crawler.persistFingerprintsToFile(fingerprints, args.output_path)
        else:
            output_path = get_this_dir() + os.sep + "dbs" + os.sep + "{}-winapi1024.csv".format(datetime.datetime.utcnow().strftime("%Y-%m-%d"))
            crawler.persistFingerprintsToFile(fingerprints, output_path)
    else:
        parser.print_help()

if __name__ == "__main__":
    sys.exit(main())

