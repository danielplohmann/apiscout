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

import struct
import os
import json
import logging
from operator import itemgetter

logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class ApiVector(object):

    def __init__(self, winapi1024_filepath=None):
        self._winapi1024 = self._loadWinApi1024(winapi1024_filepath)
        self._dllapi_only = list(zip(map(itemgetter(0), self._winapi1024), map(itemgetter(1), self._winapi1024)))

    def _loadWinApi1024(self, winapi1024_filepath):
        winapi1024 = []
        if winapi1024_filepath:
            if os.path.isfile(winapi1024_filepath):
                with open(winapi1024_filepath, "r") as infile:
                    for line in infile.readlines():
                        functionality = line.split(";")[0]
                        dll, function = line.split(";")[2].strip().split("!")
                        rank = line.split(";")[3]
                        winapi1024.append((dll, function, functionality, rank))
                if len(winapi1024) != 1024:
                    raise ValueError("WinApi1024 file contained {} instead of 1024 api definitions.".format(len(self._winapi1024)))
            else:
                LOG.error("Not a file: %s!", winapi1024_filepath)
                raise ValueError
        return winapi1024
        
    def getApiVectors(self, results):
        unique_results = self._get_uniquified_results(results)
        api_vectors = self._vectorize(results)
        coverage = {}
        for api_map_name in unique_results:
            percentage = 100.0 * sum(api_vectors[api_map_name]) / len(unique_results[api_map_name]) if len(unique_results[api_map_name]) else 0
            coverage[api_map_name] = {
                "vector": api_vectors[api_map_name],
                "num_unique_apis": len(unique_results[api_map_name]), 
                "in_api_vector": sum(api_vectors[api_map_name]), 
                "percentage": percentage
            }
        return coverage
        
    def _vectorize(self, results):
        unique_results = self._get_uniquified_results(results)
        vectors = {}
        for api_map_name, unique_results in unique_results.items():
            vectors[api_map_name] = [1 if entry in unique_results else 0 for entry in self._dllapi_only]
        return vectors
        
    def _get_uniquified_results(self, results):
        uniquified = {}
        for api_map_name, map_results in results.items():
            uniquified[api_map_name] = set(self._uniquify_api_name(t[2].split("_")[0], t[3]) for t in map_results)
        return uniquified

    def _uniquify_api_name(self, dll_name, api_name):
        if dll_name.startswith("msvcr"):
            dll_name = "msvcrt.dll"
        api_name = api_name.split("@")[0]
        if api_name.endswith("A") or api_name.endswith("W"):
            api_name = api_name[:-1]
        return dll_name, api_name

