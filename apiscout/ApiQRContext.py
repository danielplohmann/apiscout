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

import math
from operator import itemgetter


class ApiQRContext:
    """
    Class to store all context related data that is especially needed for:
    - Exports to HTML
    - Exports to PNG
    """
    data = []
    colors_format = "RGB"
    colors_white = (255, 255, 255)
    colors_dict = {
        "execution": (41, 128, 185),
        "gui":       (241, 196, 15),
        "file":      (46, 204, 113),
        "time":      (52, 152, 219),
        "memory":    (243, 156, 18), 
        "string":    (231, 76, 60), 
        "network":   (59, 216, 214), 
        "crypto":    (142, 68, 173),
        "other":     (39, 174, 96),
        "device":    (250, 206, 32),
        "system":    (192, 57, 43), 
        "registry":  (26, 188, 156),
    }

    def __init__(self, winapi1024):
        self.data = winapi1024
        if self.dimension ** 2 != len(self.data) or int(math.log(self.dimension, 2)) != math.log(self.dimension, 2):
            raise ValueError("Vector needs to have a length for which its squareroot is a power of two")

    @property
    def dimension(self):
        return int(len(self.data) ** 0.5)

    @property
    def apis(self):
        return list(zip(map(itemgetter(0), self.data), map(itemgetter(1), self.data)))

    @property
    def colors(self):
        return list(map(lambda x: self.colors_dict[x[2]], self.data))

    @property
    def empty_vector(self):
        return [0] * len(self.data)

