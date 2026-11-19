########################################################################
# Copyright (c) 2018
# Steffen Enders <steffen<at>enders<dot>nrw>
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import numbers
import operator
import os
from html import escape

import numpy as np

from .ApiQRContext import ApiQRContext
from .ApiVector import ApiVector


class ApiQR:
    """
    Class for a two-dimensional vector where each component stands for one distinct API.
    The vector is saved one-dimensionally though.
    """

    def __init__(self, winapi1024_filepath, vector=None):
        self._apivector = ApiVector(winapi1024_filepath, sort_vector=False)
        self._apivector_path = winapi1024_filepath
        self.context = ApiQRContext(self._apivector.getWinApi1024())
        if vector is None:
            self.vector = self.context.empty_vector
        else:
            self.vector = vector

    def setVector(self, vector):
        self.vector = self._apivector.decompress(vector)

    @property
    def vector_unsorted(self):
        result = [None] * len(self.vector)
        with open(self._apivector_path) as infile:
            translation = {
                new_index: entry[0]
                for new_index, entry in enumerate(
                    sorted(
                        enumerate(line for line in infile.readlines() if line.strip()),
                        key=lambda entry: int(entry[1].split(";")[3].strip()),
                        reverse=True,
                    )
                )
            }
        for index, entry in enumerate(self.vector):
            result[translation[index]] = entry
        return result

    def getPng(self, destination_path, scale_factor=5):
        # Pillow takes as long to import as numpy, and most commands draw nothing
        from PIL import Image

        # colored_vector = list(map(self.__mapColor, self.vector_unsorted, self.context.colors))
        colored_vector = []
        vector = self.vector_unsorted
        colors = self.context.colors
        for index in range(len(vector)):
            value, raw_color = vector[index], colors[index]
            color = self.__mapColor(value, raw_color)
            if color == self.context.colors_white:
                color = self.__mapColor(0.2, raw_color)
            else:
                value = 0.4 + (value * (1 - 0.4))
                color = self.__mapColor(value, raw_color)
            colored_vector.append(color)
        # each API is drawn as a square of 2**scale_factor pixels edge length, which is 4**scale_factor consecutive points on the curve
        scaled_vector = np.repeat(np.array(colored_vector, dtype=np.uint8), 4**scale_factor, axis=0)
        transformed_vector = np.asarray(self.__vectorToHilbert(scaled_vector), dtype=np.uint8)
        image = Image.fromarray(transformed_vector).convert(self.context.colors_format)
        return image

    def exportPng(self, destination_path, scale_factor=5):
        image = self.getPng(destination_path, scale_factor=scale_factor)
        image.save(destination_path, format="PNG", compress_level=0)

    def getHtmlHeader(self):
        hilbert_size = int(len(self.vector_unsorted) ** 0.5)
        return f"""\
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>ApiQR</title>
        <style>
        main {{
            max-width: 40rem;
        }}
        table {{
            width: 100%;
            table-layout: fixed;
            border-collapse: collapse;
        }}
        td.apicell {{
            padding: 0;
            width: {100.0 / hilbert_size:.4f}%;
        }}
        td.apicell::after {{
            content: '';
            display: block;
            margin-top: 100%;
        }}
        p {{
            overflow-wrap: anywhere;
        }}
        </style>\n"""

    def _getHtmlTableContent(self, hilbert_size, vector):
        result = ""
        colors = self.context.colors
        apis = self.context.apis
        for hilbert_row in self.__hilbertCurve(hilbert_size):
            result += "<tr>\n"
            for index in hilbert_row:
                value, raw_color = vector[index], colors[index]
                color = self.__mapColor(value, raw_color)
                if color == self.context.colors_white:
                    color = self.__mapColor(0.2, raw_color)
                else:
                    # rescale value to range 0.4-1.0
                    value = 0.4 + (value * (1 - 0.4))
                    color = self.__mapColor(value, raw_color)
                text = escape(":".join(apis[index]))
                result += (
                    f'<td title="{text}" class="apicell" '
                    f'style="background-color: rgb({color[0]}, {color[1]}, {color[2]});"></td>\n'
                )
            result += "</tr>\n"
        return result

    def getHtmlTable(self):
        vector = self.vector_unsorted
        hilbert_size = int(len(vector) ** 0.5)
        result = "<table>\n"
        result += self._getHtmlTableContent(hilbert_size, vector)
        result += "</table>\n"
        return result

    def exportHtml(self, output_path, full=True):
        """Write a standalone HTML diagram, or return the table fragment with full=False."""
        result = self.getHtmlTable()
        if not full:
            return result
        this_path = os.path.abspath(os.path.join(os.path.dirname(__file__)))
        with open(os.sep.join([this_path, "data", "html_frame.html"]), encoding="utf-8") as f_html:
            # the vector is kept in the order of the (rank sorted) WinApi1024 definition, which is also the order of its compressed form
            compressed_vector = self._apivector.compress([1 if value else 0 for value in self.vector])
            result = f_html.read().format(vector=compressed_vector, body=result, head=self.getHtmlHeader())
        with open(output_path, "w", encoding="utf-8") as f_out:
            f_out.write(result)

    def __mapColor(self, value, color):
        if value is True or value == 1 or value == 1.0:
            return color
        if value is False or value == 0 or value == 0.0:
            return self.context.colors_white
        alpha = max(min(value, 1), 0)
        return (
            int((1 - alpha) * 255 + alpha * color[0]),
            int((1 - alpha) * 255 + alpha * color[1]),
            int((1 - alpha) * 255 + alpha * color[2]),
        )

    @property
    def vector_hilbert(self):
        return self.__vectorToHilbert(self.vector_unsorted)

    def __vectorToHilbert(self, vector):
        element_size = 1
        if len(np.array(vector)[0].shape):
            element_size = np.array(vector)[0].shape[0]
        hilbert_indices = self.__hilbertCurve(int(len(vector) ** 0.5))
        return np.array(vector)[np.digitize(hilbert_indices.ravel(), list(range(len(vector))), right=True)].reshape(
            hilbert_indices.shape[0], hilbert_indices.shape[1], element_size
        )

    def __hilbertCurve(self, n):
        """
        Generate Hilbert curve indexing for (n, n) array. 'n' must be a power of two.
        https://github.com/znah/notebooks/blob/master/hilbert_curve.ipynb
        """
        if n == 1:
            return np.zeros((1, 1), np.int32)
        t = self.__hilbertCurve(n // 2)
        a = np.flipud(np.rot90(t))
        b = t + t.size
        c = t + t.size * 2
        d = np.flipud(np.rot90(t, -1)) + t.size * 3
        return np.vstack([i for i in map(np.hstack, [[a, b], [d, c]])])

    def __add__(self, other):
        if not isinstance(other, ApiQR):
            raise ValueError("Only another ApiQR instance can be added.")
        if self.context.data != other.context.data:
            raise ValueError("Both ApiQR instances need to share the same context in order to be added together!")
        return ApiQR(self._apivector_path, vector=list(map(operator.add, self.vector, other.vector)))

    def __mul__(self, other):
        if not isinstance(other, numbers.Number):
            raise ValueError("An ApiQR instance can only be multiplied with numbers.")
        return ApiQR(self._apivector_path, vector=list(map(lambda x: x * other, self.vector)))

    def __div__(self, other):
        if not isinstance(other, numbers.Number):
            raise ValueError("An ApiQR instance can only be divided by numbers.")
        return ApiQR(self._apivector_path, vector=list(map(lambda x: 1.0 * x / other, self.vector)))

    def __truediv__(self, other):
        return self.__div__(other)

    def __str__(self):
        return f"ApiQR {np.array(self.vector)}"

    def __repr__(self):
        return str(self)
