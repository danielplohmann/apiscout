import logging
import os
import re
import struct
import json


def get_word(buf, start):
    return _get_binary_data(buf, start, 2)


def get_dword(buf, start):
    return _get_binary_data(buf, start, 4)


def get_qword(buf, start):
    return _get_binary_data(buf, start, 8)


_unsigned_unpack_formats = {
    2: "H",
    4: "I",
    8: "Q"
}

def get_pe_offset(binary):
    if len(binary) >= 0x40:
        pe_offset = get_word(binary, 0x3c)
        return pe_offset
    raise RuntimeError("Buffer too small to extract PE offset (< 0x40)")


def check_pe(binary):
    pe_offset = get_pe_offset(binary)
    if pe_offset and len(binary) >= pe_offset + 6:
        bitness = get_word(binary, pe_offset + 4)
        bitness_map = {0x14c: 32, 0x8664: 64}
        return bitness in bitness_map
    return False


def _get_binary_data(buf, start, length):
    if length not in _unsigned_unpack_formats:
        raise RuntimeError("Unsupported data length")
    return struct.unpack(_unsigned_unpack_formats[length], buf[start:start + length])[0]


def get_string(buf, start_offset):
    string = ""
    current_offset = 0
    buf = bytearray(buf)
    current_byte = buf[start_offset]
    while current_byte != 0 and start_offset + current_offset < len(buf) - 1:
        string += chr(current_byte)
        current_offset += 1
        current_byte = buf[start_offset + current_offset]
    return string

