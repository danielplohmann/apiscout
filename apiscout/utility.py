import struct


_UNSIGNED_UNPACK_FORMATS = {
    2: "H",
    4: "I",
    8: "Q"
}


def get_word(buf, start):
    return _get_binary_data(buf, start, 2)


def get_dword(buf, start):
    return _get_binary_data(buf, start, 4)


def get_qword(buf, start):
    return _get_binary_data(buf, start, 8)


def _get_binary_data(buf, start, length):
    if length not in _UNSIGNED_UNPACK_FORMATS:
        raise RuntimeError("Unsupported data length")
    return struct.unpack(_UNSIGNED_UNPACK_FORMATS[length], buf[start:start + length])[0]


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
