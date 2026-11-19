import contextlib
import gc
import json
import struct

MAX_STRING_LENGTH = 512

_UNSIGNED_UNPACK_FORMATS = {2: "<H", 4: "<I", 8: "<Q"}


def get_word(buf, start):
    return _get_binary_data(buf, start, 2)


def get_dword(buf, start):
    return _get_binary_data(buf, start, 4)


def get_qword(buf, start):
    return _get_binary_data(buf, start, 8)


def _get_binary_data(buf, start, length):
    if length not in _UNSIGNED_UNPACK_FORMATS:
        raise RuntimeError("Unsupported data length")
    return struct.unpack(_UNSIGNED_UNPACK_FORMATS[length], buf[start : start + length])[0]


def get_string(buf, start_offset):
    if start_offset < 0 or start_offset >= len(buf):
        raise IndexError("string offset out of range")
    # names of DLLs and APIs are short, garbage is cut off instead of being copied over and over
    candidate = bytes(buf[start_offset : start_offset + MAX_STRING_LENGTH])
    return candidate.split(b"\x00", 1)[0].decode("latin-1")


@contextlib.contextmanager
def paused_garbage_collection():
    """An API DB is parsed into a million containers, the garbage collections they trigger take as long as the parsing."""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def read_json(path):
    """The content of a JSON file, read as bytes and decoded at once, which is several times faster than text mode."""
    with open(path, "rb") as f_json:
        return json.loads(f_json.read().decode("utf-8"))
