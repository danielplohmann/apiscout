"""
The DB builder, run from a clone of the repository (or a copy of its apiscout folder): `python -m apiscout.db_builder`
builds an API DB of this system and `python -m apiscout.db_builder.DllDownloader` one of a Windows build from
Microsoft's symbol server. It needs the standard library only and is not part of the installed package.
"""

import os
import shutil
import tempfile
from contextlib import suppress


def write_atomic(path, data):
    """Replace the destination after writing all data to a private file on the same filesystem."""
    path = os.path.realpath(path)
    with tempfile.TemporaryDirectory(prefix=".apiscout-", dir=os.path.dirname(path)) as directory:
        temporary = os.path.join(directory, "output")
        with open(temporary, "wb") as f_out:
            f_out.write(data)
        with suppress(FileNotFoundError):
            shutil.copymode(path, temporary)
        os.replace(temporary, path)
