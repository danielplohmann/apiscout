"""
Binary Ninja plugin of ApiScout: recovers Windows API references from memory dumps.

Needs the apiscout package in Binary Ninja's Python (pip install apiscout with that interpreter), or a checkout of
the repository this folder is part of. The commands are found in the Plugins menu under ApiScout.
"""

import os
import sys

try:
    import apiscout.ApiScout  # noqa: F401
except ImportError:
    # the plugin folder is used from a checkout of the repository, plugins/binja_scout/ lies two folders below its root
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")))

# registers the commands, once, also when the extension manager imports apiscout.binja_scout itself
from apiscout.binja_scout import scan_and_annotate  # noqa: E402

__all__ = ["scan_and_annotate"]
