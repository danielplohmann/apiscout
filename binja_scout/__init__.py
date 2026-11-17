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
    # the plugin folder is used from a checkout of the repository
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from apiscout.BinaryNinjaTools import register_commands, scan_and_annotate  # noqa: E402

__all__ = ["scan_and_annotate"]

register_commands()
