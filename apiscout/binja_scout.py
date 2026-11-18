"""
The Binary Ninja plugin of ApiScout as module of the apiscout package: importing it registers the commands.

Binary Ninja's extension manager imports a plugin as <install folder>.<subdir>. Installed under the name ApiScout,
that is apiscout.binja_scout, and the apiscout package found first is the one of the repository or the one installed
with pip, not the install folder. This module is that import, the plugin folder plugins/binja imports it as well.
"""

from apiscout.BinaryNinjaTools import register_commands, scan_and_annotate

__all__ = ["scan_and_annotate"]

register_commands()
