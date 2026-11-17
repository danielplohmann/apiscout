"""
Binary Ninja entry point: the extension manager installs the whole repository into a folder and imports that folder
as a package, so this file is what it runs.
"""

import os

if __name__ == "apiscout":
    # the repository is installed (or checked out) in a folder named apiscout and imported under that name:
    # let apiscout.ApiScout etc. be found in the package apiscout/ of the repository, as with any other name
    __path__.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "apiscout"))

try:
    import binaryninja  # noqa: F401
except ImportError:
    pass
else:
    import apiscout.binja_scout  # noqa: F401
