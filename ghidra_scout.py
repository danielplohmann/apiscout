# ApiScout for Ghidra: finds the Windows APIs referenced in the memory of a program, e.g. a memory dump,
# and annotates them like imports.
# Runs with PyGhidra (Ghidra started with support/pyghidraRun) and needs apiscout in its Python environment,
# or a clone of the repository as script directory. When run for the first time, the script asks for the
# folder with the API DBs and remembers it in the user preferences of Ghidra.
# Ctrl+A chooses all APIs found for annotation.
# Headless: pyghidraRun -H ... -postScript ghidra_scout.py <API DB> [<API DB> ...] annotates all APIs found.
# @author @mari-mari
# @category ApiScoutForGhidra
# @keybinding
# @menupath Tools.ApiScout
# @toolbar
# @runtime PyGhidra

import builtins
import logging
import os
import re
import sys
import threading

PREFERENCE_DB_FOLDER = "apiscout.db.folder"
OTHER_API_DB = "Other file..."
ORDINAL_ONLY_API = re.compile(r"None<(\d+)>")
CHUNK_SIZE = 0x100000
KEPT_MODULES = "_apiscout_kept_modules"


class ApiHit:
    """an API address found in memory"""

    def __init__(self, address, api, dll, api_address, bitness):
        self.address = address
        self.api = api
        self.dll = dll
        self.api_address = api_address
        # of the DLL: a 32bit API address in a 64bit program is no pointer
        self.bitness = bitness


class MemoryRegion:
    """adjacent initialized memory blocks, scanned as one buffer"""

    def __init__(self, block):
        self.start = block.getStart()
        self.blocks = [block]


def get_label_name(api, dll):
    ordinal_only = ORDINAL_ONLY_API.fullmatch(api)
    if ordinal_only:
        # exported by ordinal only, so the API DB has no name for it
        return f"{dll}_ordinal_{ordinal_only.group(1)}"
    return api


def get_db_choices(db_folder):
    """the API DBs of the folder by name, and the choice of any other file"""
    try:
        names = sorted(name for name in os.listdir(db_folder) if name.endswith(".json"))
    except OSError:
        names = []
    return [*names, OTHER_API_DB]


def get_memory_regions(blocks):
    """the memory of the program as Ghidra knows it, adjacent initialized blocks merged"""
    regions = []
    current = None
    for block in blocks:
        if not block.isInitialized() or not block.getStart().getAddressSpace().isLoadedMemorySpace():
            current = None
            continue
        if current is not None and current.blocks[-1].getEnd().isSuccessor(block.getStart()):
            current.blocks.append(block)
        else:
            current = MemoryRegion(block)
            regions.append(current)
    return regions


def import_api_scout():
    """the ApiScout class, None if the apiscout package is not found"""
    # PyGhidra removes the modules a script imported from sys.modules when it ends, but numpy can not be
    # initialized twice in one process: a second import fails and apiscout would fall back to its slow plain
    # Python scan. The modules of the first run are kept in builtins, which outlives the runs, and put back.
    kept = getattr(builtins, KEPT_MODULES, {})
    for name, module in kept.items():
        sys.modules.setdefault(name, module)
    before = set(sys.modules)
    try:
        from apiscout.ApiScout import ApiScout
    except ModuleNotFoundError as exc:
        if exc.name == "apiscout":
            return None
        raise
    kept.update({name: sys.modules[name] for name in set(sys.modules) - before if name in sys.modules})
    setattr(builtins, KEPT_MODULES, kept)
    return ApiScout


def load_scout(api_scout_class, db_paths):
    """an ApiScout with the given API DBs, raises ValueError for a file that is missing or no API DB"""
    scout = api_scout_class()
    for db_path in db_paths:
        if not os.path.isfile(db_path):
            raise ValueError(f"API DB not found: {db_path}")
        try:
            scout.loadDbFile(db_path)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ValueError(f"not an API DB: {db_path}") from None
    return scout


def scan_buffer(scout, base_address, binary):
    """(offset, API address, DLL, API, bitness) of the APIs found in a buffer, filtered like `apiscout scan` does
    by default: API addresses within the buffer itself are left out"""
    scout.setBaseAddress(base_address)
    results = scout.filter(scout.crawl(binary), 0, 0, 0)
    # DLLs are named with their base address in the API DB, e.g. kernel32.dll_0x7dd60000
    return [
        (entry[0], entry[1], re.sub(r"_0x[0-9a-fA-F]+$", "", entry[2]), entry[3], entry[4])
        for api_map_name in results
        for entry in results[api_map_name]
    ]


def order_hits(hits, pointer_bits):
    """each location and API once, as several API DBs can resolve the same location, in the order of the addresses;
    a hit of the program's pointer size comes before one of another size at the same location"""
    unique: dict = {}
    for hit in hits:
        unique.setdefault((hit.address, hit.dll, hit.bitness, hit.api), hit)
    return sorted(unique.values(), key=lambda hit: (hit.address, hit.bitness != pointer_bits))


class ScriptLogHandler(logging.Handler):
    """shows the warnings of the apiscout package, e.g. on colliding exports of an API DB, in the script console"""

    def __init__(self, script):
        super().__init__(logging.WARNING)
        self.script = script

    def emit(self, record):
        self.script.println(f"ApiScout: {record.getMessage()}")


class GhidraScout:
    def __init__(self, script):
        self.script = script
        self.program = script.getCurrentProgram()
        self.pointer_bits = self.program.getDefaultPointerSize() * 8
        self.windows_archive = None
        self.windows_archive_missing = False
        # the archive is closed with the dialog, which can happen while rows are still annotated
        self.archive_lock = threading.Lock()

    def run(self):
        if self.script.isRunningHeadless():
            db_paths = [os.path.abspath(arg) for arg in self.script.getScriptArgs()]
            if not db_paths:
                self.script.printerr("Usage: ghidra_scout.py <path to API DB> [<path to API DB> ...]")
                return
        else:
            # cancelling one of the dialogs ends the script
            db_paths = self.ask_for_databases(self.get_db_folder())
        self.script.println(f"\nProcessing {self.program.getName()}\nImage file: {self.program.getExecutablePath()}")
        hits = self.scan(db_paths)
        if hits is None:
            return
        hits = order_hits(hits, self.pointer_bits)
        self.script.println(f"ApiScout found {len(hits)} API references")
        if self.script.isRunningHeadless():
            annotated = sum(1 for hit in hits if self.annotate(hit))
            self.close_windows_archive()
            self.script.println(f"Annotated {annotated} API references")
            return
        self.show_table(hits)

    def get_db_folder(self):
        from ghidra.framework.preferences import Preferences

        folder = Preferences.getProperty(PREFERENCE_DB_FOLDER)
        if folder and os.path.isdir(folder):
            return folder
        chosen = self.script.askDirectory("Folder with ApiScout's API DBs", "Select").getAbsolutePath()
        Preferences.setProperty(PREFERENCE_DB_FOLDER, chosen)
        Preferences.store()
        return chosen

    def ask_for_databases(self, db_folder):
        """the API DBs of the folder are offered by name, any other file can be chosen as well"""
        from ghidra.util.exception import CancelledException
        from java.util import ArrayList

        chosen = self.script.askChoices(
            "ApiScout", "API DBs of the system the memory dump was taken from:", ArrayList(get_db_choices(db_folder))
        )
        db_paths = []
        for choice in chosen:
            if choice == OTHER_API_DB:
                db_paths.append(self.script.askFile("ApiScout: API DB file", "OK").getAbsolutePath())
            else:
                db_paths.append(os.path.join(db_folder, str(choice)))
        if not db_paths:
            raise CancelledException()
        return db_paths

    def scan(self, db_paths):
        """the API references in the memory of the program, None if the API DBs can not be used"""
        api_scout_class = import_api_scout()
        if api_scout_class is None:
            self.script.printerr(
                "ApiScout is not installed in the Python environment of PyGhidra. Install it with:\n"
                f"{sys.executable} -m pip install apiscout"
            )
            return None
        monitor = self.script.getMonitor()
        package_log = logging.getLogger("apiscout")
        handler = ScriptLogHandler(self.script)
        package_log.addHandler(handler)
        try:
            monitor.setMessage("ApiScout: loading the API DBs")
            try:
                scout = load_scout(api_scout_class, db_paths)
            except ValueError as exc:
                self.script.printerr(f"ApiScout: {exc}")
                return None
            hits = []
            # the memory instead of the imported file keeps the offsets right for every loader
            for region in get_memory_regions(self.program.getMemory().getBlocks()):
                monitor.checkCancelled()
                monitor.setMessage(f"ApiScout: scanning {region.start}")
                base_address = region.start.getUnsignedOffset()
                for offset, api_address, dll, api, bitness in scan_buffer(
                    scout, base_address, self.read_region(region)
                ):
                    hits.append(ApiHit(region.start.add(offset), api, dll, api_address, bitness))
            return hits
        finally:
            package_log.removeHandler(handler)

    def read_region(self, region):
        import jpype

        chunk = jpype.JByte[CHUNK_SIZE]
        buffer = bytearray()
        for block in region.blocks:
            for offset in range(0, block.getSize(), CHUNK_SIZE):
                length = min(CHUNK_SIZE, block.getSize() - offset)
                block.getBytes(block.getStart().add(offset), chunk, 0, length)
                buffer += memoryview(chunk)[:length]
        return bytes(buffer)

    def annotate(self, hit):
        """annotates a reference the way Ghidra's own loaders describe an import:
        a pointer with an external reference to the function of its library"""
        from ghidra.program.model.data import DataUtilities, DWordDataType, PointerDataType, QWordDataType
        from ghidra.program.model.symbol import RefType, SourceType, SymbolUtilities
        from ghidra.program.model.util import CodeUnitInsertionException

        try:
            if self.script.getInstructionContaining(hit.address) is not None:
                # an API address within an instruction is a chance hit in code, which is left as it is
                self.script.println(f"Skipping {hit.address}: location of {hit.api} is part of an instruction.")
                return False
            name = SymbolUtilities.replaceInvalidChars(get_label_name(hit.api, hit.dll), True)
            is_pointer_sized = hit.bitness == self.pointer_bits
            # new instances: in Python, PointerDataType.dataType is the property of getDataType(), not the static field
            data_type = (
                PointerDataType() if is_pointer_sized else QWordDataType() if hit.bitness == 64 else DWordDataType()
            )
            existing = self.script.getDataAt(hit.address)
            if existing is None or not existing.isPointer() or not is_pointer_sized:
                try:
                    DataUtilities.createData(
                        self.program,
                        hit.address,
                        data_type,
                        -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
                    )
                except CodeUnitInsertionException as exc:
                    self.script.println(f"Skipping {hit.address}: {hit.api} overlaps other data ({exc.getMessage()}).")
                    return False
            # of several hits at one location, the one of the program's pointer size keeps the primary label
            primary = self.script.getSymbolAt(hit.address)
            self.script.createLabel(
                hit.address, name, is_pointer_sized or primary is None or primary.getSource() == SourceType.DEFAULT
            )
            if not is_pointer_sized:
                # e.g. a 32bit API address in a 64bit program, which is no pointer the program can follow
                return True
            location = self.get_external_location(hit.address, hit.dll.upper(), name)
            self.apply_prototype(location.getFunction(), hit.api)
            self.program.getReferenceManager().addExternalReference(
                hit.address, 0, location, SourceType.ANALYSIS, RefType.DATA
            )
            return True
        except Exception as exc:
            self.script.printerr(f"Could not annotate {hit.address} with {hit.api}: {exc}")
            return False

    def get_external_location(self, pointer, library, name):
        """every pointer gets an external location of its own: the decompiler fails on a function that reaches
        one external function through two pointers, as with exports sharing an address (htons and ntohs)"""
        from ghidra.program.model.symbol import ExternalReference, SourceType

        reference_manager = self.program.getReferenceManager()
        for reference in reference_manager.getReferencesFrom(pointer):
            if isinstance(reference, ExternalReference):
                existing = reference.getExternalLocation()
                if existing.getLabel() == name and existing.getLibraryName() == library:
                    # annotated before
                    return existing
        external_manager = self.program.getExternalManager()
        location = external_manager.addExtFunction(library, name, None, SourceType.ANALYSIS)
        if reference_manager.hasReferencesTo(location.getExternalSpaceAddress()):
            location = external_manager.addExtLocation(
                location.getParentNameSpace(), name, None, SourceType.ANALYSIS, False
            )
            location.createFunction()
        return location

    def apply_prototype(self, function, api):
        """prototypes are taken from the Windows data type archive shipped with Ghidra"""
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.data import FunctionDefinition
        from ghidra.program.model.symbol import SourceType
        from java.util import ArrayList

        if function is None or function.getSignatureSource() != SourceType.DEFAULT:
            return
        with self.archive_lock:
            archive = self.get_windows_archive()
            if archive is None:
                return
            candidates = ArrayList()
            archive.findDataTypes(api, candidates)
            for candidate in candidates:
                if isinstance(candidate, FunctionDefinition):
                    ApplyFunctionSignatureCmd(function.getEntryPoint(), candidate, SourceType.ANALYSIS).applyTo(
                        self.program
                    )
                    return

    def get_windows_archive(self):
        from ghidra.framework import Application
        from ghidra.program.model.data import FileDataTypeManager

        if self.windows_archive is None and not self.windows_archive_missing:
            try:
                archive_file = Application.findDataFileInAnyModule(
                    f"typeinfo/win32/windows_vs12_{self.pointer_bits}.gdt"
                )
                if archive_file is not None:
                    self.windows_archive = FileDataTypeManager.openFileArchive(archive_file, False)
            except Exception as exc:
                self.script.printerr(f"Could not open the Windows data type archive: {exc}")
            self.windows_archive_missing = self.windows_archive is None
        return self.windows_archive

    def close_windows_archive(self):
        with self.archive_lock:
            if self.windows_archive is not None:
                self.windows_archive.close()
                self.windows_archive = None
            # not opened again by rows that are annotated after the dialog was closed
            self.windows_archive_missing = True

    def show_table(self, hits):
        from ghidra.app.tablechooser import AddressableRowObject, ColumnDisplay, TableChooserExecutor
        from java.lang import String
        from jpype import JImplements, JOverride

        scout = self

        @JImplements(AddressableRowObject)
        class ApiRow:
            def __init__(self, hit):
                self.hit = hit

            @JOverride
            def getAddress(self):
                return self.hit.address

        # JPype proxies do not run the default methods of an interface, they are implemented here as well
        @JImplements(ColumnDisplay)
        class Column:
            def __init__(self, name, get_value, get_sort_key=None):
                self.name = name
                self.get_value = get_value
                self.get_sort_key = get_sort_key or get_value

            @JOverride
            def getColumnName(self):
                return self.name

            @JOverride
            def getColumnValue(self, row):
                return self.get_value(row.hit)

            @JOverride
            def getColumnClass(self):
                return String.class_

            @JOverride
            def getRenderer(self):
                # the default renderer of the table
                return None

            @JOverride
            def compare(self, row, other):
                key, other_key = self.get_sort_key(row.hit), self.get_sort_key(other.hit)
                return (key > other_key) - (key < other_key)

            @JOverride
            def equals(self, other):
                return other is self

        @JImplements(TableChooserExecutor)
        class Annotator:
            @JOverride
            def getButtonName(self):
                return "Annotate"

            @JOverride
            def execute(self, row):
                scout.annotate(row.hit)
                # the row stays in the table
                return False

            @JOverride
            def executeInBulk(self, rows, deleted, monitor):
                # called by the dialog within a transaction, its worker would drop an exception silently
                for row in rows:
                    if monitor.isCancelled():
                        break
                    monitor.setMessage(f"Annotating {row.hit.address}")
                    try:
                        self.execute(row)
                    except Exception as exc:
                        scout.script.printerr(f"Could not annotate {row.hit.address} with {row.hit.api}: {exc}")
                    monitor.incrementProgress(1)
                return True

        dialog = self.script.createTableChooserDialog("ApiScout: API references", Annotator())
        dialog.addCustomColumn(Column("API", lambda hit: get_label_name(hit.api, hit.dll)))
        dialog.addCustomColumn(Column("Library", lambda hit: hit.dll))
        dialog.addCustomColumn(Column("API Address", lambda hit: f"{hit.api_address:x}", lambda hit: hit.api_address))
        for hit in hits:
            dialog.add(ApiRow(hit))
        dialog.setClosedListener(self.close_windows_archive)
        dialog.setPreferredSize(900, 600)
        dialog.show()
        dialog.setMessage(f"{len(hits)} API references found, select the ones to annotate")


def main(script):
    from ghidra.util.exception import CancelledException

    try:
        GhidraScout(script).run()
    except CancelledException:
        script.println("ApiScout: cancelled")


if __name__ == "__main__":
    main(globals()["this"])
