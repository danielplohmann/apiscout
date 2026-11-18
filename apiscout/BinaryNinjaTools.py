"""
ApiScout for Binary Ninja: scans the memory of a BinaryView for API addresses and annotates the references found.

Headless (Binary Ninja's Python API):

    import binaryninja
    from apiscout.BinaryNinjaTools import scan_and_annotate

    with binaryninja.load("dump.bndb") as bv:
        result = scan_and_annotate(bv, ["dbs/win7_prof-n_sp1_example.json"])
        bv.update_analysis_and_wait()

The commands of the plugin (plugins/binja) are registered with register_commands().
"""

import functools
import os
import re

from binaryninja import interaction
from binaryninja.enums import SymbolType, TypeClass
from binaryninja.log import log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.types import Symbol, Type

from apiscout import db_index
from apiscout.ApiScout import ApiScout
from apiscout.LoadAddresses import describe_placements, placed_image_ranges, placer_for_modules, read_from_regions
from apiscout.utility import paused_garbage_collection, read_json

LOGGER = "ApiScout"
SESSION_KEY = "apiscout"
ANNOTATIONS_KEY = "apiscout.annotations"
# the default of the neighbourhood filter, as in the IDA plugin
DEFAULT_DISTANCE = 0x800
CONFIDENCE_PROMPT = "Minimum confidence (0 keeps all, maximum 100)"
DLL_SUFFIX = re.compile(r"(_0x[0-9a-fA-F]+)? \(\d+bit\)$")
ORDINAL_ONLY = re.compile(r"None<(?P<ordinal>\d+)>$")


def _info(text):
    log_info(text, LOGGER)


def get_memory(bv):
    """the bytes of the view's segments, adjacent ones merged into one buffer: {start address: bytes}"""
    result = {}
    block_start = None
    block_end = None
    for segment in sorted(bv.segments, key=lambda segment: segment.start):
        if segment.data_length == 0:
            # no bytes of the dump, e.g. the section Binary Ninja adds for its synthetic builtins
            continue
        # read returns at most the bytes requested, fewer where the segment has no data
        content = bv.read(segment.start, segment.end - segment.start)
        if not content:
            continue
        if block_start is not None and segment.start == block_end:
            result[block_start] += content
        else:
            block_start = segment.start
            result[block_start] = content
        block_end = segment.start + len(content)
    return result


def get_bitness(row):
    match = re.search(r"\((?P<bitness>\d+)bit\)", row[2])
    return int(match.group("bitness")) if match else 0


def get_dll_name(row):
    return DLL_SUFFIX.sub("", row[2])


def get_api_name(row):
    """the name given to the location, an API exported by ordinal only is named after its DLL and ordinal"""
    match = ORDINAL_ONLY.match(str(row[3]))
    if match:
        return "{}_ordinal_{}".format(re.sub(r"\W", "_", get_dll_name(row)), match.group("ordinal"))
    return str(row[3])


def _merge_results(results, new_results):
    for key, entries in new_results.items():
        results.setdefault(key, []).extend(entries)


def _count_references(bv, address):
    return sum(1 for _ in bv.get_code_refs(address)) + sum(1 for _ in bv.get_data_refs(address))


def get_result_rows(bv, results, confidences=None, confidence_scores=None):
    """
    unique API references over the results of all API DBs as rows [address, API address, DLL, API, references],
    without pointers into the view's own memory
    """
    rows = {}
    for map_name, entries in results.items():
        for entry in entries:
            if bv.get_segment_at(entry[1]) is not None:
                continue
            key = (bv.start + entry[0], entry[1], f"{entry[2]} ({entry[4]}bit)", entry[3])
            rows[key] = max(rows.get(key, 0), entry[6] - 1)
            if confidence_scores is not None and confidences is not None:
                score = confidences[map_name][entry[0], entry[4]]
                confidence_scores[key] = max(score, confidence_scores.get(key, 0))
    # the references known to Binary Ninja include those from other segments
    return [list(key) + [max(references, _count_references(bv, key[0]))] for key, references in sorted(rows.items())]


def scan(bv, db_paths, ignore_aslr_offsets=False, task=None, modules=None, *, confidence_scores=None):
    """the API references found in the view's memory with the given API DBs as rows, see get_result_rows().
    The DLLs of the API DBs are placed where the module list in the file `modules` has them, as `apiscout scan
    --modules` does; raises ModuleListError if it can not be used."""
    placer = placer_for_modules(modules)
    scout = ApiScout()
    scout.ignoreAslrOffsets(ignore_aslr_offsets)
    for path in db_paths:
        path = os.fspath(path)
        if os.path.basename(path) == path and not os.path.isfile(path):
            path = next(
                (
                    os.path.join(folder, path)
                    for folder in get_db_folders()
                    if os.path.isfile(os.path.join(folder, path))
                ),
                path,
            )
        if not os.path.isfile(path):
            raise ValueError(f"API DB not found: {path}. Run apiscout dbs download or choose an existing API DB.")
        try:
            with paused_garbage_collection():
                document = read_json(path)
            if not db_index.is_api_db(document):
                raise ValueError("expected an API database JSON object")
            scout.loadDbFile(path, placer.forDb(path), api_db=document)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"Cannot read API DB {path}: {exc}") from exc
    for line in describe_placements(placer):
        _info(line)
    bitness_string = "32bit and 64bit" if scout.has_64bit else "32bit"
    memory = sorted(get_memory(bv).items())
    if not memory:
        return []
    results = {}
    for segment_address, binary in memory:
        if task is not None and task.cancelled:
            break
        if task is not None:
            task.progress = f"ApiScout: scanning 0x{segment_address:x}"
        scout.setLoadOffset(segment_address - bv.start)
        # code references are resolved relative to the buffer they are found in
        scout.setBaseAddress(segment_address)
        _info(f"Scanning {len(binary)} bytes @0x{segment_address:x} in {bitness_string} mode.")
        _merge_results(results, scout.crawl(binary))
    # the images of the DLLs in the memory hold their export tables and import address tables, not references
    ranges = placed_image_ranges(placer, functools.partial(read_from_regions, memory))
    scout.setBaseAddress(bv.start)
    if ranges:
        results = scout.filter(results, 0, 0, 0, own_image=False, exclude_ranges=ranges)
    confidences = scout.getConfidences(results) if confidence_scores is not None else None
    return get_result_rows(bv, results, confidences, confidence_scores)


def filter_by_distance(rows, distance):
    """only the rows with another API reference within the given distance, 0 keeps all of them"""
    return ApiScout._getFilteredList(distance, rows) if distance else list(rows)


def _select_rows(rows, distance, confidence_scores, min_confidence):
    selected = filter_by_distance(rows, distance)
    if min_confidence:
        selected = [row for row in selected if confidence_scores.get(tuple(row[:4]), 0) >= min_confidence]
    return selected


class PrototypeResolver:
    """finds the prototype of an API in the type libraries of the view's platform"""

    def __init__(self, bv):
        self.bv = bv
        self._cache = {}
        self._all_libraries = None

    def _candidates(self, dll_name):
        platform = self.bv.platform
        if platform is None:
            return []
        libraries = list(platform.get_type_libraries_by_name(dll_name.lower()))
        if libraries:
            return libraries
        # e.g. an API of kernelbase.dll that the platform describes in another library
        if self._all_libraries is None:
            self._all_libraries = list(platform.type_libraries)
        return self._all_libraries

    def resolve(self, dll_name, api_name):
        """(function type, type library, name of the object in the library) of the API or None"""
        key = (dll_name.lower(), api_name)
        if key not in self._cache:
            self._cache[key] = self._resolve(dll_name, api_name)
        return self._cache[key]

    def _resolve(self, dll_name, api_name):
        names = [api_name]
        if api_name.startswith("Zw"):
            # the type libraries describe the system calls of ntdll by their Nt names only, Zw* has the same prototype
            names.append("Nt" + api_name[2:])
        for name in names:
            for library in self._candidates(dll_name):
                if library.get_named_object(name) is None:
                    continue
                if self.bv.get_type_library(library.name) is None:
                    self.bv.add_type_library(library)
                object_type = self.bv.import_library_object(name, library)
                if object_type is not None and object_type.type_class == TypeClass.FunctionTypeClass:
                    return object_type, library, name
        return None


def _is_referenced(bv, function):
    if function.start == bv.entry_point or any(entry.start == function.start for entry in bv.entry_functions):
        return True
    return any(True for _ in bv.get_code_refs(function.start)) or any(True for _ in bv.get_data_refs(function.start))


def _check_location(bv, address, size):
    """
    (the reason why no pointer can be defined at the location or None, the functions in the way of the pointer).
    Functions in the way are those that nothing refers to, e.g. found by the linear sweep in a table of pointers.
    """
    if size not in (4, 8):
        return "of unknown pointer size", []
    segment = bv.get_segment_at(address)
    if segment is None:
        return "not in a segment", []
    if segment.end < address + size:
        return "at the end of its segment", []
    functions = {}
    for location in range(address, address + size):
        for block in bv.get_basic_blocks_at(location):
            functions[block.function.start] = block.function
    # only a pointer the view's code can call through is worth removing code for, a value of the other bitness
    # in a 64bit view is mostly a chance hit
    if any(_is_referenced(bv, function) for function in functions.values()) or (functions and size != bv.address_size):
        return "part of an instruction", []
    return None, [functions[start] for start in sorted(functions)]


def _set_name(bv, address, name, symbol_type):
    """Replace a symbol previously added by ApiScout, after the caller checks ownership."""
    symbol = bv.get_symbol_at(address)
    if (
        symbol is not None
        and not symbol.auto
        and symbol.type in (SymbolType.ImportAddressSymbol, SymbolType.DataSymbol)
    ):
        if symbol.name == name and symbol.type == symbol_type:
            return
        bv.undefine_user_symbol(symbol)
    bv.define_user_symbol(Symbol(symbol_type, address, name))


def _apply(bv, row, resolver):
    """annotate one location, returns the outcome"""
    address = row[0]
    size = get_bitness(row) // 8
    name = get_api_name(row)
    if size != bv.address_size:
        # e.g. a 32bit API address in a 64bit view, which is no pointer the code of the view follows
        bv.define_user_data_var(address, Type.int(size, False))
        _set_name(bv, address, name, SymbolType.DataSymbol)
        return "annotated (no pointer of this view)"
    prototype = None
    if not ORDINAL_ONLY.match(str(row[3])):
        prototype = resolver.resolve(get_dll_name(row), str(row[3]))
    target = prototype[0] if prototype else Type.void()
    # an import address symbol makes calls through the pointer appear as calls of the API
    _set_name(bv, address, name, SymbolType.ImportAddressSymbol)
    bv.define_user_data_var(address, Type.pointer_of_width(size, target))
    if not prototype:
        return "annotated (no type information)"
    bv.record_imported_object_library(prototype[1], prototype[2], address)
    return "annotated"


def _current_annotations(bv):
    annotations = bv.session_data.get(ANNOTATIONS_KEY)
    if annotations is None:
        annotations = {}
        bv.session_data[ANNOTATIONS_KEY] = annotations
    for address, (key, _) in list(annotations.items()):
        symbol = bv.get_symbol_at(address)
        expected_type = (
            SymbolType.ImportAddressSymbol if get_bitness(key) == bv.address_size * 8 else SymbolType.DataSymbol
        )
        if symbol is None or symbol.auto or symbol.name != get_api_name(key) or symbol.type != expected_type:
            del annotations[address]
    return annotations


def _refresh_status(bv, status, rows=()):
    annotations = _current_annotations(bv)
    current = {key: outcome for key, outcome in annotations.values()}
    for key, outcome in list(status.items()):
        if outcome.startswith("annotated") and key not in current:
            del status[key]
    for row in rows:
        key = tuple(row[:4])
        if key in current:
            status[key] = current[key]
    return annotations


def annotate(bv, rows, status=None, task=None):
    """
    annotate the given rows, a description of the outcome per row is stored in the optional dict status.
    Returns (number annotated, number skipped).
    """
    if status is None:
        status = {}
    annotations = _refresh_status(bv, status)
    resolver = PrototypeResolver(bv)
    num_annotated = 0
    num_skipped = 0
    unresolved_types = set()
    annotated_locations = {}
    # pointers annotated earlier or in this run as {location: (API name, size, row)}, which a later row must not cut
    pointers = {key[0]: (get_api_name(key), get_bitness(key) // 8, key) for key, _ in annotations.values()}
    pointer_bits = bv.address_size * 8
    undo_state = bv.begin_undo_actions()
    try:
        # of several rows for one location, the one of the view's pointer size is applied
        for row in sorted(rows, key=lambda row: (row[0], get_bitness(row) != pointer_bits, row[1:4])):
            if task is not None and task.cancelled:
                break
            key = tuple(row[:4])
            if row[0] in annotated_locations:
                # several API DBs can resolve one location differently, the first one listed is applied
                num_skipped += 1
                status[key] = "skipped: location is annotated as " + annotated_locations[row[0]]
                continue
            size = get_bitness(row) // 8
            overlapped = [
                pointers[location][0]
                for location in range(row[0] - 7, row[0] + size)
                if location != row[0] and location in pointers and location + pointers[location][1] > row[0]
            ]
            if overlapped:
                reason, in_the_way = "overlapping " + overlapped[0], []
            elif (symbol := bv.get_symbol_at(row[0])) is not None and not symbol.auto and row[0] not in annotations:
                reason, in_the_way = f"already named {symbol.name}", []
            else:
                reason, in_the_way = _check_location(bv, row[0], size)
            if reason:
                num_skipped += 1
                status[key] = "skipped: " + reason
                log_warn(f"Skipping 0x{row[0]:x}: location of {get_api_name(row)} is {reason}.", LOGGER)
                continue
            for function in in_the_way:
                _info(f"Removing the function at 0x{function.start:x} without references, it overlaps 0x{row[0]:x}.")
                bv.remove_user_function(function)
            outcome = _apply(bv, row, resolver)
            num_annotated += 1
            annotated_locations[row[0]] = get_api_name(row)
            if row[0] in pointers and pointers[row[0]][2] != key:
                # another row of this location was annotated before, its name is replaced now
                status[pointers[row[0]][2]] = "skipped: location is annotated as " + get_api_name(row)
            pointers[row[0]] = (get_api_name(row), size, key)
            status[key] = outcome
            annotations[row[0]] = (key, outcome)
            if outcome == "annotated (no type information)" and not ORDINAL_ONLY.match(str(row[3])):
                unresolved_types.add(str(row[3]))
    finally:
        bv.commit_undo_actions(undo_state)
    if unresolved_types:
        _info(
            "No type information available for {} APIs: {}".format(
                len(unresolved_types), ", ".join(sorted(unresolved_types))
            )
        )
    bv.update_analysis()
    return num_annotated, num_skipped


def get_state(bv):
    return bv.session_data.get(SESSION_KEY)


def scan_and_annotate(
    bv, db_paths, ignore_aslr_offsets=False, distance=0, task=None, modules=None, *, min_confidence=0
):
    """
    scan the view with the given API DBs and annotate all references found, with distance > 0 only those with
    another reference within this many bytes. modules is the file with the module list that gives the load addresses
    of the DLLs (lines of hex load address and DLL path, as `apiscout scan --modules`).
    min_confidence (0 to 100) limits annotation to hits at or above that score.
    Returns the state also kept in bv.session_data["apiscout"]:
    {"rows": rows found, "status": {row[:4]: outcome}, "annotated": number, "skipped": number}.
    A scan cancelled with the task annotates nothing and keeps the state of the last scan.
    """
    if not 0 <= min_confidence <= 100:
        raise ValueError("Minimum confidence must be between 0 and 100.")
    db_paths = list(db_paths)
    confidence_scores = {}
    rows = scan(bv, db_paths, ignore_aslr_offsets, task, modules, confidence_scores=confidence_scores)
    state = {
        "rows": rows,
        "status": {},
        "db_paths": db_paths,
        "confidence": confidence_scores,
        "annotated": 0,
        "skipped": 0,
    }
    if task is not None and task.cancelled:
        _info("ApiScout: the scan was cancelled, nothing annotated.")
        return state
    bv.session_data[SESSION_KEY] = state
    selected = _select_rows(rows, distance, confidence_scores, min_confidence)
    state["annotated"], state["skipped"] = annotate(bv, selected, state["status"], task)
    _info(f"ApiScout: annotated {state['annotated']} of {len(rows)} API references ({state['skipped']} skipped).")
    return state


# ---------------------------------------------------------------------------------------------------------------
# the commands of the plugin


def _as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value or ""


def get_db_folders():
    """Existing API DB folders in the same search order as the CLI."""
    return list(
        dict.fromkeys(os.path.realpath(folder) for folder in db_index.default_db_dirs() if os.path.isdir(folder))
    )


def _minimum_confidence(field):
    value = field.result if field.result is not None else 0
    if 0 <= value <= 100:
        return value
    log_warn("Minimum confidence must be between 0 and 100.", LOGGER)
    return None


def ask_parameters(for_annotation=False):
    """the API DBs and options chosen in a form, None if cancelled or nothing chosen"""
    db_files = []
    listed = set()
    for folder in get_db_folders():
        try:
            paths = db_index.db_paths(folder)
        except OSError as exc:
            log_warn(f"Cannot list API DB folder {folder}: {exc}", LOGGER)
            continue
        for path in paths:
            # the same DB in several folders is offered once, from the first folder
            name = os.path.basename(path)
            if name in listed:
                continue
            if db_index.read_api_db(path) is None:
                continue
            listed.add(name)
            db_files.append(path)
    fields = ["API DBs of the system the memory dump was taken from:"]
    if not db_files:
        fields.append("Run apiscout dbs download or choose an existing API DB file below.")
    checkboxes = [interaction.CheckboxField(os.path.basename(path), False) for path in db_files]
    other_db = interaction.OpenFileNameField("Other API DB file", "*.json")
    modules = interaction.OpenFileNameField("Module list with the load addresses of the DLLs (optional)")
    ignore_aslr = interaction.CheckboxField("Ignore the ASLR offsets stored in the API DBs", False)
    fields.extend(checkboxes)
    fields.extend([None, other_db, modules, ignore_aslr])
    confidence = interaction.IntegerField(CONFIDENCE_PROMPT, 0) if for_annotation else None
    if confidence is not None:
        fields.append(confidence)
    if not interaction.get_form_input(fields, "ApiScout"):
        return None
    db_paths = [path for path, checkbox in zip(db_files, checkboxes, strict=True) if checkbox.result]
    other_path = _as_text(other_db.result)
    if other_path and not os.path.isfile(other_path):
        log_error(f"API DB not found: {other_path}", LOGGER)
        return None
    if other_path and os.path.realpath(other_path) not in map(os.path.realpath, db_paths):
        db_paths.append(other_path)
    if not db_paths:
        log_warn("No API DB selected, nothing to do.", LOGGER)
        return None
    parameters = {
        "db_paths": db_paths,
        "ignore_aslr_offsets": bool(ignore_aslr.result),
        "modules": _as_text(modules.result) or None,
    }
    if confidence is not None:
        minimum = _minimum_confidence(confidence)
        if minimum is None:
            return None
        parameters["min_confidence"] = minimum
    return parameters


def render_markdown(rows, status, confidence=None):
    confidence = confidence or {}
    lines = [
        f"# ApiScout: {len(rows)} API references",
        "",
        "| Address | API | Library | API Address | References | Confidence | Status |",
        "| :--- | :--- | :--- | :--- | ---: | ---: | :--- |",
    ]
    for row in rows:
        key = tuple(row[:4])
        lines.append(
            f"| [0x{row[0]:x}](binaryninja://?expr=0x{row[0]:x}) | {get_api_name(row)} | {get_dll_name(row)} "
            f"({get_bitness(row)}bit) | 0x{row[1]:x} | {row[4]} | {confidence.get(key, '')} | {status.get(key, '')} |"
        )
    return "\n".join(lines) + "\n"


def render_text(rows, status, confidence=None):
    confidence = confidence or {}
    lines = [f"ApiScout: {len(rows)} API references"]
    for row in rows:
        key = tuple(row[:4])
        library = f"{get_dll_name(row)} ({get_bitness(row)}bit)"
        outcome = status.get(key, "")
        score = f"  confidence {confidence[key]}" if key in confidence else ""
        lines.append(f"0x{row[0]:x}  {get_api_name(row):40} {library:30} 0x{row[1]:x}  {row[4]:4}{score}  {outcome}")
    return "\n".join(lines) + "\n"


def show_results(bv):
    state = get_state(bv)
    if not state:
        log_warn("ApiScout: no scan results for this view, scan it first.", LOGGER)
        return
    _refresh_status(bv, state["status"], state["rows"])
    bv.show_markdown_report(
        "ApiScout",
        render_markdown(state["rows"], state["status"], state.get("confidence")),
        render_text(state["rows"], state["status"], state.get("confidence")),
    )


class ScanTask(BackgroundTaskThread):
    def __init__(self, bv, parameters):
        BackgroundTaskThread.__init__(self, "ApiScout: scanning", True)
        self.bv = bv
        self.parameters = parameters

    def run(self):
        confidence = {}
        try:
            rows = scan(
                self.bv,
                self.parameters["db_paths"],
                self.parameters["ignore_aslr_offsets"],
                self,
                self.parameters.get("modules"),
                confidence_scores=confidence,
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log_error(f"ApiScout: the scan failed: {exc!r}", LOGGER)
            return
        if self.cancelled:
            return
        self.bv.session_data[SESSION_KEY] = {
            "rows": rows,
            "status": {},
            "db_paths": self.parameters["db_paths"],
            "confidence": confidence,
        }
        _info(f"ApiScout: {len(rows)} API references found, annotate them with the ApiScout commands.")
        show_results(self.bv)


class AnnotateTask(BackgroundTaskThread):
    def __init__(self, bv, distance=0, min_confidence=0):
        BackgroundTaskThread.__init__(self, "ApiScout: annotating", True)
        self.bv = bv
        self.distance = distance
        self.min_confidence = min_confidence

    def run(self):
        state = get_state(self.bv)
        if not state or not state["rows"]:
            log_warn("ApiScout: no API references to annotate, scan this view first.", LOGGER)
            return
        rows = _select_rows(state["rows"], self.distance, state.get("confidence", {}), self.min_confidence)
        num_annotated, num_skipped = annotate(self.bv, rows, state["status"], self)
        _info(f"ApiScout: annotated {num_annotated} APIs ({num_skipped} skipped).")
        show_results(self.bv)


class ScanAndAnnotateTask(BackgroundTaskThread):
    def __init__(self, bv, parameters):
        BackgroundTaskThread.__init__(self, "ApiScout: scanning and annotating", True)
        self.bv = bv
        self.parameters = parameters

    def run(self):
        try:
            scan_and_annotate(
                self.bv,
                self.parameters["db_paths"],
                self.parameters["ignore_aslr_offsets"],
                task=self,
                modules=self.parameters.get("modules"),
                min_confidence=self.parameters.get("min_confidence", 0),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log_error(f"ApiScout: the scan failed: {exc!r}", LOGGER)
            return
        show_results(self.bv)


def command_scan(bv):
    parameters = ask_parameters()
    if parameters:
        ScanTask(bv, parameters).start()


def command_scan_and_annotate(bv):
    parameters = ask_parameters(for_annotation=True)
    if parameters:
        ScanAndAnnotateTask(bv, parameters).start()


def command_annotate_all(bv):
    AnnotateTask(bv).start()


def command_annotate_filtered(bv):
    field = interaction.IntegerField(
        "Maximum distance in bytes to the next API (0 annotates all APIs)", DEFAULT_DISTANCE
    )
    confidence = interaction.IntegerField(CONFIDENCE_PROMPT, 0)
    if not interaction.get_form_input([field, confidence], "ApiScout"):
        return
    distance = field.result
    if distance is None or distance < 0:
        return
    minimum = _minimum_confidence(confidence)
    if minimum is not None:
        AnnotateTask(bv, distance, minimum).start()


def has_results(bv):
    state = get_state(bv)
    return bool(state and state["rows"])


def register_commands():
    PluginCommand.register(
        "ApiScout\\Scan for API references...",
        "Scan the memory of the view with ApiScout API DBs and list the API references found",
        command_scan,
    )
    PluginCommand.register(
        "ApiScout\\Show results", "List the API references found by the last scan", show_results, has_results
    )
    PluginCommand.register(
        "ApiScout\\Annotate all",
        "Annotate all API references found by the last scan",
        command_annotate_all,
        has_results,
    )
    PluginCommand.register(
        "ApiScout\\Annotate filtered...",
        "Annotate the API references that meet the selected distance and confidence filters",
        command_annotate_filtered,
        has_results,
    )
    PluginCommand.register(
        "ApiScout\\Scan and annotate all...",
        "Scan the memory of the view with ApiScout API DBs and annotate all API references found",
        command_scan_and_annotate,
    )
