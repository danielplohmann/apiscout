"""the apiscout command line tool, see `apiscout --help`"""

import argparse
import functools
import json
import logging
import os
import re
import sys

from . import db_index
from .utility import paused_garbage_collection, read_json

PROJECT_URL = "https://github.com/danielplohmann/apiscout"
MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de"
DB_DIR_VARIABLE = "APISCOUT_DB_DIR"
COLLECTION_PATTERN = r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv"
COMMANDS = ("scan", "match", "export", "collect", "update", "dbs", "help")
EXPLAIN_TOP = 10  # APIs listed per group when two vectors are explained

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

EXAMPLES = {
    None: f"""examples:
  apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json
      list the Windows APIs referenced in a memory dump, with its ApiVector
  apiscout scan sample.exe --import-table
      take the APIs of a PE file from its import table, no API DB needed
  apiscout scan dump_0x00400000 --collection apivectors.csv
      also name the malware families with the most similar ApiVectors
  apiscout match 'WDBCAgBBAAgCA159' --collection apivectors.csv
      compare a vector with a collection, or with another vector
  apiscout export 'WDBCAgBBAAgCA159' --png vector.png
      draw a vector as ApiQR diagram
  apiscout dbs
      show the API DBs that are used when --db is not given
  apiscout dbs download
      download the example API DBs of the repository

API DBs describe one Windows system each. The DB builder is part of the
repository: {PROJECT_URL}
""",
    "scan": """examples:
  apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json
  apiscout scan dump.bin --base-addr 0x400000 --filter 32 --json -o result.json
  apiscout scan dump_0x00400000 --min-confidence 30
  apiscout scan shellcode_0x00400000 --dynamic
  apiscout scan sample.exe --import-table
  cat dump.bin | apiscout scan - --base-addr 0x400000
  apiscout scan crash.dmp --db win10_prof_1803_example.json
  apiscout scan dump.bin --base-addr 0x400000 --db win11_pro_26h2_example.json --modules modules.txt
""",
    "match": """examples:
  apiscout match 'WDBCAgBBAAgCA159' 'WDBCABBACAgAEAAgA155'
  apiscout match 'WDBCAgBBAAgCA159' --collection apivectors.csv -n 10
  apiscout scan dump_0x00400000 --json | apiscout match - -c apivectors.csv

Quote vectors, they contain characters that are special to the shell.
""",
    "export": """examples:
  apiscout export 'WDBCAgBBAAgCA159' --png vector.png --html vector.html
  apiscout export 'WDBCAgBBAAgCA159' --png - > vector.png
""",
    "collect": """examples:
  apiscout collect malpedia/ --require _dump -o apivectors.csv
  apiscout collect malpedia/ --require _dump --update apivectors.csv
""",
    "update": """examples:
  apiscout update
  apiscout update --db-dir ~/apiscout-dbs --token-file ~/malpedia-token
""",
    "dbs": """examples:
  apiscout dbs
  apiscout dbs --db-dir ~/apiscout-dbs --json
  apiscout dbs download
""",
    "download": """examples:
  apiscout dbs download
  apiscout dbs download win7_prof-n_sp1_example.json
  apiscout dbs download --db-dir ~/apiscout-dbs --ref master
""",
}


class CliError(Exception):
    """an expected error, reported without traceback"""


class VersionAction(argparse.Action):
    """argparse's own --version formats its output with a theme, which imports a module for colors (11 ms)"""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        sys.stdout.write(f"apiscout {get_version()}\n")
        parser.exit()


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        # a mistyped or shortened flag is an error, not another flag
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        # a mistyped command gets a suggestion instead of the list of all choices
        match = re.match(r"argument command: invalid choice: '([^']*)'", message)
        if match:
            import difflib

            close = difflib.get_close_matches(match.group(1), COMMANDS, n=1)
            hint = f" Did you mean '{close[0]}'?" if close else ""
            message = f"unknown command '{match.group(1)}'.{hint}"
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\nTry '{self.prog} --help'.\n")


def get_default_db_dir():
    """the folder searched for API DBs and collections: $APISCOUT_DB_DIR, ./dbs, the folder of downloaded DBs
    or the dbs folder of a checkout"""
    if os.environ.get(DB_DIR_VARIABLE):
        return os.environ[DB_DIR_VARIABLE]
    candidates = [
        os.path.join(os.getcwd(), "dbs"),
        db_index.get_data_dir(),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "dbs"),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def get_db_files(db_dir):
    if not os.path.isdir(db_dir):
        return []
    return sorted(os.path.join(db_dir, name) for name in os.listdir(db_dir) if name.endswith(".json"))


def locate(path, args, what):
    """a file given by path, or by its bare name when it is in the DB folder (e.g. from `apiscout dbs download`)"""
    if path == "-" or os.path.exists(path) or os.path.basename(path) != path:
        check_file(path, what)
        return path
    db_dir = getattr(args, "db_dir", None) or get_default_db_dir()
    candidate = os.path.join(db_dir, path)
    if not os.path.isfile(candidate):
        raise CliError(f"{what} not found: {path}, also not in the DB folder {db_dir}")
    return candidate


def resolve_db_files(args):
    """the API DBs to use: those given with --db, otherwise all of the DB folder"""
    if args.db:
        return [locate(db_path, args, "API DB") for db_path in args.db]
    db_paths = get_db_files(args.db_dir or get_default_db_dir())
    if not db_paths:
        raise CliError(
            f"no API DB found in {args.db_dir or get_default_db_dir()}. Download the example DBs with "
            f"'apiscout dbs download', pass one with --db, or point --db-dir or ${DB_DIR_VARIABLE} to a folder of API DBs."
        )
    return db_paths


def not_an_api_db(db_path):
    return CliError(f"not an API DB: {db_path}. API DBs are built with the DB builder, see {PROJECT_URL}#api-dbs")


def check_file(path, what):
    if os.path.isdir(path):
        raise CliError(f"{path} is a folder, the {what} has to be a file.")
    if not os.path.isfile(path):
        raise CliError(f"{what} not found: {path}")


def check_output(path):
    """found out before the work, not after it"""
    if not path or path == "-":
        return
    if os.path.isdir(path):
        raise CliError(f"{path} is a folder, a file is expected.")
    folder = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(folder):
        raise CliError(f"folder not found: {folder}. Create it or choose another file with --output.")
    if not os.access(folder, os.W_OK):
        raise CliError(f"can not write to the folder of {path}.")


def match_collection(scout, vector, collection_path):
    try:
        result = scout.matchVectorCollection(vector, collection_path)
    except ValueError as exc:
        raise CliError(str(exc) or f"can not match against {collection_path}") from None
    if not result["match_results"]:
        raise CliError(f"no ApiVectors in {collection_path}. A collection has lines of family;sample;...;vector.")
    return result


def explain_pair(scout, vector_a, vector_b):
    try:
        return scout.explainMatch(vector_a, vector_b)
    except ValueError as exc:
        raise CliError(str(exc)) from None


def explain_best_match(scout, vector, collection_path, matches):
    """the explanation of the best match of the collection, which is first in matches"""
    family, sample, _ = matches["match_results"][0]
    other = scout.getCollectionVector(collection_path, family, sample)
    return {"family": family, "sample": sample, **explain_pair(scout, vector, other)}


def parse_address(value):
    try:
        address = int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an address: {value} (use decimal or 0x-prefixed hex)") from None
    if address < 0:
        raise argparse.ArgumentTypeError(f"not an address: {value}")
    return address


def parse_count(minimum):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            number = None
        if number is None or number < minimum:
            raise argparse.ArgumentTypeError(f"expected a number of at least {minimum}, got {value}")
        return number

    return parse


def parse_confidence(value):
    try:
        number = int(value)
    except ValueError:
        number = None
    if number is None or not 0 <= number <= 100:
        raise argparse.ArgumentTypeError(f"expected a number from 0 to 100, got {value}")
    return number


def parse_timeout(value):
    try:
        seconds = float(value)
    except ValueError:
        seconds = 0
    if not 0 < seconds < float("inf"):
        raise argparse.ArgumentTypeError(f"expected a number of seconds above 0, got {value}")
    return seconds


def read_input(path):
    if path == "-":
        if sys.stdin.isatty():
            raise CliError("no data on standard input. Pipe a dump into the command or pass a file.")
        binary = sys.stdin.buffer.read()
        if not binary:
            raise CliError("no data on standard input.")
        return binary
    check_file(path, "dump")
    with open(path, "rb") as f_binary:
        binary = f_binary.read()
    if not binary:
        raise CliError(f"file is empty: {path}")
    return binary


def read_vector(value):
    """a vector given as - is read from standard input, plain or within the JSON result of scan"""
    if value != "-":
        return value
    if sys.stdin.isatty():
        raise CliError("no vector on standard input. Pipe one into the command or pass it as argument.")
    text = sys.stdin.read().strip()
    if text.startswith("{"):
        # the result of `apiscout scan --json`
        try:
            return str(json.loads(text)["apivector"])
        except (ValueError, KeyError, TypeError):
            raise CliError("the JSON on standard input is not a result of `apiscout scan --json`.") from None
    if not text:
        raise CliError("no vector on standard input.")
    return text.split()[0]


def results_to_records(results, confidences=None):
    """JSON records of the hits, with their confidence from ApiScout.getConfidences() where it is given"""
    records = []
    for api_map_name in results:
        for api in results[api_map_name]:
            record = {
                "offset": api[0],
                "apiAddress": api[1],
                "dll": re.sub(r"_0x[0-9a-fA-F]+$", "", api[2]) + f"({api[4]} bit)",
                "api": api[3],
                "references": sorted(api[7]),
            }
            if confidences is not None:
                record["confidence"] = confidences[api_map_name][(api[0], api[4])]
            records.append(record)
    return records


def dynamic_to_records(dynamic_results):
    return [
        {
            "offset": api.offset,
            "type": api.kind,
            "algorithm": api.algorithm,
            "value": api.value,
            "api": api.api,
            "dlls": list(api.dlls),
            "api_db": api_map_name,
        }
        for api_map_name, apis in dynamic_results.items()
        for api in apis
    ]


def write_output(text, output_path):
    """to the file given with --output, or to standard output"""
    if output_path and output_path != "-":
        with open(output_path, "w", encoding="utf-8") as f_out:
            f_out.write(text)
    else:
        sys.stdout.write(text)


def write_file(write, output_path):
    """lets write(path) produce a file, - sends its content to standard output instead"""
    if output_path != "-":
        write(output_path)
        return
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        temp_path = os.path.join(directory, "output")
        write(temp_path)
        with open(temp_path, "rb") as f_result:
            sys.stdout.flush()
            shutil.copyfileobj(f_result, sys.stdout.buffer)
    sys.stdout.buffer.flush()


def report(args, message):
    """progress and results that are not the output of the command go to standard error"""
    if not args.quiet:
        print(message, file=sys.stderr)


def report_placements(args, placer):
    """how many DLLs of each API DB were placed at the addresses the dump tells, and from which source"""
    for db_path, _, num_dlls, counts in placer.summaries:
        placed = sum(counts.values())
        sources = ", ".join(f"{count} from the {source}" for source, count in counts.items())
        has_module_list = bool(placer.module_lists)
        message = f"Placed {placed} of {num_dlls} DLLs of {os.path.basename(db_path)} at their load addresses"
        message += f" ({sources})" if sources else ""
        message += f", {num_dlls - placed} keep the addresses of the DB." if num_dlls != placed else "."
        report(args, ("Warning: " if has_module_list and num_dlls != placed else "") + message)


def scan_minidump(scout, minidump, args):
    """scan the memory ranges of a minidump at their addresses, without the images of the system DLLs in its module
    list: what they hold are the export tables and import address tables of the DLLs, not references of the sample"""
    for warning in minidump.warnings:
        report(args, f"Warning: {warning}")
    if minidump.bitness == 32:
        scout.setBitness(32)
    ranges = minidump.getRanges()
    results = scout.crawlRegions(ranges)
    dll_images = [
        (module.base_address, module.end_address)
        for module in minidump.getModules()
        if scout.hasDll(module.name.replace("\\", "/").rsplit("/", 1)[-1])
    ]
    num_hits = sum(len(hits) for hits in results.values())
    results = scout.filter(results, 0, 0, 0, own_image=False, exclude_ranges=dll_images)
    num_excluded = num_hits - sum(len(hits) for hits in results.values())
    summary = (
        f"Scanned a {minidump.bitness or 'unknown'}bit minidump: {sum(len(data) for _, data in ranges)} bytes in "
        f"{len(ranges)} memory ranges, {len(minidump.getModules())} modules, "
        f"{num_excluded} hits in the images of {len(dll_images)} system DLLs left out"
    )
    return results, summary, dll_images


def cmd_scan(args):
    from .ApiScout import ApiScout
    from .LoadAddresses import (
        SOURCE_MINIDUMP,
        SOURCE_MODULES,
        DllPlacer,
        find_dll_images,
        normalize_dll_path,
        read_load_addresses,
    )
    from .Minidump import Minidump, MinidumpError
    from .PeTools import PeTools

    if args.dynamic and args.import_table:
        raise CliError(
            "--dynamic searches the dump for hashes and names of the APIs of API DBs, it can not be combined with --import-table."
        )
    check_output(args.output)
    placer = DllPlacer()
    if args.modules:
        if args.import_table:
            raise CliError("--modules places the DLLs of an API DB, which --import-table does not use.")
        check_file(args.modules, "module list")
        load_addresses = read_load_addresses(args.modules)
        if not load_addresses:
            raise CliError(f"no lines of '<hex load address> <DLL path>' in {args.modules}.")
        placer.addModuleList(SOURCE_MODULES, load_addresses)
    if args.explain and not args.collection:
        raise CliError("--explain explains the best match with a collection, give --collection as well.")
    binary = read_input(args.dump)
    minidump = None
    if Minidump.isMinidump(binary):
        if args.import_table:
            raise CliError(f"{args.dump} is a minidump. --import-table needs a PE file as it is stored on disk.")
        try:
            minidump = Minidump(binary)
        except MinidumpError as exc:
            raise CliError(f"can not read {args.dump} as minidump: {exc}.") from None
    scout = ApiScout()
    if args.collection:
        args.collection = locate(args.collection, args, "collection")
        # a file that is no collection is found out before the scan, without the warnings for each of its lines
        logging.disable(logging.WARNING)
        try:
            match_collection(scout, scout.getPrimaryVector({})[1]["vector"], args.collection)
        finally:
            logging.disable(logging.NOTSET)
    base_address = args.base_addr
    if base_address is None and minidump:
        # a minidump has the addresses of its memory ranges, offsets are their virtual addresses
        base_address = 0
    elif base_address is None:
        # memory dumps are commonly named after the address they were taken from
        match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})$", args.dump)
        base_address = int(match.group("base_addr"), 16) if match else 0
    scout.setBaseAddress(base_address)
    scout.ignoreAslrOffsets(args.ignore_aslr)
    db_paths = []
    if minidump:
        placer.addModuleList(
            SOURCE_MINIDUMP,
            [(normalize_dll_path(module.name), module.base_address) for module in minidump.getModules() if module.name],
        )
    elif not args.import_table:
        placer.addImages(find_dll_images(binary, base_address))
    if args.import_table:
        if not PeTools.checkPe(binary):
            raise CliError(f"not a PE file: {args.dump}. --import-table needs a PE file as it is stored on disk.")
        results = scout.evaluateImportTable(binary, is_unmapped=True)
        summary = f"Scanned {len(binary)} bytes at base address 0x{base_address:x} with the import table."
    else:
        db_paths = resolve_db_files(args)
        for db_path in db_paths:
            try:
                scout.loadDbFile(db_path, functools.partial(placer, db_path=db_path) if not placer.isEmpty() else None)
            except (ValueError, KeyError, TypeError, AttributeError):
                raise not_an_api_db(db_path) from None
        report_placements(args, placer)
        source = f"{scout.getNumApisLoaded()} APIs of {len(db_paths)} DBs"
        if minidump:
            results, summary, dll_images = scan_minidump(scout, minidump, args)
            summary += f", with {source}."
        else:
            results = scout.crawl(binary)
            summary = f"Scanned {len(binary)} bytes at base address 0x{base_address:x} with {source}."
    # neighbours count in the complete results, so score them before anything is dropped
    confidences = scout.getConfidences(results)
    results = scout.filter(results, 0, 0, args.filter)
    if args.min_confidence:
        num_hits = sum(len(hits) for hits in results.values())
        results = scout.filterByConfidence(results, args.min_confidence, confidences)
        dropped = num_hits - sum(len(hits) for hits in results.values())
        report(args, f"Dropped {dropped} of {num_hits} hits with a confidence below {args.min_confidence}.")
    report(args, summary)
    dynamic = None
    vector_results = results
    if args.dynamic:
        if minidump:
            dynamic = scout.findDynamicApisInRegions(minidump.getRanges(), dll_images)
        else:
            dynamic = scout.findDynamicApis(binary)
        vector_results = scout.addDynamicApisToResults(results, dynamic)
    vector = scout.getPrimaryVector(scout.getWinApi1024Vectors(vector_results))[1]
    matches = match_collection(scout, vector["vector"], args.collection) if args.collection else None
    best_match = explain_best_match(scout, vector["vector"], args.collection, matches) if args.explain else None
    if args.json:
        document = {
            "base_address": base_address,
            "api_dbs": db_paths,
            "placed_dlls": placer.placed,
            "apis": results_to_records(results, confidences),
            "apivector": vector["vector"],
            "apis_in_vector": vector["in_api_vector"],
        }
        if dynamic is not None:
            document["dynamic_apis"] = dynamic_to_records(dynamic)
        if matches:
            matches["match_results"] = matches["match_results"][: args.max_results]
            document["collection_matches"] = matches
        if best_match:
            document["best_match"] = best_match
        write_output(json.dumps(document, indent=1, default=list) + "\n", args.output)
        return EXIT_OK
    lines = [scout.render(results)]
    if dynamic is not None:
        lines.append(scout.renderDynamicApis(dynamic))
    lines.append(scout.renderVectorResults(vector_results))
    if matches:
        lines.append(scout.renderVectorCollectionResults(matches, args.max_results))
    if best_match:
        lines.append(scout.renderBestMatchExplanation(best_match))
    write_output("\n".join(lines) + "\n", args.output)
    return EXIT_OK


def cmd_match(args):
    from .ApiScout import ApiScout

    if bool(args.other) == bool(args.collection):
        raise CliError("give either a second vector or --collection to match against.")
    check_output(args.output)
    if args.collection:
        args.collection = locate(args.collection, args, "collection")
    vector = read_vector(args.vector)
    scout = ApiScout()
    scout.loadWinApi1024()
    if args.other:
        try:
            score = scout.matchVectors(vector, args.other)
        except ValueError as exc:
            raise CliError(str(exc)) from None
        if args.explain:
            explanation = explain_pair(scout, vector, args.other)
            if args.json:
                text = json.dumps({"vector_a": vector, "vector_b": args.other, **explanation}) + "\n"
            else:
                text = f"Vector A: {vector}\nVector B: {args.other}\nScore: {score}\n"
                text += scout.renderMatchExplanation(explanation, EXPLAIN_TOP)
        elif args.json:
            text = json.dumps({"vector_a": vector, "vector_b": args.other, "score": score}) + "\n"
        else:
            text = f"Vector A: {vector}\nVector B: {args.other}\nScore: {score}\n"
    else:
        result = match_collection(scout, vector, args.collection)
        best_match = explain_best_match(scout, vector, args.collection, result) if args.explain else None
        if args.json:
            result["match_results"] = result["match_results"][: args.max_results]
            if best_match:
                result["best_match"] = best_match
            text = json.dumps(result, indent=1, default=list) + "\n"
        else:
            lines = [scout.renderVectorCollectionResults(result, args.max_results)]
            if best_match:
                lines.append(scout.renderBestMatchExplanation(best_match))
            text = "\n".join(lines) + "\n"
    write_output(text, args.output)
    return EXIT_OK


def cmd_export(args):
    from .ApiQR import ApiQR

    if not args.html and not args.png:
        raise CliError("nothing to write, give --png and/or --html.")
    if args.html == "-" and args.png == "-":
        raise CliError("only one of --png and --html can go to standard output.")
    if args.png == "-" and sys.stdout.isatty():
        raise CliError("a PNG image is not written to the terminal. Redirect standard output or give a file.")
    if args.png and args.html and os.path.realpath(args.png) == os.path.realpath(args.html):
        raise CliError("--png and --html name the same file.")
    for path in (args.html, args.png):
        check_output(path)
    apiqr = ApiQR(os.path.join(os.path.dirname(__file__), "data", "winapi1024v1.txt"))
    try:
        apiqr.setVector(read_vector(args.vector))
    except ValueError as exc:
        raise CliError(str(exc)) from None
    for path, write in ((args.html, lambda path: apiqr.exportHtml(path, full=True)), (args.png, apiqr.exportPng)):
        if path:
            write_file(write, path)
            if path != "-":
                report(args, f"Wrote {path}")
    return EXIT_OK


def cmd_collect(args):
    import datetime
    from multiprocessing import Pool, cpu_count

    from .FingerprintCrawler import FingerprintCrawler

    if not os.path.isdir(args.folder):
        raise CliError(f"folder not found: {args.folder}")
    if args.update == "-":
        raise CliError("--update needs a file, use --output - to write to standard output.")
    destinations = [path for path in (args.update, args.output) if path]
    if not destinations:
        db_dir = args.db_dir or get_default_db_dir()
        destinations = [os.path.join(db_dir, f"{datetime.date.today().isoformat()}-winapi1024.csv")]
    if args.update and args.output and os.path.realpath(args.update) == os.path.realpath(args.output):
        raise CliError("--update and --output name the same file, leave out --output.")
    for destination in destinations:
        check_output(destination)
    db_paths = []
    for db_path in resolve_db_files(args):
        try:
            has_aslr_offsets = FingerprintCrawler.dbHasAslrOffsets(db_path)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise not_an_api_db(db_path) from None
        if has_aslr_offsets and not (args.use_aslr_dbs or args.ignore_aslr):
            # such a DB only describes the boot it was built in
            report(args, f"Skipping API DB with ASLR offsets (--use-aslr-dbs or --ignore-aslr includes it): {db_path}")
            continue
        db_paths.append(db_path)
    if not db_paths:
        raise CliError("all API DBs carry ASLR offsets. Pass --use-aslr-dbs or --ignore-aslr to use them.")
    winapi1024_path = os.path.join(os.path.dirname(__file__), "data", "winapi1024v1.txt")
    crawler_arguments = (db_paths, winapi1024_path, args.folder, args.filter, args.ignore_aslr, args.update)
    try:
        crawler = create_crawler(*crawler_arguments)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise CliError("one of the API DBs can not be loaded, `apiscout dbs` shows which are usable.") from None
    file_list = []
    for root, _, files in os.walk(args.folder):
        file_list.extend(os.path.join(root, name) for name in files if args.require in name)
    num_crawlable = crawler.getNumberOfCrawlableFiles(file_list)
    report(args, f"Fingerprinting {num_crawlable} of {len(file_list)} files with {cpu_count()} processes...")
    fingerprints = []
    show_progress = not args.quiet and sys.stderr.isatty()
    # every worker builds its own crawler once, tasks then only carry a path
    log_level = logging.getLogger("apiscout").getEffectiveLevel()
    with Pool(cpu_count(), initializer=init_worker, initargs=(log_level, *crawler_arguments)) as pool:
        try:
            for fingerprint in pool.imap(get_fingerprint, file_list, chunksize=4):
                fingerprints.append(fingerprint)
                if show_progress:
                    print(f"\r{len(fingerprints)} / {len(file_list)}", end="", file=sys.stderr, flush=True)
        except RuntimeError as exc:
            raise CliError(f"a worker process could not load the API DBs or the collection ({exc}).") from None
    if show_progress:
        print(file=sys.stderr)
    if args.skip_empty:
        empty_fingerprint = crawler.getEmptyFingerprint()
        fingerprints = [fingerprint for fingerprint in fingerprints if fingerprint[-1] != empty_fingerprint]
    if args.update:
        merged = crawler.mergeWithIgnoreList(fingerprints)
        crawler.persistFingerprintsToFile(merged, args.update)
        report(args, f"Wrote {len(merged)} fingerprints to {args.update}")
        destinations.remove(args.update)
    for destination in destinations:
        # with --update as well, the output file gets the fingerprints of this folder without the other entries
        write_file(lambda path: crawler.persistFingerprintsToFile(fingerprints, path), destination)
        if destination != "-":
            report(args, f"Wrote {len(fingerprints)} fingerprints to {destination}")
    return EXIT_OK


WORKER_CRAWLER = None
WORKER_ERROR = None


def create_crawler(db_paths, winapi1024_path, folder, filter_size, ignore_aslr, known_collection):
    from .FingerprintCrawler import FingerprintCrawler

    crawler = FingerprintCrawler(db_paths, winapi1024_path, folder, filter_size, ignore_aslr_offsets=ignore_aslr)
    if known_collection and os.path.isfile(known_collection):
        crawler.loadIgnoreList(known_collection)
    return crawler


def init_worker(log_level, *crawler_arguments):
    import signal

    global WORKER_CRAWLER, WORKER_ERROR
    # Ctrl-C is handled by the main process, which then ends its workers
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # what loading the API DBs has to say was reported by the main process already
    package_log = logging.getLogger("apiscout")
    package_log.setLevel(logging.ERROR)
    # the processes keep every core busy already, search threads in each of them would only compete for the cores
    try:
        from . import numpy_search
    except ImportError:
        pass
    else:
        numpy_search.MAX_THREADS = 1
    try:
        WORKER_CRAWLER = create_crawler(*crawler_arguments)
    except Exception as exc:
        # reported with the first task, a worker that ends here would be started again and again
        WORKER_ERROR = f"{type(exc).__name__}: {exc}"
    if not logging.getLogger().handlers:
        # a worker that was not forked has no logging set up
        logging.basicConfig(level=logging.WARNING, format="%(message)s")
    package_log.setLevel(log_level)


def get_fingerprint(path):
    if WORKER_CRAWLER is None:
        raise RuntimeError(WORKER_ERROR)
    return WORKER_CRAWLER.getFingerprint(path)


def get_token_path():
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(config_home, "apiscout", "malpedia-token")


def cmd_update(args):
    try:
        import requests
    except ImportError:
        raise CliError("this command needs the requests package: pip install 'apiscout[update]'") from None
    token_path = args.token_file or get_token_path()
    if not os.path.isfile(token_path):
        raise CliError(
            f"no Malpedia API token found. Store the token of your account at {MALPEDIA_URL} in {token_path}, "
            "or pass a file that holds it with --token-file."
        )
    with open(token_path, encoding="utf-8") as f_token:
        token = f_token.read().strip()
    db_dir = args.db_dir or get_default_db_dir()
    if os.path.exists(db_dir) and not os.path.isdir(db_dir):
        raise CliError(f"not a folder: {db_dir}")
    names = os.listdir(db_dir) if os.path.isdir(db_dir) else []
    versions = {name: re.fullmatch(COLLECTION_PATTERN, name) for name in names}
    collections = {name: int(version.group(1)) for name, version in versions.items() if version}
    local_version = max(collections.values(), default=0)
    report(args, f"Asking {MALPEDIA_URL} for the current collection (local version: {local_version or 'none'})...")
    try:
        response = requests.get(f"{MALPEDIA_URL}/api/get/version", timeout=args.timeout)
        response.raise_for_status()
        remote_version = response.json()["version"]
        if not isinstance(remote_version, int):
            raise ValueError
        if local_version >= remote_version:
            report(args, f"The collection in {db_dir} is the most recent one ({remote_version}).")
            return EXIT_OK
        response = requests.get(
            f"{MALPEDIA_URL}/api/list/apiscout/csv",
            headers={"Authorization": "apitoken " + token},
            timeout=args.timeout,
        )
        if response.status_code in (401, 403):
            raise CliError(f"Malpedia rejected the API token in {token_path}.")
        response.raise_for_status()
    except requests.RequestException as exc:
        raise CliError(f"request to Malpedia failed: {exc}") from None
    except (ValueError, KeyError, TypeError):
        raise CliError("Malpedia sent an answer that is not understood, try again later.") from None
    name = re.search(COLLECTION_PATTERN, response.headers.get("Content-Disposition", ""))
    if not name or not response.content.strip():
        raise CliError("Malpedia sent no collection.")
    os.makedirs(db_dir, exist_ok=True)
    target_path = os.path.join(db_dir, name.group(0))
    # stored under its final name only once it is written completely
    temp_path = target_path + ".tmp"
    try:
        with open(temp_path, "wb") as f_out:
            f_out.write(response.content)
        os.replace(temp_path, target_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    outdated = [old_name for old_name in collections if old_name != name.group(0)]
    for old_name in outdated:
        os.remove(os.path.join(db_dir, old_name))
    report(args, f"Stored {target_path}" + (f", removed {len(outdated)} older collections" if outdated else ""))
    return EXIT_OK


def cmd_dbs(args):
    check_output(args.output)
    db_dir = args.db_dir or get_default_db_dir()
    if not os.path.isdir(db_dir):
        raise CliError(
            f"folder not found: {db_dir}. Download the example DBs with 'apiscout dbs download', or point "
            f"--db-dir or ${DB_DIR_VARIABLE} to a folder of API DBs."
        )
    entries = []
    for db_path in get_db_files(db_dir):
        try:
            with paused_garbage_collection():
                content = read_json(db_path)
            entries.append(
                {
                    "path": db_path,
                    "os_name": str(content["os_name"]),
                    "os_version": str(content["os_version"]),
                    "dlls": len(content["dlls"]),
                    "apis": sum(len(dll["exports"]) for dll in content["dlls"].values()),
                    "aslr_offsets": bool(content.get("aslr_offsets")),
                }
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            report(args, f"Not an API DB, ignored: {db_path}")
    if args.json:
        write_output(json.dumps({"db_dir": db_dir, "api_dbs": entries}, indent=1) + "\n", args.output)
        return EXIT_OK
    if not entries:
        lines = [
            f"No API DBs in {db_dir}.",
            f"Download the example DBs with 'apiscout dbs download', or point --db-dir or ${DB_DIR_VARIABLE} "
            "to a folder of API DBs.",
        ]
        write_output("\n".join(lines) + "\n", args.output)
        return EXIT_OK
    row = "{:<34} {:<36} {:<12} {:>5} {:>7}  {}"
    lines = [f"API DBs in {db_dir}:", "", row.format("File", "System", "Version", "DLLs", "APIs", "ASLR offsets")]
    for entry in entries:
        system, version = str(entry["os_name"])[:36], str(entry["os_version"]).split(" ")[0]
        aslr = "yes" if entry["aslr_offsets"] else "no"
        lines.append(
            row.format(os.path.basename(str(entry["path"])), system, version, entry["dlls"], entry["apis"], aslr)
        )
    if any(entry["aslr_offsets"] for entry in entries):
        lines.extend(["", "A DB with ASLR offsets only fits memory dumps of the boot it was built in."])
    write_output("\n".join(lines) + "\n", args.output)
    return EXIT_OK


def get_download_ref():
    """the git tag of the installed version, so that code and DBs match; master for a checkout that is not installed"""
    version = get_version()
    return f"v{version}" if re.fullmatch(r"\d+(\.\d+)*", version) else "master"


def cmd_dbs_download(args):
    db_dir = getattr(args, "db_dir", None) or os.environ.get(DB_DIR_VARIABLE) or db_index.get_data_dir()
    if os.path.exists(db_dir) and not os.path.isdir(db_dir):
        raise CliError(f"not a folder: {db_dir}")
    ref = args.ref or get_download_ref()
    try:
        files = db_index.fetch_index(ref, args.timeout)
    except db_index.DownloadError as exc:
        hint = ""
        if "HTTP 404" in str(exc) and not args.ref:
            hint = f" There are no DBs for apiscout {get_version()} yet, --ref master downloads the current ones."
        raise CliError(f"could not read the list of API DBs: {exc}.{hint}") from exc
    unknown = [name for name in args.names if name not in files]
    if unknown:
        raise CliError(f"not in the repository ({ref}): {', '.join(unknown)}. Available: {', '.join(sorted(files))}")
    selected = list(dict.fromkeys(args.names)) if args.names else sorted(files)
    os.makedirs(db_dir, exist_ok=True)
    kept = []
    for name in selected:
        path = os.path.join(db_dir, name)
        if db_index.is_current(path, files[name]):
            report(args, f"Up to date: {path}")
            continue
        if os.path.exists(path) and not args.force:
            kept.append(path)
            continue
        report(args, f"Downloading {name} ...")
        try:
            db_index.download(ref, name, files[name], db_dir, args.timeout)
        except db_index.DownloadError as exc:
            raise CliError(f"{exc}. Files downloaded so far are kept, run the command again to continue.") from exc
        report(args, f"Stored {path}")
    if kept:
        raise CliError(
            f"kept {len(kept)} files that differ from those of the repository: {', '.join(kept)}. "
            "--force replaces them."
        )
    if not getattr(args, "db_dir", None) and not os.environ.get(DB_DIR_VARIABLE):
        report(args, "scan, collect and dbs use this folder when there is no ./dbs and --db is not given.")
    return EXIT_OK


def add_db_options(parser, with_db=True):
    if with_db:
        parser.add_argument(
            "--db",
            action="append",
            metavar="FILE",
            help="API DB to use, can be given several times (default: all of --db-dir)",
        )
    parser.add_argument(
        "--db-dir", metavar="DIR", help=f"folder with API DBs and collections (default: ${DB_DIR_VARIABLE}, then ./dbs)"
    )


def add_output_options(parser):
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("-o", "--output", metavar="FILE", help="write the result to FILE instead of standard output")


def build_parser():
    # accepted before and after the command; the value given in front of it is kept
    common = Parser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("-q", "--quiet", action="store_true", help="only print results and errors")
    common.add_argument("--verbose", action="store_true", help="print what the library logs while it works")
    parser = Parser(
        prog="apiscout",
        description="Recover the Windows APIs a memory dump refers to and compare dumps by their API usage (ApiVectors).",
        epilog=EXAMPLES[None],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action=VersionAction, help="show program's version number and exit")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print results and errors")
    parser.add_argument("--verbose", action="store_true", help="print what the library logs while it works")
    commands = parser.add_subparsers(dest="command", metavar="command", parser_class=Parser)

    def add_command(name, **kwargs):
        return commands.add_parser(
            name,
            parents=[common],
            epilog=EXAMPLES[name],
            formatter_class=argparse.RawDescriptionHelpFormatter,
            **kwargs,
        )

    scan = add_command(
        "scan",
        help="list the Windows APIs referenced in a memory dump",
        description="List the Windows APIs referenced in a memory dump, with its ApiVector. The base address is taken "
        "from a file name ending in 0x and 8 to 16 hex digits, and is 0 otherwise; --base-addr sets it. A Windows "
        "minidump (MDMP) is detected by its signature and scanned range by range at the addresses of its memory. The DLLs "
        "of the API DBs are placed at the load addresses of the module list of a minidump, of --modules, or of DLL "
        "images found in the dump, so that one API DB per Windows build fits dumps of every boot.",
    )
    scan.add_argument("dump", help="memory dump to scan, - reads standard input")
    add_db_options(scan)
    scan.add_argument(
        "-b",
        "--base-addr",
        type=parse_address,
        metavar="ADDR",
        help="address the dump was taken from; offsets are relative to it (a minidump: 0 by default, so they are "
        "virtual addresses)",
    )
    scan.add_argument(
        "-t",
        "--import-table",
        action="store_true",
        help="read the import table of a PE file as stored on disk instead, no API DB needed",
    )
    scan.add_argument(
        "-f",
        "--filter",
        type=parse_count(0),
        default=0,
        metavar="N",
        help="drop APIs without another API within N bytes (e.g. 32)",
    )
    scan.add_argument(
        "-m",
        "--modules",
        metavar="FILE",
        help="lines of '<hex load address> <DLL path>', the module list of the process: the DLLs of the API DBs are "
        "placed at these addresses instead of those of the DB (as DatabaseBuilder.py --load_addresses does)",
    )
    scan.add_argument(
        "--min-confidence",
        type=parse_confidence,
        default=0,
        metavar="N",
        help="drop hits with a confidence below N (0 to 100, default: 0 keeps all). The confidence, listed as "
        "confidence in --json, says how unlikely a hit is bytes that happen to equal an API address. A hit in the "
        "import table scores 100. Others add up: neighbours (other APIs within 16 bytes: 30 for one, 50 for two, "
        "60 for three or more, an address repeated counts once), a call or jmp through it 40, another API DB agreeing "
        "10, an offset aligned to the pointer size 10; an unaligned hit scores at most 25. 20 to 40 drops the "
        "chance hits of a scan with the right API DB, an API with no neighbour and no call scores 10",
    )
    scan.add_argument("--ignore-aslr", action="store_true", help="do not apply the ASLR offsets stored in an API DB")
    scan.add_argument(
        "--dynamic",
        action="store_true",
        help="also find APIs that are resolved at run time: hashes of their names (ROR13, Metasploit block_api, CRC32, "
        "djb2, FNV-1a, sdbm) in groups of several, also those that the sample XORs or adds a key of its own to (listed "
        "with the key, e.g. sdbm^0x1e5c48de), and their names as strings; they are added to the ApiVector",
    )
    scan.add_argument("-c", "--collection", metavar="FILE", help="also match the ApiVector against this collection")
    scan.add_argument(
        "-n",
        "--max-results",
        type=parse_count(1),
        default=5,
        metavar="N",
        help="matches of the collection to list (default: 5)",
    )
    scan.add_argument(
        "--explain",
        action="store_true",
        help="with --collection: also list the APIs the best match shares with the vector and those only one of them has",
    )
    add_output_options(scan)
    scan.set_defaults(run=cmd_scan)

    match = add_command(
        "match",
        help="compare an ApiVector with another one or with a collection",
        description="Compare an ApiVector with another vector, or with every vector of a collection.",
    )
    match.add_argument(
        "vector",
        help="compressed ApiVector as printed by scan; - reads it, or the output of scan --json, from standard input",
    )
    match.add_argument("other", nargs="?", help="second vector to compare with")
    match.add_argument("-c", "--collection", metavar="FILE", help="collection of ApiVectors to compare with")
    match.add_argument(
        "-n", "--max-results", type=parse_count(1), default=5, metavar="N", help="matches to list (default: 5)"
    )
    match.add_argument(
        "--explain",
        action="store_true",
        help="list the APIs that drive the score: shared by both vectors, or in only one of them, with their weights "
        "(with --collection: for the best match)",
    )
    add_output_options(match)
    match.set_defaults(run=cmd_match)

    export = add_command(
        "export",
        help="draw an ApiVector as ApiQR diagram",
        description="Draw an ApiVector as ApiQR diagram, a picture of the 1024 APIs ordered by topic.",
    )
    export.add_argument("vector", help="compressed ApiVector as printed by scan, - reads it from standard input")
    export.add_argument("--png", metavar="FILE", help="write a PNG image, - writes it to standard output")
    export.add_argument(
        "--html", metavar="FILE", help="write an HTML page that names the APIs on hover, - for standard output"
    )
    export.set_defaults(run=cmd_export)

    collect = add_command(
        "collect",
        help="build a collection of ApiVectors from a folder of dumps",
        description="Build a collection of ApiVectors from a folder of memory dumps. The first folder level names the "
        "malware family, as in Malpedia.",
    )
    collect.add_argument("folder", help="folder with one sub folder per family")
    add_db_options(collect)
    collect.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="collection to write, - for standard output (default: <db dir>/<date>-winapi1024.csv)",
    )
    collect.add_argument(
        "-u",
        "--update",
        metavar="FILE",
        help="reuse the fingerprints FILE has for the dumps, add the missing ones and keep its other entries",
    )
    collect.add_argument(
        "-r", "--require", default="", metavar="TEXT", help='only use files whose name contains TEXT (e.g. "_dump")'
    )
    collect.add_argument(
        "-f",
        "--filter",
        type=parse_count(0),
        default=32,
        metavar="N",
        help="drop APIs without another API within N bytes (default: 32)",
    )
    collect.add_argument("--skip-empty", action="store_true", help="leave out dumps without any API")
    collect.add_argument(
        "--use-aslr-dbs", action="store_true", help="also use API DBs with ASLR offsets and apply the offsets"
    )
    collect.add_argument(
        "--ignore-aslr", action="store_true", help="also use API DBs with ASLR offsets, without the offsets"
    )
    collect.set_defaults(run=cmd_collect)

    update = add_command(
        "update",
        help="download the current ApiVector collection from Malpedia",
        description=f"Download the current ApiVector collection from Malpedia ({MALPEDIA_URL}) into the DB folder, "
        f"which is created if needed, and remove older ones. The API token of your Malpedia account is read from "
        f"{get_token_path()}.",
    )
    add_db_options(update, with_db=False)
    update.add_argument("--token-file", metavar="FILE", help="file that holds the Malpedia API token")
    update.add_argument(
        "--timeout", type=parse_timeout, default=60, metavar="SECONDS", help="timeout of a request (default: 60)"
    )
    update.set_defaults(run=cmd_update)

    dbs = add_command(
        "dbs",
        help="show the API DBs that are available",
        description="Show the API DBs of the DB folder, which scan and collect use when --db is not given.",
    )
    add_db_options(dbs, with_db=False)
    add_output_options(dbs)
    dbs.set_defaults(run=cmd_dbs)
    dbs_commands = dbs.add_subparsers(dest="dbs_command", metavar="command", parser_class=Parser)
    download = dbs_commands.add_parser(
        "download",
        parents=[common],
        help="download the example API DBs of the repository",
        description="Download the example API DBs and the example collection of the repository, checked against "
        f"the SHA-256 sums in its dbs/{db_index.INDEX_NAME}. They are stored in --db-dir, else ${DB_DIR_VARIABLE}, else "
        f"{db_index.get_data_dir()}, which scan, collect and dbs search after ./dbs.",
        epilog=EXAMPLES["download"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    download.add_argument("names", nargs="*", metavar="file", help="files to download (default: all)")
    download.add_argument(
        "--db-dir",
        metavar="DIR",
        default=argparse.SUPPRESS,
        help=f"folder to store them in (default: ${DB_DIR_VARIABLE}, then {db_index.get_data_dir()})",
    )
    download.add_argument(
        "--ref",
        metavar="REF",
        help="git tag or branch to download from (default: the tag of this version, v" + get_version() + ")",
    )
    download.add_argument("--force", action="store_true", help="replace files that differ from those of the repository")
    download.add_argument(
        "--timeout", type=parse_timeout, default=60, metavar="SECONDS", help="timeout of a request (default: 60)"
    )
    download.set_defaults(run=cmd_dbs_download)

    help_command = commands.add_parser(
        "help", help="show the help of a command", description="Show the help of apiscout or of one of its commands."
    )
    help_command.add_argument("topic", nargs="?", metavar="command")
    help_command.set_defaults(run=None)
    return parser, commands


def get_version():
    """the installed version. The METADATA of the installation is read directly: importlib.metadata takes 30 ms to
    import and to find it, as much as numpy, and every command looks the version up for its help."""
    for folder in sys.path:
        try:
            names = os.listdir(folder or ".")
        except OSError:
            continue
        for name in names:
            if name.startswith("apiscout-") and name.endswith(".dist-info"):
                try:
                    with open(os.path.join(folder, name, "METADATA"), encoding="utf-8") as f_metadata:
                        headers = f_metadata.read().split("\n\n", 1)[0]
                except OSError:
                    continue
                match = re.search(r"^Version: *(\S+)", headers, re.MULTILINE)
                if match:
                    return match.group(1)
    import importlib.metadata

    try:
        return importlib.metadata.version("apiscout")
    except importlib.metadata.PackageNotFoundError:
        return "(not installed)"


def main(argv=None):
    parser, commands = build_parser()
    args, unknown = parser.parse_known_args(argv)
    if args.command is None:
        if unknown:
            parser.error("unrecognized arguments: " + " ".join(unknown))
        parser.print_help()
        return EXIT_OK
    if unknown:
        # reported by the command, so that the message points to its help
        commands.choices[args.command].error("unrecognized arguments: " + " ".join(unknown))
    if args.command == "help":
        if args.topic and args.topic not in commands.choices:
            parser.error(f"argument command: invalid choice: '{args.topic}'")
        (commands.choices[args.topic] if args.topic else parser).print_help()
        return EXIT_OK
    logging.basicConfig(level=logging.ERROR if args.quiet else logging.WARNING, format="%(message)s")
    if args.verbose:
        # the messages of this package only, not those of the libraries it uses
        logging.getLogger("apiscout").setLevel(logging.DEBUG)
    try:
        return args.run(args)
    except CliError as exc:
        print(f"apiscout: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # the reader of a pipe has enough, e.g. `apiscout scan ... | head`
        sys.stderr.close()
        return EXIT_OK
    except KeyboardInterrupt:
        print("\napiscout: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except OSError as exc:
        print(f"apiscout: error: {exc.strerror or exc}: {exc.filename or ''}".rstrip(": "), file=sys.stderr)
        return EXIT_ERROR
    except Exception:
        import traceback

        traceback.print_exc()
        print(f"\napiscout: unexpected error, please report it: {PROJECT_URL}/issues", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
