"""the apiscout command line tool, see `apiscout --help`"""

import argparse
import datetime
import difflib
import importlib.metadata
import json
import logging
import os
import re
import sys
import traceback
from multiprocessing import Pool, cpu_count

from .ApiQR import ApiQR
from .ApiScout import ApiScout
from .FingerprintCrawler import FingerprintCrawler

PROJECT_URL = "https://github.com/danielplohmann/apiscout"
MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de"
DB_DIR_VARIABLE = "APISCOUT_DB_DIR"
COLLECTION_PATTERN = r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

EXAMPLES = f"""examples:
  apiscout scan dump_0x00400000 --db dbs/win7_prof-n_sp1_example.json
      list the Windows APIs referenced in a memory dump, with its ApiVector
  apiscout scan sample.exe --import-table
      take the APIs of a PE file from its import table, no API DB needed
  apiscout scan dump_0x00400000 --collection apivectors.csv
      also name the malware families with the most similar ApiVectors
  apiscout match A171 --collection apivectors.csv
      compare a vector with a collection, or with another vector
  apiscout export A171 --png vector.png
      draw a vector as ApiQR diagram
  apiscout dbs
      show the API DBs that are used when --db is not given

API DBs describe one Windows system each. Example DBs and the DB builder
are part of the repository: {PROJECT_URL}
"""


class CliError(Exception):
    """an expected error, reported without traceback"""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # a mistyped command gets a suggestion instead of the list of all choices
        match = re.match(r"argument command: invalid choice: '([^']*)'", message)
        if match:
            close = difflib.get_close_matches(match.group(1), COMMANDS, n=1)
            hint = f" Did you mean '{close[0]}'?" if close else ""
            message = f"unknown command '{match.group(1)}'.{hint}"
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\nTry '{self.prog} --help'.\n")


def get_default_db_dir():
    """the folder searched for API DBs and collections: $APISCOUT_DB_DIR, ./dbs or the dbs folder of a checkout"""
    if os.environ.get(DB_DIR_VARIABLE):
        return os.environ[DB_DIR_VARIABLE]
    candidates = [os.path.join(os.getcwd(), "dbs"), os.path.join(os.path.dirname(os.path.dirname(__file__)), "dbs")]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def get_db_files(db_dir):
    if not os.path.isdir(db_dir):
        return []
    return sorted(os.path.join(db_dir, name) for name in os.listdir(db_dir) if name.endswith(".json"))


def resolve_db_files(args):
    """the API DBs to use: those given with --db, otherwise all of the DB folder"""
    db_paths = list(args.db) if args.db else get_db_files(args.db_dir or get_default_db_dir())
    for db_path in db_paths:
        if not os.path.isfile(db_path):
            raise CliError(f"API DB not found: {db_path}")
    if not db_paths:
        raise CliError(
            f"no API DB found in {args.db_dir or get_default_db_dir()}. Pass one with --db, or point --db-dir or "
            f"${DB_DIR_VARIABLE} to a folder of API DBs (example DBs: {PROJECT_URL}/tree/master/dbs)."
        )
    return db_paths


def parse_address(value):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an address: {value} (use decimal or 0x-prefixed hex)") from None


def read_input(path):
    if path == "-":
        if sys.stdin.isatty():
            raise CliError("no data on standard input. Pipe a dump into the command or pass a file.")
        return sys.stdin.buffer.read()
    if not os.path.isfile(path):
        raise CliError(f"file not found: {path}")
    with open(path, "rb") as f_binary:
        return f_binary.read()


def results_to_records(results):
    records = []
    for api_map_name in results:
        for api in results[api_map_name]:
            records.append(
                {
                    "offset": api[0],
                    "apiAddress": api[1],
                    "dll": re.sub(r"_0x[0-9a-fA-F]+$", "", api[2]) + f"({api[4]} bit)",
                    "api": api[3],
                    "references": sorted(api[7]),
                }
            )
    return records


def write_output(text, output_path):
    """to the file given with --output, or to standard output"""
    if output_path and output_path != "-":
        with open(output_path, "w", encoding="utf-8") as f_out:
            f_out.write(text)
    else:
        sys.stdout.write(text)


def cmd_scan(args):
    binary = read_input(args.dump)
    scout = ApiScout()
    base_address = args.base_addr
    if base_address is None:
        # memory dumps are commonly named after the address they were taken from
        match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})$", args.dump)
        base_address = int(match.group("base_addr"), 16) if match else 0
    scout.setBaseAddress(base_address)
    scout.ignoreAslrOffsets(args.ignore_aslr)
    db_paths = []
    if args.import_table:
        results = scout.evaluateImportTable(binary, is_unmapped=True)
    else:
        db_paths = resolve_db_files(args)
        for db_path in db_paths:
            scout.loadDbFile(db_path)
        results = scout.crawl(binary)
    results = scout.filter(results, 0, 0, args.filter)
    if args.json:
        vector = scout.getPrimaryVector(scout.getWinApi1024Vectors(results))[1]
        document = {
            "base_address": base_address,
            "api_dbs": db_paths,
            "apis": results_to_records(results),
            "apivector": vector["vector"],
            "apis_in_vector": vector["in_api_vector"],
        }
        if args.collection:
            document["collection_matches"] = scout.matchVectorCollection(vector["vector"], args.collection)
        write_output(json.dumps(document, indent=1, default=list) + "\n", args.output)
        return EXIT_OK
    lines = []
    if not args.quiet:
        source = "the import table" if args.import_table else f"{scout.getNumApisLoaded()} APIs of {len(db_paths)} DBs"
        lines.append(f"Scanned {len(binary)} bytes at base address 0x{base_address:x} with {source}.\n")
    lines.append(scout.render(results))
    lines.append(scout.renderVectorResults(results))
    if args.collection:
        lines.append(scout.renderResultsVsCollection(results, args.collection))
    write_output("\n".join(lines) + "\n", args.output)
    return EXIT_OK


def cmd_match(args):
    if bool(args.other) == bool(args.collection):
        raise CliError("give either a second vector or --collection to match against.")
    scout = ApiScout()
    scout.loadWinApi1024()
    try:
        if args.other:
            score = scout.matchVectors(args.vector, args.other)
            if args.json:
                print(json.dumps({"vector_a": args.vector, "vector_b": args.other, "score": score}))
            else:
                print(f"Vector A: {args.vector}\nVector B: {args.other}\nScore: {score}")
            return EXIT_OK
        if not os.path.isfile(args.collection):
            raise CliError(f"collection not found: {args.collection}")
        result = scout.matchVectorCollection(args.vector, args.collection)
    except ValueError as exc:
        raise CliError(str(exc)) from None
    if args.json:
        print(json.dumps(result, indent=1, default=list))
    else:
        print(scout.renderVectorCollectionResults(result, args.max_results))
    return EXIT_OK


def cmd_export(args):
    if not args.html and not args.png:
        raise CliError("nothing to write, give --png and/or --html.")
    apiqr = ApiQR(os.path.join(os.path.dirname(__file__), "data", "winapi1024v1.txt"))
    try:
        apiqr.setVector(args.vector)
    except ValueError as exc:
        raise CliError(str(exc)) from None
    if args.html:
        apiqr.exportHtml(args.html, full=True)
        report(args, f"Wrote {args.html}")
    if args.png:
        apiqr.exportPng(args.png)
        report(args, f"Wrote {args.png}")
    return EXIT_OK


def cmd_collect(args):
    if not os.path.isdir(args.folder):
        raise CliError(f"folder not found: {args.folder}")
    output_path = args.update or args.output
    if not output_path:
        output_path = os.path.join(
            args.db_dir or get_default_db_dir(), f"{datetime.date.today().isoformat()}-winapi1024.csv"
        )
    if os.path.isdir(output_path):
        raise CliError(f"{output_path} is a folder, a file is expected.")
    if not os.access(os.path.dirname(os.path.abspath(output_path)), os.W_OK):
        raise CliError(f"can not write to the folder of {output_path}.")
    db_paths = []
    for db_path in resolve_db_files(args):
        if FingerprintCrawler.dbHasAslrOffsets(db_path) and not (args.use_aslr_dbs or args.ignore_aslr):
            # such a DB only describes the boot it was built in
            report(args, f"Skipping API DB with ASLR offsets (--use-aslr-dbs or --ignore-aslr includes it): {db_path}")
            continue
        db_paths.append(db_path)
    if not db_paths:
        raise CliError("all API DBs carry ASLR offsets. Pass --use-aslr-dbs or --ignore-aslr to use them.")
    winapi1024_path = os.path.join(os.path.dirname(__file__), "data", "winapi1024v1.txt")
    crawler = FingerprintCrawler(
        db_paths, winapi1024_path, args.folder, args.filter, ignore_aslr_offsets=args.ignore_aslr
    )
    if args.update and os.path.isfile(args.update):
        crawler.loadIgnoreList(args.update)
    file_list = []
    for root, _, files in os.walk(args.folder):
        file_list.extend(os.path.join(root, name) for name in files if args.require in name)
    num_crawlable = crawler.getNumberOfCrawlableFiles(file_list)
    report(args, f"Fingerprinting {num_crawlable} of {len(file_list)} files with {cpu_count()} processes...")
    with Pool(cpu_count()) as pool:
        fingerprints = pool.map(crawler.getFingerprint, file_list)
    if args.skip_empty:
        empty_fingerprint = crawler.getEmptyFingerprint()
        fingerprints = [fingerprint for fingerprint in fingerprints if fingerprint[-1] != empty_fingerprint]
    if args.update:
        fingerprints = crawler.mergeWithIgnoreList(fingerprints)
    crawler.persistFingerprintsToFile(fingerprints, output_path)
    report(args, f"Wrote {len(fingerprints)} fingerprints to {output_path}")
    return EXIT_OK


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
            f"no Malpedia API token found. Store your token (from {MALPEDIA_URL}) in {token_path}, "
            "or pass a file that holds it with --token-file."
        )
    with open(token_path, encoding="utf-8") as f_token:
        token = f_token.read().strip()
    db_dir = args.db_dir or get_default_db_dir()
    if not os.path.isdir(db_dir):
        raise CliError(f"folder not found: {db_dir}. Create it or pass another one with --db-dir.")
    versions = {name: re.fullmatch(COLLECTION_PATTERN, name) for name in os.listdir(db_dir)}
    collections = {name: int(version.group(1)) for name, version in versions.items() if version}
    local_version = max(collections.values(), default=0)
    report(args, f"Asking {MALPEDIA_URL} for the current collection (local version: {local_version or 'none'})...")
    try:
        response = requests.get(f"{MALPEDIA_URL}/api/get/version", timeout=args.timeout)
        response.raise_for_status()
        remote_version = response.json()["version"]
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
    name = re.search(COLLECTION_PATTERN, response.headers.get("Content-Disposition", ""))
    if not name or not response.content.strip():
        raise CliError("Malpedia sent no collection.")
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
    for old_name in collections:
        if old_name != name.group(0):
            os.remove(os.path.join(db_dir, old_name))
    report(args, f"Stored {target_path}" + (f", removed {len(collections)} older collections" if collections else ""))
    return EXIT_OK


def cmd_dbs(args):
    db_dir = args.db_dir or get_default_db_dir()
    entries = []
    for db_path in get_db_files(db_dir):
        try:
            with open(db_path, encoding="utf-8") as f_db:
                content = json.load(f_db)
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
        except (ValueError, KeyError, TypeError, AttributeError):
            logging.warning("not an API DB: %s", db_path)
    if args.json:
        print(json.dumps({"db_dir": db_dir, "api_dbs": entries}, indent=1))
        return EXIT_OK
    if not entries:
        print(f"No API DBs in {db_dir}.")
        print(
            f"Point --db-dir or ${DB_DIR_VARIABLE} to a folder of API DBs (example DBs: {PROJECT_URL}/tree/master/dbs)."
        )
        return EXIT_OK
    print(f"API DBs in {db_dir}:\n")
    row = "{:<34} {:<36} {:<12} {:>5} {:>7}  {}"
    print(row.format("File", "System", "Version", "DLLs", "APIs", "ASLR offsets"))
    for entry in entries:
        system, version = str(entry["os_name"])[:36], str(entry["os_version"]).split(" ")[0]
        aslr = "yes" if entry["aslr_offsets"] else "no"
        print(row.format(os.path.basename(str(entry["path"])), system, version, entry["dlls"], entry["apis"], aslr))
    if any(entry["aslr_offsets"] for entry in entries):
        print("\nA DB with ASLR offsets only fits memory dumps of the boot it was built in.")
    return EXIT_OK


def report(args, message):
    """progress and results that are not the output of the command go to standard error"""
    if not args.quiet:
        print(message, file=sys.stderr)


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


def build_parser():
    common = Parser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="only print results and errors")
    common.add_argument("--verbose", action="store_true", help="print what the library logs while it works")
    parser = Parser(
        prog="apiscout",
        description="Recover the Windows APIs a memory dump refers to and compare dumps by their API usage (ApiVectors).",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"apiscout {get_version()}")
    commands = parser.add_subparsers(dest="command", metavar="command", parser_class=Parser)

    scan = commands.add_parser(
        "scan",
        parents=[common],
        help="list the Windows APIs referenced in a memory dump",
        description="List the Windows APIs referenced in a memory dump, with its ApiVector. The base address is taken "
        "from a file name ending in 0x<address> unless --base-addr is given.",
    )
    scan.add_argument("dump", help="memory dump to scan, - reads standard input")
    add_db_options(scan)
    scan.add_argument("-b", "--base-addr", type=parse_address, metavar="ADDR", help="address the dump was taken from")
    scan.add_argument(
        "-t",
        "--import-table",
        action="store_true",
        help="read the import table of an unmapped PE file instead, no API DB needed",
    )
    scan.add_argument(
        "-f",
        "--filter",
        type=int,
        default=0,
        metavar="N",
        help="drop APIs without another API within N bytes (e.g. 32)",
    )
    scan.add_argument("--ignore-aslr", action="store_true", help="do not apply the ASLR offsets stored in an API DB")
    scan.add_argument("-c", "--collection", metavar="FILE", help="also match the ApiVector against this collection")
    scan.add_argument("--json", action="store_true", help="print the result as JSON")
    scan.add_argument("-o", "--output", metavar="FILE", help="write the result to FILE instead of standard output")
    scan.set_defaults(run=cmd_scan)

    match = commands.add_parser(
        "match",
        parents=[common],
        help="compare an ApiVector with another one or with a collection",
        description="Compare an ApiVector with another vector, or with every vector of a collection.",
    )
    match.add_argument("vector", help="compressed ApiVector, as printed by scan")
    match.add_argument("other", nargs="?", help="second vector to compare with")
    match.add_argument("-c", "--collection", metavar="FILE", help="collection of ApiVectors to compare with")
    match.add_argument("-n", "--max-results", type=int, default=5, metavar="N", help="families to list (default: 5)")
    match.add_argument("--json", action="store_true", help="print the result as JSON")
    match.set_defaults(run=cmd_match)

    export = commands.add_parser(
        "export",
        parents=[common],
        help="draw an ApiVector as ApiQR diagram",
        description="Draw an ApiVector as ApiQR diagram, a picture of the 1024 APIs ordered by topic.",
    )
    export.add_argument("vector", help="compressed ApiVector, as printed by scan")
    export.add_argument("--png", metavar="FILE", help="write a PNG image")
    export.add_argument("--html", metavar="FILE", help="write an HTML page that names the APIs on hover")
    export.set_defaults(run=cmd_export)

    collect = commands.add_parser(
        "collect",
        parents=[common],
        help="build a collection of ApiVectors from a folder of dumps",
        description="Build a collection of ApiVectors from a folder of memory dumps. The first folder level names the "
        "malware family, as in Malpedia.",
    )
    collect.add_argument("folder", help="folder with one sub folder per family")
    add_db_options(collect)
    collect.add_argument(
        "-o", "--output", metavar="FILE", help="collection to write (default: <db dir>/<date>-winapi1024.csv)"
    )
    collect.add_argument("-u", "--update", metavar="FILE", help="add the dumps that FILE does not contain yet to FILE")
    collect.add_argument(
        "-r", "--require", default="", metavar="TEXT", help='only use files whose name contains TEXT (e.g. "_dump")'
    )
    collect.add_argument(
        "-f",
        "--filter",
        type=int,
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

    update = commands.add_parser(
        "update",
        parents=[common],
        help="download the current ApiVector collection from Malpedia",
        description=f"Download the current ApiVector collection from Malpedia ({MALPEDIA_URL}) into the DB folder and "
        f"remove older ones. The API token of your Malpedia account is read from {get_token_path()}.",
    )
    add_db_options(update, with_db=False)
    update.add_argument("--token-file", metavar="FILE", help="file that holds the Malpedia API token")
    update.add_argument(
        "--timeout", type=float, default=60, metavar="SECONDS", help="timeout of a request (default: 60)"
    )
    update.set_defaults(run=cmd_update)

    dbs = commands.add_parser(
        "dbs",
        parents=[common],
        help="show the API DBs that are available",
        description="Show the API DBs of the DB folder, which scan and collect use when --db is not given.",
    )
    add_db_options(dbs, with_db=False)
    dbs.add_argument("--json", action="store_true", help="print the result as JSON")
    dbs.set_defaults(run=cmd_dbs)

    help_command = commands.add_parser("help", help="show the help of a command")
    help_command.add_argument("topic", nargs="?", metavar="command")
    help_command.set_defaults(run=None)
    return parser, commands


COMMANDS = ("scan", "match", "export", "collect", "update", "dbs", "help")


def get_version():
    try:
        return importlib.metadata.version("apiscout")
    except importlib.metadata.PackageNotFoundError:
        return "(not installed)"


def main(argv=None):
    parser, commands = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_OK
    if args.command == "help":
        if args.topic and args.topic not in commands.choices:
            parser.error(f"argument command: invalid choice: '{args.topic}'")
        (commands.choices[args.topic] if args.topic else parser).print_help()
        return EXIT_OK
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s")
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
        traceback.print_exc()
        print(f"\napiscout: unexpected error, please report it: {PROJECT_URL}/issues", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
