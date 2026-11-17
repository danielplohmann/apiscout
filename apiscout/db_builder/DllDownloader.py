#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

"""Build an API DB for a Windows build without a machine of that build.

Winbindex (the index of the files of Windows updates) tells which file, identified by its SHA-256, belongs to which
update, and the timestamp and SizeOfImage of the PE, which make up the address of the file on Microsoft's public symbol
server. This script looks the DLLs of config.DLL_FILTER up in the index, downloads the 64bit ones for System32 and the
32bit ones for SysWOW64, verifies each against the hash of the index and writes them to <out>/System32 and
<out>/SysWOW64, the folders DatabaseBuilder.py --paths takes. Then it builds the API DB from them (--download-only
stops before). Like DatabaseBuilder.py, it only needs the standard library (Python 3.8 or newer).

The DB has no ASLR offsets: `apiscout scan` places the DLLs where the dump has them (--modules, minidumps).
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

import config

WINBINDEX_URL = "https://winbindex.m417z.com/data/by_filename_compressed/{name}.json.gz"
SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols/{name}/{file_id}/{name}"
USER_AGENT = "Microsoft-Symbol-Server/10.0"

MACHINE_X86 = 332
MACHINE_AMD64 = 34404
# folder, processor architectures of the Winbindex assemblies and machine type of the files that a 64bit Windows has
# there (its 32bit files come from "wow64" assemblies and from "x86" ones, which install into SysWOW64 there)
SYSTEM_FOLDERS = (("System32", ("amd64",), MACHINE_AMD64), ("SysWOW64", ("wow64", "x86"), MACHINE_X86))
FOLDER_BY_SOURCE_PATH = {"system32": ("System32", MACHINE_AMD64), "syswow64": ("SysWOW64", MACHINE_X86)}
BITNESS = {"System32": "x64", "SysWOW64": "x86"}

MAX_INDEX_BYTES = 256 * 1024 * 1024
INDEX_MAX_AGE = 24 * 3600
PAGE_SIZE = 0x1000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")


class DownloaderError(Exception):
    """a problem to report to the user without a traceback"""


class NotFound(DownloaderError):
    """HTTP 404"""


class Mismatch(DownloaderError):
    """a download that is not the file the index describes"""


class Unavailable(DownloaderError):
    """a file that can not be had, no matter how often it is tried; rejected if a download did not match the index"""

    def __init__(self, message, rejected=False):
        super().__init__(message)
        self.rejected = rejected


class FileEntry:
    """one file of an update, as the index describes it"""

    def __init__(self, folder, filename, sha256, info, source_kb=None):
        self.folder = folder
        self.filename = filename
        self.sha256 = sha256
        # the update that lists the file, which is an earlier one if the DLL did not change in the selected update
        self.source_kb = source_kb
        self.size = info.get("size")
        self.timestamp = info.get("timestamp")
        self.virtual_size = info.get("virtualSize")
        self.last_section_virtual_address = info.get("lastSectionVirtualAddress")
        self.last_section_raw_data = info.get("lastSectionPointerToRawData")
        self.version = (info.get("version") or "").split(" ")[0]

    def imageSizes(self):
        """the SizeOfImage values to try on the symbol server, the most likely first"""
        if self.virtual_size:
            return [self.virtual_size]
        # Winbindex indexes some files with a limited amount of information, the SizeOfImage lies between these
        # two values, in steps of one page (the way Winbindex itself lists its candidate download links)
        if self.size and self.last_section_raw_data and self.last_section_virtual_address:
            tail = self.last_section_virtual_address + self.size - self.last_section_raw_data
            highest = (tail + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
            lowest = self.last_section_virtual_address + PAGE_SIZE
            return list(range(highest, lowest - 1, -PAGE_SIZE))
        return []

    def symbolServerUrl(self, image_size):
        file_id = f"{self.timestamp & 0xFFFFFFFF:08X}{image_size:x}"
        name = self.filename.lower()
        return SYMBOL_SERVER_URL.format(name=name, file_id=file_id)


class Update:
    """an update (or the first release, BASE) of a Windows version, as listed in the index"""

    def __init__(self, windows, kb, update_info, primary, names=()):
        self.windows = windows
        self.kb = kb
        # the update is stored under one Windows version and names the others it applies to
        self.primary = primary
        self.names = list(names)
        # the Windows versions that share their updates with this one, set by select_update()
        self.family = {windows}
        self.release = update_info.get("releaseVersion")
        self.date = update_info.get("releaseDate") or ""
        self.builds = re.findall(r"\b\d{4,5}\.\d+\b", update_info.get("heading") or "")
        if self.release and self.release not in self.builds:
            self.builds.insert(0, self.release)
        self.heading = update_info.get("heading") or ""

    def description(self):
        builds = " / ".join(self.builds) if self.builds else "first release"
        return f"{self.windows} {self.kb} ({builds})"


def parse_index(raw):
    """the index of a file name: a gzip compressed JSON object, keyed by the SHA-256 of the files"""
    try:
        data = json.loads(gzip.decompress(raw).decode("utf-8"))
    except (OSError, EOFError, ValueError) as exc:
        raise DownloaderError(f"the Winbindex data is not a gzip compressed JSON document ({exc})") from None
    if not isinstance(data, dict):
        raise DownloaderError("the Winbindex data has an unexpected format")
    return data


def iter_updates(index):
    """(sha256, fileInfo, Windows versions, update name, entry of the update) for every file in every update"""
    for sha256, entry in index.items():
        if not isinstance(entry, dict):
            continue
        info = entry.get("fileInfo") or {}
        for windows, updates in (entry.get("windowsVersions") or {}).items():
            for kb, update in (updates or {}).items():
                update_info = update.get("updateInfo") or update.get("windowsVersionInfo") or {}
                others = update_info.get("otherWindowsVersions") or []
                yield sha256, info, [windows] + list(others), kb, update, update_info


def list_updates(index):
    """{(Windows version, update name): Update} of all the updates the index knows"""
    updates = {}
    for _, _, names, kb, _, update_info in iter_updates(index):
        for position, windows in enumerate(names):
            if (windows, kb) not in updates:
                updates[(windows, kb)] = Update(windows, kb, update_info, position == 0, names)
    return updates


def parse_update_selector(text):
    """('kb', 'KB5046617'), ('build', '26100.2605') or ('base', 'BASE') from what the user typed"""
    text = text.strip()
    if text.upper() == "BASE":
        return "base", "BASE"
    match = re.fullmatch(r"(?:KB)?(\d{6,8})", text, re.IGNORECASE)
    if match:
        return "kb", "KB" + match.group(1)
    match = re.fullmatch(r"(?:10\.0\.)?(\d{4,5}\.\d+)", text)
    if match:
        return "build", match.group(1)
    raise DownloaderError(
        f"'{text}' is neither an update (KB5046617), a build (26100.2605 or 10.0.26100.2605) nor BASE."
    )


def select_update(updates, windows, update_text):
    """the one Update that a Windows version (optional) and an update name or build identify"""
    kind, value = parse_update_selector(update_text)
    matches = []
    for (update_windows, kb), update in updates.items():
        if windows and update_windows.lower() != windows.lower():
            continue
        if kind == "build" and value not in update.builds:
            continue
        if kind != "build" and kb.upper() != value:
            continue
        matches.append(update)
    if not matches:
        known = sorted({update_windows for update_windows, _ in updates})
        if windows and windows.lower() not in (known_windows.lower() for known_windows in known):
            raise DownloaderError(
                "Winbindex has no Windows version '{}'. Known: {}. Use --list to see the updates.".format(
                    windows, ", ".join(known)
                )
            )
        raise DownloaderError(
            "no update '{}'{} in Winbindex. Use --list{} to see the updates.".format(
                update_text, " for " + windows if windows else "", " --windows " + windows if windows else ""
            )
        )
    kbs = sorted({update.kb for update in matches})
    if len(kbs) > 1:
        raise DownloaderError(
            "'{}' fits several updates ({}), choose one with --update.".format(update_text, ", ".join(kbs))
        )
    # the same update listed for several Windows versions is one set of files: take the one that was asked for
    matches.sort(key=lambda update: (not update.primary, update.windows))
    update = matches[0]
    if kind == "base" and not windows:
        raise DownloaderError(
            "BASE exists for every Windows version ({}), name one with --windows.".format(
                ", ".join(match.windows for match in matches)
            )
        )
    update.family = windows_family(updates, update.windows)
    return update


def windows_family(updates, windows):
    """the Windows versions that share updates with a Windows version (11-24H2, 11-25H2 and 11-26H2 do), as the files
    that an update does not change come from the updates before it, which may be listed under a version of them"""
    groups = [set(update.names) for update in updates.values()]
    family = {windows}
    changed = True
    while changed:
        changed = False
        for group in groups:
            if group & family and not group <= family:
                family |= group
                changed = True
    return family


def find_files(index, name, update, fallback=True):
    """{folder: [FileEntry]} with the 64bit System32 and the 32bit SysWOW64 files of the DLL for the update, the one to
    use first. A DLL that the update does not list was not changed by it: the Windows of the update has the file of the
    latest earlier update that lists it (fallback)."""
    exact, earlier = {}, {}
    for sha256, info, names, kb, entry, update_info in iter_updates(index):
        # the key of the index is the SHA-256 of the file, without it the file can not be verified
        if not SHA256.match(sha256) or (info.get("sha256") or sha256).lower() != sha256:
            continue
        is_update = kb == update.kb and update.windows in names
        date = update_info.get("releaseDate") or ""
        if not is_update and not (fallback and date and date <= update.date and update.family & set(names)):
            continue
        for folder, filename in _install_targets(entry, info.get("machineType"), name):
            file = FileEntry(folder, filename, sha256, info, kb)
            if is_update:
                exact.setdefault(folder, {})[sha256] = file
            else:
                earlier.setdefault(folder, {}).setdefault(date, {})[sha256] = file
    files = {}
    for folder in {folder for folder, _, _ in SYSTEM_FOLDERS}:
        if folder in exact:
            candidates = exact[folder]
        elif folder in earlier:
            candidates = earlier[folder][max(earlier[folder])]
        else:
            continue
        # several files that Windows would put in the same place: the newest build first
        files[folder] = sorted(candidates.values(), key=lambda file: (file.timestamp or 0, file.sha256), reverse=True)
    return files


def _safe_filename(name, fallback):
    return name if isinstance(name, str) and SAFE_NAME.match(name) else fallback


def _install_targets(entry, machine, name):
    """(folder, file name) where the Windows of the update puts a file of this machine type, if System32 or SysWOW64"""
    targets = set()
    for assembly in (entry.get("assemblies") or {}).values():
        architecture = (assembly.get("assemblyIdentity") or {}).get("processorArchitecture")
        for attribute in assembly.get("attributes") or []:
            destination = (attribute.get("destinationPath") or "").replace("/", "\\").rstrip("\\").lower()
            attribute_name = attribute.get("name") or ""
            if destination != "$(runtime.system32)" or attribute_name.lower() != name.lower():
                continue
            for folder, folder_architectures, folder_machine in SYSTEM_FOLDERS:
                if architecture in folder_architectures and machine == folder_machine:
                    targets.add((folder, _safe_filename(attribute_name, name)))
    # the files of the first release (BASE) come with the path they have on the installation medium
    for source_path in entry.get("sourcePaths") or []:
        parts = [part for part in re.split(r"[\\/]", source_path) if part]
        if len(parts) == 3 and parts[0].lower() == "windows" and parts[2].lower() == name.lower():
            folder, folder_machine = FOLDER_BY_SOURCE_PATH.get(parts[1].lower(), (None, None))
            if folder and machine == folder_machine:
                targets.add((folder, _safe_filename(parts[2], name)))
    return sorted(targets)


def os_names(update, os_version_hint=None):
    """(os_name, os_version) of the API DB of an update"""
    windows = update.windows
    product = "Windows 11 " + windows[3:] if windows.startswith("11-") else "Windows 10 " + windows
    os_name = "{} {} (AMD64)".format(product, update.kb if update.kb != "BASE" else "RTM")
    build = os_version_hint or update.release
    return os_name, "10.0." + build if build else "10.0"


def http_get(url, max_bytes, retries=4, sleep=time.sleep, timeout=60):
    """the body of an URL (at most max_bytes), retried with a growing pause on network errors and server errors"""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(retries + 1):
        pause = 2.0 * 2**attempt
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise Mismatch(f"larger than the {max_bytes} bytes of Winbindex")
            return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFound("not found: " + url) from None
            if exc.code not in (408, 429, 500, 502, 503, 504):
                raise DownloaderError(f"HTTP {exc.code} for {url}") from None
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if retry_after and retry_after.isdigit():
                pause = min(int(retry_after), 120)
            error = f"HTTP {exc.code}"
        except (urllib.error.URLError, http.client.HTTPException, OSError, EOFError) as exc:
            error = str(getattr(exc, "reason", exc))
        if attempt == retries:
            raise DownloaderError(f"{error} for {url} (gave up after {retries + 1} attempts)")
        sleep(pause)
    raise AssertionError("unreachable")


def sha256_of_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f_in:
        for chunk in iter(lambda: f_in.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_verified(path, file):
    return (
        os.path.isfile(path)
        and (file.size is None or os.path.getsize(path) == file.size)
        and sha256_of_file(path) == file.sha256
    )


def load_index(name, cache_dir, fetch=http_get, now=time.time):
    """the parsed index of a file name, from the cache folder (if there is one) if it is less than a day old"""
    cache_path = os.path.join(cache_dir, name.lower() + ".json.gz") if cache_dir else None
    if cache_path and os.path.isfile(cache_path) and now() - os.path.getmtime(cache_path) < INDEX_MAX_AGE:
        try:
            with open(cache_path, "rb") as f_in:
                return parse_index(f_in.read())
        except DownloaderError:
            pass
    raw = fetch(WINBINDEX_URL.format(name=name.lower()), MAX_INDEX_BYTES)
    index = parse_index(raw)
    if cache_path:
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_path + ".part", "wb") as f_out:
            f_out.write(raw)
        os.replace(cache_path + ".part", cache_path)
    return index


def download_file(files, out_dir, fetch=http_get):
    """download one of the files (the first that is available) to <out_dir>/<folder>/<name>, returns the file and
    "present" if a verified copy is already there, otherwise "downloaded". A file is only put in place when its size
    and SHA-256 are the ones of the index."""
    problem, rejected = "not on the symbol server", False
    for file in files:
        target = os.path.join(out_dir, file.folder, file.filename)
        if is_verified(target, file):
            return file, "present"
        image_sizes = file.imageSizes() if file.timestamp is not None else []
        if not image_sizes:
            problem, rejected = "Winbindex has not enough information to find the file on the symbol server", False
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        for image_size in image_sizes:
            try:
                data = fetch(file.symbolServerUrl(image_size), file.size if file.size else 1 << 30)
            except NotFound:
                continue
            except Mismatch as exc:
                problem, rejected = f"the download is {exc}, dropped", True
                continue
            if (file.size is None or len(data) == file.size) and hashlib.sha256(data).hexdigest() == file.sha256:
                with open(target + ".part", "wb") as f_out:
                    f_out.write(data)
                os.replace(target + ".part", target)
                return file, "downloaded"
            problem, rejected = (
                f"the download differs from the file of Winbindex ({len(data)} instead of {file.size} bytes or "
                "other SHA-256), dropped",
                True,
            )
    raise Unavailable(problem, rejected)


def fetch_dll(name, update, out_dir, cache_dir, fetch=http_get, verified=None):
    """get the files of one DLL, returns (status, message) of each folder or of the DLL as a whole. The paths of the
    files that are now the ones of the update are added to the list verified."""
    try:
        index = load_index(name, cache_dir, fetch)
    except NotFound:
        return [("missing", "not in Winbindex")]
    except DownloaderError as exc:
        return [("failed", f"Winbindex index: {exc}")]
    files = find_files(index, name, update)
    if not files:
        return [("missing", f"no file in System32 or SysWOW64 of {update.kb} or the updates before it")]
    results = []
    for folder, _, _ in SYSTEM_FOLDERS:
        if folder not in files:
            results.append(("missing", f"{folder}: no {BITNESS[folder]} file"))
            continue
        try:
            file, status = download_file(files[folder], out_dir, fetch)
            if verified is not None:
                verified.append(os.path.join(out_dir, file.folder, file.filename))
            note = f" as of {file.source_kb}" if file.source_kb != update.kb else ""
            results.append((status, f"{folder}: {status}{note}"))
        except Unavailable as exc:
            results.append(("rejected" if exc.rejected else "missing", f"{folder}: {exc}"))
        except DownloaderError as exc:
            results.append(("failed", f"{folder}: {exc}"))
    return results


def dll_names(extra_names=None):
    """the DLLs of the DLL filter (config.py) without duplicates that only differ in case, or the given names"""
    names, seen = [], set()
    for name in extra_names or config.DLL_FILTER:
        if not SAFE_NAME.match(name):
            raise DownloaderError(f"'{name}' is not a file name.")
        if name.lower() not in seen:
            seen.add(name.lower())
            names.append(name.lower())
    return names


def default_db_name(update):
    windows = update.windows.lower().replace("-", "_")
    return "win{}_{}.json".format(windows if windows.startswith("11_") else "10_" + windows, update.kb.lower())


def print_listing(index, name, windows, out=sys.stdout):
    """the Windows versions of a DLL's index, or the updates of one Windows version with the files they have"""
    updates = list_updates(index)
    if not windows:
        out.write(f"Windows versions and updates that Winbindex lists for {name}:\n")
        by_windows = {}
        for (update_windows, _), update in updates.items():
            by_windows.setdefault(update_windows, []).append(update)
        for update_windows, listed in sorted(by_windows.items(), key=lambda item: min(u.date for u in item[1])):
            dated = sorted(update.date for update in listed if update.date)
            builds = sorted(
                {b for update in listed for b in update.builds[:1]}, key=lambda b: tuple(int(p) for p in b.split("."))
            )
            out.write(
                "  {:<8} {:>4} updates  {}  {}\n".format(
                    update_windows,
                    len(listed),
                    f"{dated[0]} .. {dated[-1]}" if dated else "",
                    f"builds {builds[0]} .. {builds[-1]}" if builds else "",
                )
            )
        out.write("--windows NAME --list shows the updates of one of them.\n")
        return
    listed = sorted((u for u in updates.values() if u.windows.lower() == windows.lower()), key=lambda u: u.date)
    if not listed:
        raise DownloaderError(
            "Winbindex has no Windows version '{}'. Known: {}.".format(
                windows, ", ".join(sorted({w for w, _ in updates}))
            )
        )
    out.write(f"Updates of {windows} with {name} (--update takes the name or a build):\n")
    for update in listed:
        files = find_files(index, name, update, fallback=False)
        arch = " ".join(BITNESS[folder] for folder, _, _ in SYSTEM_FOLDERS if folder in files)
        out.write(
            "  {:<10} {:<11} {:<30} {}\n".format(
                update.kb, update.date, " / ".join(update.builds) if update.builds else "first release", arch
            )
        )


def build_db(out_dir, update, os_version_hint, outfile, files=None):
    """the API DB of the folders, with the DatabaseBuilder that lies next to this script. With files, only those files
    of the folders are used."""
    import DatabaseBuilder

    paths = [
        os.path.join(out_dir, folder) for folder, _, _ in SYSTEM_FOLDERS if os.path.isdir(os.path.join(out_dir, folder))
    ]
    os_name, os_version = os_names(update, os_version_hint)
    builder = DatabaseBuilder.DatabaseBuilder()
    only_files = None if files is None else {os.path.abspath(path) for path in files}
    api_db = builder.extractRecursively(paths, False, os_name, os_version, only_files=only_files)
    if not api_db["dlls"]:
        raise DownloaderError("no DLLs to build an API DB from in {}.".format(", ".join(paths)))
    builder.persistApiDb(api_db, outfile)
    return api_db


def run(args, fetch=None, out=None):
    fetch = fetch or http_get
    out = out or sys.stdout
    cache_dir = os.path.join(args.out, ".winbindex") if args.out else None
    names = dll_names(args.dlls)
    if args.list is not None:
        name = args.list.lower() if args.list else "ntdll.dll"
        if not SAFE_NAME.match(name):
            raise DownloaderError(f"'{name}' is not a file name.")
        try:
            index = load_index(name, cache_dir, fetch)
        except NotFound:
            raise DownloaderError(f"Winbindex does not know {name}.") from None
        print_listing(index, name, args.windows, out)
        return 0
    if not args.update or not args.out:
        raise DownloaderError("--update and --out are required (--list shows the available updates).")
    # ntdll.dll exists in every build, so its index tells which update is meant
    try:
        ntdll_index = load_index("ntdll.dll", cache_dir, fetch)
        updates = list_updates(ntdll_index)
    except NotFound:
        raise DownloaderError("Winbindex does not know ntdll.dll.") from None
    update = select_update(updates, args.windows, args.update)
    kind, value = parse_update_selector(args.update)
    out.write("Update: {} on {}\n".format(update.description(), update.date or "-"))
    os_version_hint = value if kind == "build" else None
    if not os_version_hint and not update.release:
        # the first release has no build in the index, its ntdll.dll is the one of it
        ntdll = find_files(ntdll_index, "ntdll.dll", update).get("System32")
        if ntdll and ntdll[0].version.startswith("10.0."):
            os_version_hint = ntdll[0].version[len("10.0.") :]
    outfile = args.outfile or os.path.join(args.out, default_db_name(update))
    counts = {"downloaded": 0, "present": 0, "missing": 0, "rejected": 0, "failed": 0}
    problems = []
    verified = []
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(fetch_dll, name, update, args.out, cache_dir, fetch, verified): name for name in names}
        try:
            for number, future in enumerate(concurrent.futures.as_completed(futures), 1):
                name = futures[future]
                try:
                    results = future.result()
                except Exception as exc:  # a bug must not end the run of the other DLLs
                    results = [("failed", f"unexpected error: {exc}")]
                for status, _ in results:
                    counts[status] += 1
                    if status == "failed":
                        problems.append(name)
                out.write("[{:3d}/{}] {:<24} {}\n".format(number, len(names), name, "; ".join(m for _, m in results)))
                out.flush()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise
    out.write(
        "{downloaded} downloaded, {present} already present, {missing} not available, {rejected} rejected (not the "
        "file of Winbindex), {failed} failed".format(**counts)
        + f" in {time.time() - started:.0f} s.\n"
    )
    if args.download_only:
        return 1 if counts["failed"] else 0
    # the folders may hold files of another update or of other DLLs from an earlier run, only this run's go in
    others = other_files(args.out, verified)
    if others:
        out.write(
            "Left out of the DB, not verified as files of {}: {}{}.\n".format(
                update.kb, ", ".join(others[:10]), f" and {len(others) - 10} more" if len(others) > 10 else ""
            )
        )
    api_db = build_db(args.out, update, os_version_hint, outfile, files=verified)
    out.write("API DB {}: {} DLLs, {} APIs.\n".format(outfile, api_db["num_dlls"], api_db["num_apis"]))
    if counts["failed"]:
        out.write(
            f"Failed: {', '.join(sorted(set(problems)))}. Run the command again to retry these and build the DB.\n"
        )
        return 1
    return 0


def other_files(out_dir, files):
    """the DLLs in the folders of out_dir that are not among files, e.g. left from a run for another update"""
    kept = {os.path.abspath(path) for path in files}
    others = []
    for folder, _, _ in SYSTEM_FOLDERS:
        folder_path = os.path.join(out_dir, folder)
        if os.path.isdir(folder_path):
            for name in sorted(os.listdir(folder_path)):
                path = os.path.join(folder_path, name)
                if name.lower().endswith(".dll") and os.path.abspath(path) not in kept:
                    others.append(f"{folder}/{name}")
    return others


def clean_partial_files(out_dir):
    for folder, _, _ in SYSTEM_FOLDERS:
        folder_path = os.path.join(out_dir, folder)
        if os.path.isdir(folder_path):
            for name in os.listdir(folder_path):
                if name.endswith(".part"):
                    os.remove(os.path.join(folder_path, name))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build an API DB for a Windows build from DLLs of Microsoft's symbol server, found with Winbindex.",
        epilog="examples:\n"
        "  DllDownloader.py --list                           Windows versions Winbindex knows\n"
        "  DllDownloader.py --list --windows 11-24H2         the updates of one, with the architectures they have\n"
        "  DllDownloader.py --windows 11-24H2 --update KB5046617 --out win11\n"
        "  DllDownloader.py --update 10.0.26100.2605 --out win11     the same, by build\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--windows", metavar="VERSION", help="Windows version as Winbindex names it: 1607, 21H2, 11-24H2"
    )
    parser.add_argument(
        "--update", metavar="KB|BUILD", help="update (KB5046617), build (26100.2605) or BASE (first release)"
    )
    parser.add_argument(
        "--list",
        nargs="?",
        const="",
        metavar="DLL",
        help="list Windows versions (or, with --windows, updates) that Winbindex knows for a DLL (default ntdll.dll)",
    )
    parser.add_argument("--out", help="folder for System32, SysWOW64, the API DB and the cache of the Winbindex data")
    parser.add_argument("--outfile", help="the API DB file (default: in --out)")
    parser.add_argument("--download-only", action="store_true", help="only download the DLLs, do not build the API DB")
    parser.add_argument("--dlls", nargs="+", metavar="NAME", help="DLL file names to get instead of config.DLL_FILTER")
    parser.add_argument("--jobs", type=int, default=4, help="parallel downloads (default 4, at most 8)")
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 8:
        parser.error("--jobs is between 1 and 8.")
    try:
        if args.list is None and args.out:
            clean_partial_files(args.out)
        return run(args)
    except DownloaderError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except KeyboardInterrupt:
        sys.stderr.write("interrupted, run the same command again to continue.\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
