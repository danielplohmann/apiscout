# Changelog

 * 2026-11-17: v3.0.0 - (BREAKING) Python 2 and IDA before 9.0 are no longer supported, and the scripts `scout.py`, `match.py`, `export.py`, `collect.py` and `update.py` are replaced by the `apiscout` command. Packaging moved to `pyproject.toml` (with `uv.lock`), code is linted and formatted with ruff and type checked with ty, CI runs on GitHub Actions, and a release published on GitHub is tested, built and uploaded to PyPI by a workflow (trusted publishing, with attestations).
   * Command line: `pip install apiscout` installs the `apiscout` command with the sub commands `scan`, `match`, `export`, `collect`, `update` and `dbs`. It prints JSON with `--json`, takes API DBs from `--db`, `--db-dir` or `$APISCOUT_DB_DIR`, reads and writes standard input and output with `-`, and its errors say what to do. `update` reads the Malpedia token from a file instead of `config.py`.
   * Library: fixed a crash when a buffer ends in `FF 15`/`FF 25`, import tables (`apiscout scan --import-table`) are read by the own parser only, which gave the same imports as LIEF on all files tested and is bounded for crafted files, so LIEF is no longer a dependency, import descriptors without import name table, PE mapping of truncated or unusual files, matching of vectors given as lists, `NaN` when matching empty vectors, and API DBs of the same OS replacing each other. Crawl results are now ordered by offset. Imports by ordinal are resolved for `ws2_32.dll`, `wsock32.dll` and `oleaut32.dll`, compressed ApiVectors are validated, and a 32bit and a 64bit export at the same address are both resolved.
   * The ApiQR export works again, the update works from any directory, and updating a collection no longer writes a second file.
   * IDA: `ida_scout.py` is a plugin now (see the README) with a dockable results view instead of a modal dialog, a batch mode and `ida-plugin.json` for the plugin manager. APIs are also annotated when their location was defined as something else before, type libraries match the bitness of the database and include ntapi, API locations are typed as function pointers, and the decompiler shows the API names for dumps loaded as binary file.
   * Ghidra: the script runs `python3 -m apiscout` and asks for the folder with the API DBs (headless, its arguments are the API DBs only). It scans the program's memory instead of the imported file, keeps all references to an API, annotates them like imports (external references and prototypes) and can be run headless.
   * DB Builder: `--os_name`/`--os_version` build a DB from a copy of the DLLs on any OS, `--load_addresses` takes the ASLR offsets from a module list (lines of `<hex load address> <DLL path>`) instead of loading each DLL; DLLs are matched by folder and file name, or by file name alone where it is unique. The DLL filter covers DLLs of current Windows versions.
 * 2026-11-16: Added a Windows Server 2022 (21H2, build 20348) 64bit import DB (`dbs/win2022_server_21h2_example.json`, 343 DLLs, built with `DatabaseBuilder.py --filter` on a fresh installation). Like the Windows 10 DB, it carries the ASLR offsets of the boot it was built in and serves as example and for tests, not for dumps of other systems.
 * 2026-11-16: Follow-ups for the Windows 10 DB: `collect.py` now skips API DBs with ASLR offsets unless `--use_aslr_dbs` or `--ignore_aslr` is given (`FingerprintCrawler` got an `ignore_aslr_offsets` parameter) and loading a DB warns about many colliding addresses. ApiVector now matches DLL names case-insensitively (e.g. `IPHLPAPI.DLL`). Fixed `ws2_32.dll` being truncated in the JSON output of `scout.py`, missed references of 64bit `jmp [rip+x]` thunks, the base address of PE32+ headers and 64bit imports by ordinal. Tests now run with `unittest` instead of nose.
 * 2026-11-01: Added Windows 10 Pro 1803 (build 17134.1) 64bit import DB, including the ASLR offsets of the boot it was built in (as all 64bit system DLLs share the file ImageBase 0x180000000). These offsets are only valid for memory dumps from that very boot; for other dumps, use import table parsing (`scout.py -t`) or rebuild the DB on the system the dump was taken from. `scout.py --ignore_aslr` (`ApiScout.ignoreAslrOffsets(True)`) is only meaningful for systems without ASLR and not usable for this DB's 64bit DLLs, as they then overlap at 0x180000000. Also note that the offsets of several rarely loaded DLLs in this DB (mostly 32bit ones, e.g. iphlpapi.dll, wininet.dll) put them at overlapping addresses, so APIs of these DLLs may be resolved incorrectly. Also fixed two DB Builder bugs: version 0.0.0.0 was written for all DLLs, and ordinal-only exports were truncated for DLLs mapping many ordinals to one address (e.g. mfc42.dll lost ~90% of its exports).
 * 2023-03-27: v2.0.2 - Bugfix for IdaScout and handling of sets, contributed by @7a6570 (THX!!)
 * 2023-01-02: v2.0.1 - Bugfix for lief-based import table parsing with Python 3.10, contributed by @malware-kitten (THX!!)
 * 2022-08-01: v1.2.0 - Added plugin for Ghidra, contributed by @mari-mari (THX!!)
 * 2022-09-20: v2.0.0 - (potentially BREAKING) crawl results now have one additional output field with a set of calling references for a given WinAPI. This is also included in the JSON output of `scout.py`, contributed by @renzhexigua (THX!!)
 * 2022-08-01: v1.2.0 - Added plugin for Ghidra, contributed by @mari-mari (THX!!)
 * 2022-01-17: v1.1.9 - Fixed `ida_scout.py` to work with IDA 7.5+ when apiscout is also installed as a Python package.
 * 2021-10-04: v1.1.8 - Extension of winapi contexts based on observations provided by @blattm (THX!).
 * 2021-08-30: v1.1.7 - Fixed deprecation warning in ApiQR as raised by numpy.
 * 2021-07-31: v1.1.6 - It's no longer required to keep a fixed LIEF version. (THX to @cccs-rs!)
 * 2021-01-10: v1.1.5 - Python3 LIEF package fixed to version 0.10.1 (THX to @akhribfarouk!)
 * 2020-12-09: v1.1.4 - Python3 fixes on DatabaseBuilder (THX to @Dump-GUY!)
 * 2020-07-13: v1.1.3 - Added "install_requires" to setup.py to ensure dependencies are installed.
 * 2020-06-30: v1.1.0 - Now using LIEF for import table parsing. Fixed bug which would not produce ApiVectors when using import table parsing. ApiScout is now also available through PyPI.
 * 2020-03-03: Added a script to pull the most recent ApiVector DB from Malpedia (requires Malpedia account / API token).
 * 2020-03-02: Ported to IDA 7.4 (THX to @jenfrie).
 * 2020-02-18: DB Builder is now compatible up to Python 3.7 (THX to @elanfer).
 * 2019-10-08: Workaround for broken filtering of the API view in IDA 7.3 (THX to @enzok for pointing this out).
 * 2019-08-22: Fixed a bug where missing type info in IDA would lead to a crash (now gives an error message instead).
 * 2019-08-20: Added self-filter to eliminate pointers to own memory image that could be mistakenly treated as API references.
 * 2019-06-06: Added support for proper type reconstruction for annotated APIs in IDA Pro (THX to @FlxP0c)
 * 2019-05-15: Added numpy support for vector calculations (based on implementation provided by @garanews - THX!)
 * 2019-05-15: Fixed a bug in PE mapper where buffer would be shortened because of misinterpretation of section sizes.
 * 2019-01-23: QoL improvements: automated data folder deployment when used as module, logger initialization (THX to @jdval)
 * 2018-08-23: Fixed a bug in PE mapper where the PE header would be overwritten by (empty) section data.
 * 2018-08-21: Added functionality that allows to use import table information instead of crawling for references.
 * 2018-07-31: Fixed convenience functions to create/export vectors from/to lists and dicts, added test coverage.
 * 2018-07-23: WARNING: Change in Apivector format -- Introduced sorted ApiVectors which are even more space efficient (20%+).
 * 2018-06-25: Fixed incompatibility with IDA Pro 7.0+ (THX to @nazywam!)
 * 2018-05-23: Added further semantic context groups (THX to Quoscient.io)
 * 2018-03-27: Heuristic estimation of Windows API reference counts added
 * 2018-03-06: ApiQR visualization of vector results (C-1024)
 * 2017-11-28: Added own import table parser to enrich result information
 * 2017-08-24: Multi-Segment support in IDA Pro (THX to @nazywam!)
 * 2017-05-31: Added Windows 7 SP1 64bit import DB (compatible to Malpedia)
