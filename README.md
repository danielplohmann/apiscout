# ApiScout

ApiScout recovers the Windows API calls of malware from memory dumps.

A dumped process has no usable import table any more, but it still holds the addresses of the API functions it calls. ApiScout checks every pointer-sized value of a dump against a database of the API addresses of the system the dump was taken from. The result is the list of APIs the code uses, where it references them, and an **ApiVector**: a compact fingerprint of API usage that can be compared with those of other samples to find the malware family.

It comes as a command line tool, a Python library, a plugin for IDA Pro and a script for Ghidra.

![IDA Pro listing the API references ApiScout found in a memory dump](docs/images/ida.png)

## Quick start

```bash
pip install apiscout
```

An API DB describes one Windows installation. The repository has example DBs for Windows XP SP3 and Windows 7 SP1, the systems the dumps of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) were mostly taken on. For dumps from your own sandbox, [build a DB](#api-dbs) on it.

```bash
curl -LO https://raw.githubusercontent.com/danielplohmann/apiscout/master/dbs/win7_prof-n_sp1_example.json
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json
```

```text
Scanned 147456 bytes at base address 0x400000 with 97310 APIs of 1 DBs.

Results for API DB: Microsoft Windows 7 Professional N
idx: offset    ; VA                ; IT?; #ref;DLL                                     ; API
  1: 0x00420000;         0x41ac4b1b; err;    4; ws2_32.dll_0x41ac0000 (32bit)           ; freeaddrinfo
  2: 0x00420004;         0x41ac4296; err;    3; ws2_32.dll_0x41ac0000 (32bit)           ; getaddrinfo
  3: 0x00420008;         0x41aca05b; err;    2; ws2_32.dll_0x41ac0000 (32bit)           ; gethostname
...
WinApi1024 Vector Results:
Microsoft Windows 7 Professional N: 154 / 181 (85.08%) APIs covered in WinApi1024 vector.
    Vector:     A22gQAAgABA6QACA9EAACA9gAIA9oCA4kAgRAABAAwA7CEARBADCggIAEAAJAIB.gBAEEIoAjEBIACTGgwdjTATJnJCCHpAgwNKeAJ^BFJuYAgCYQEYdn_^?
    Confidence: 89.37009000226523
```

The base address is read from a file name that ends in `0x<address>`, as memory dumps are commonly named; `--base-addr` sets it otherwise. `#ref` counts the location itself plus the `call`/`jmp` instructions that go through it.

For a PE file that was not unpacked or dumped, the import table is enough and no API DB is needed:

```bash
apiscout scan sample.exe --import-table
```

> [!IMPORTANT]
> A scan only finds APIs if the DB matches the system of the dump. On Windows versions with ASLR, DLLs are loaded at other addresses after every boot, so a DB for them has to be built on the very system the dump comes from, during the same boot. See [API DBs](#api-dbs).

## What you can do with it

### Name the malware family of a dump

An ApiVector records which of 1024 selected APIs a sample uses. Malpedia publishes the vectors of its samples; with an account, `apiscout update` downloads the current collection. A scan can then list the families with the most similar API usage:

```bash
apiscout update --db-dir dbs
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json --collection dbs/2026-11-09-apivectors-v26649.csv
```

Shortened output:

```text
Top 5 individual matches
win.trickbot    - 2021-10-05-v2000035/97b489b89e6818767adde8c8f42778c04beb1512db4e4d0b6649413a2e99e6ae - 1.000
win.trickbot    - 2017-07-24/2ebeef906142f328168e7e62e8be7fbaee48e3521853d76ea778005ada6e938a          - 0.492
```

`apiscout match` compares a vector you already have, either with a collection or with a second vector. `apiscout collect` builds a collection from your own folder of dumps.

### See what a sample is about

`apiscout export <vector> --png vector.png` draws a vector as ApiQR diagram. The 1024 APIs are laid out on a curve and coloured by topic (networking, file system, crypto, GUI, ...), so samples with similar capabilities look alike. `--html` writes a page that names each API on hover.

<img src="docs/images/apiqr.png" alt="ApiQR diagram of a TrickBot dump" width="256">

### Annotate a dump in IDA Pro or Ghidra

Both integrations name the API pointers, type them and apply the prototypes to the calls, so that the disassembly and the decompiler read like those of a file with an intact import table. See [IDA Pro](#ida-pro) and [Ghidra](#ghidra).

### Use the results in your own tools

Every command that prints results has `--json`, and `scan` reads a dump from standard input when the file is `-`:

```bash
apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json --json | jq -r '.apis[].api' | sort -u
```

From Python:

```python
from apiscout.ApiScout import ApiScout

scout = ApiScout("win7_prof-n_sp1_example.json")
scout.setBaseAddress(0x400000)
with open("trickbot_dump_0x00400000", "rb") as f_dump:
    results = scout.crawl(f_dump.read())
for apis in results.values():
    for offset, api_address, dll, api, bitness, in_import_table, references, callers in apis:
        print(hex(0x400000 + offset), dll, api, references)
vector = scout.getPrimaryVector(scout.getWinApi1024Vectors(results))[1]["vector"]
```

## Commands

| Command | Purpose |
| :--- | :--- |
| `apiscout scan <dump>` | List the APIs referenced in a memory dump and its ApiVector. `--import-table` reads the import table of a PE file instead. |
| `apiscout match <vector> [<vector>]` | Compare a vector with another one, or with a collection given by `--collection`. |
| `apiscout export <vector>` | Draw a vector as ApiQR diagram (`--png`, `--html`). |
| `apiscout collect <folder>` | Build a collection of ApiVectors from a folder of dumps, one sub folder per family. |
| `apiscout update` | Download the current ApiVector collection from Malpedia. |
| `apiscout dbs` | Show the API DBs that are available. |

`apiscout <command> --help` lists the options with their defaults. Results go to standard output, progress and errors to standard error; `-q` leaves only the results. The exit code is 0 on success, 1 on an error and 2 for a wrong command line.

API DBs are taken from `--db` (repeatable). Without it, all DBs of one folder are used: `--db-dir`, else `$APISCOUT_DB_DIR`, else `./dbs`.

`apiscout update` needs the `requests` package (`pip install 'apiscout[update]'`) and the API token of your Malpedia account in `~/.config/apiscout/malpedia-token`, or in a file given with `--token-file`.

The scripts of earlier versions (`scout.py`, `match.py`, `export.py`, `collect.py`, `update.py`) are replaced by these commands, see the [changelog](CHANGELOG.md).

## API DBs

| File in [`dbs`](dbs) | System | ASLR offsets |
| :--- | :--- | :---: |
| `winxp_prof_sp3_example.json` | Windows XP Professional SP3, 32bit DLLs | no |
| `win7_prof-n_sp1_example.json` | Windows 7 Professional N SP1, 32bit and 64bit DLLs | no |
| `win10_prof_1803_example.json` | Windows 10 Pro 1803, 32bit and 64bit DLLs | yes |
| `win2022_server_21h2_example.json` | Windows Server 2022 21H2, 32bit and 64bit DLLs | yes |

The Windows XP and Windows 7 DBs were built on systems without ASLR and fit dumps from such systems. The Windows 10 and Windows Server 2022 DBs carry the load addresses of the boot they were built in. They show the format and serve the tests, but do not fit dumps from other machines.

To build a DB for your own analysis system, run the DB builder on it:

```bash
cd apiscout/db_builder
python DatabaseBuilder.py --auto
```

`--auto` takes the commonly used DLLs of the system folders and their ASLR offsets, `--paths` and `--filter` choose folders and DLLs. It also runs on other operating systems for a copy of the DLLs (`--os_name`, `--os_version`); the load addresses then come from the module list of a process on the target system (`--load_addresses`, lines of `<hex load address> <DLL path>`).

## IDA Pro

`ida_scout.py` works as plugin and as script (File > Script file...) with IDA 9.0 and newer. To use it as plugin, install it with the plugin manager (`hcli plugin install <path to apiscout>`) or link the repository into `$IDAUSR/plugins`; it is then available as Edit > Plugins > ApiScout (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd>).

After choosing the API DBs, the API references found are listed in the dockable ApiScout view shown at the top of this page.

| Key | Action |
| :--- | :--- |
| <kbd>Enter</kbd> or double click | Jump to the reference |
| <kbd>A</kbd> | Annotate the selected APIs |
| <kbd>Shift</kbd>+<kbd>A</kbd> | Annotate all APIs of the view (IDA's quick filter only hides rows) |
| <kbd>F</kbd> | Only show APIs with a neighbour within a given distance |
| <kbd>Ctrl</kbd>+<kbd>U</kbd> | Scan the database again |

Annotating an API names its location, types it as pointer to the API's prototype and applies the prototype to the calls referencing it. Memory dumps should be loaded as binary file at the address they were dumped from.

In batch mode, all references are annotated:

```bash
idat -A -TBinary -b<dump address / 16, hex> -pmetapc -S"ida_scout.py <API DB> [<API DB> ...]" <dump>
```

The segment base that `-b` sets is reset to 0 so that calls reference the API pointers, and the database is saved when the script is done. A database that was analysed with such a base before is repaired as far as possible; functions that IDA split under the base stay split, switches it missed there are not recovered, and `noreturn` flags are determined again, so the batch command is best run on the dump itself. Without `-TBinary`, IDA loads a dump that starts with a PE header as file instead of as memory image, and idat creates a 64bit database for binary files, so 32bit dumps are best prepared as database first.

## Ghidra

Install ApiScout for the `python3` on the `PATH` (`pip install apiscout`), copy `GhidraScout.java` into a script directory of Ghidra and run it from the Script Manager (ticking its "In Tool" checkbox adds it as Tools > ApiScout). It asks for the folder with the API DBs once and scans the memory of the current program. Tested with Ghidra 12.2.

The table lists the API references found, the selected ones are annotated like imports: a pointer with an external reference to the function of its library, with the prototype of Ghidra's Windows data type archive.

![Ghidra listing with API pointers annotated as external functions](docs/images/ghidra.png)

Headless:

```bash
analyzeHeadless <project> <name> -import <dump> -loader BinaryLoader -loader-baseAddr <address> -processor x86:LE:64:default -postScript GhidraScout.java <API DB> [<API DB> ...]
```

## Background

* [ApiScout: Painless Windows API information recovery](http://byte-atlas.blogspot.com/2017/04/apiscout.html) describes the method.
* [ApiVectors](https://byte-atlas.blogspot.com/2018/04/apivectors.html) explains how the fingerprints are built and stored.
* [ApiScout: Robust Windows API Usage Recovery for Malware Characterization and Similarity Analysis](https://cyberjournal.cecyf.fr/index.php/cybin/en/article/download/20/15/50) (Botconf 2018) evaluates it over Malpedia.

## Development

ApiScout requires Python 3.10 or newer. [uv](https://docs.astral.sh/uv/) sets up the environment:

```bash
uv sync
uv run python -m unittest discover -s tests -p "test*.py" -t .
uv run ruff check && uv run ruff format --check && uv run ty check
```

Questions and bug reports are welcome as [issues](https://github.com/danielplohmann/apiscout/issues). ApiScout is written by Daniel Plohmann and [contributors](https://github.com/danielplohmann/apiscout/graphs/contributors) and licensed under the [BSD 2-Clause License](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
