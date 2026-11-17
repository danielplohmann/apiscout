# ApiScout

ApiScout recovers the Windows API calls of malware from memory dumps.

A dumped process has no usable import table any more, but it still holds the addresses of the API functions it calls. ApiScout checks every pointer-sized value of a dump against a database of the API addresses of the system the dump was taken from. The result is the list of APIs the code uses, where it references them, and an **ApiVector**: a compact fingerprint of API usage that can be compared with those of other samples to find the malware family.

It comes as a command line tool, a Python library, a plugin for IDA Pro and a script for Ghidra.

![IDA Pro listing the API references ApiScout found in a memory dump](docs/images/ida.png)

## Quick start

ApiScout needs Python 3.10 or newer.

```bash
pip install apiscout
```

You also need a memory dump and an API DB. An API DB describes one Windows installation: which DLL exports which function at which address. The repository has example DBs for Windows XP SP3 and Windows 7 SP1, the systems most dumps of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) were taken on, so they fit the dumps published there:

```bash
curl -LO https://raw.githubusercontent.com/danielplohmann/apiscout/master/dbs/win7_prof-n_sp1_example.json
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json
```

```text
Results for API DB: Microsoft Windows 7 Professional N
idx: offset    ; VA                ; IT?; #ref;DLL                                     ; API
  1: 0x00409aef;         0x10006839; err;    1; devrtl.dll_0x10000000 (32bit)           ; NdxTableAddObjectToList
---------------------------------------------------------------------------------------------------
  2: 0x00420000;         0x41ac4b1b; err;    4; ws2_32.dll_0x41ac0000 (32bit)           ; freeaddrinfo
  3: 0x00420004;         0x41ac4296; err;    3; ws2_32.dll_0x41ac0000 (32bit)           ; getaddrinfo
  4: 0x00420008;         0x41aca05b; err;    2; ws2_32.dll_0x41ac0000 (32bit)           ; gethostname
  [...]
DLLs: 15, APIs: 183, references: 496

WinApi1024 Vector Results:
Microsoft Windows 7 Professional N: 154 / 181 (85.08%) APIs covered in WinApi1024 vector.
    Vector:     A22gQAAgABA6QACA9EAACA9gAIA9oCA4kAgRAABAAwA7CEARBADCggIAEAAJAIB.gBAEEIoAjEBIACTGgwdjTATJnJCCHpAgwNKeAJ^BFJuYAgCYQEYdn_^?
    Confidence: 89.37009000226523
```

How to read the listing:

| Column | Meaning |
| :--- | :--- |
| `offset` | Where the API address is stored in the dump. |
| `VA` | The API address found there. |
| `IT?` | Whether the location lies in the import table of the dump: `yes`, `no`, or `err` if the dump has no import table that can be read, which is the normal case for dumped code. |
| `#ref` | The location itself plus the `call` and `jmp` instructions that go through it. |
| `DLL` | The DLL, the address it is loaded at according to the DB, and whether it is the 32bit or 64bit one. |

A single API far away from all others, like the first row, is usually a chance hit: some bytes that happen to equal an API address. `--filter 32` drops APIs that have no other API within 32 bytes.

`Confidence` (0 to 100) says how much a vector is worth as fingerprint. It is low when only few or only very common APIs were found.

The offsets are only right if ApiScout knows the address the dump was taken from. It reads the address from a file name that ends in `0x` and 8 to 16 hex digits, as in `dump_0x00400000`. For any other name, pass `--base-addr 0x400000`; without it, the base address is 0.

No dump at hand? Any Windows program or DLL will do for a first try. For a PE file as stored on disk, the import table is read and no API DB is needed:

```bash
apiscout scan sample.exe --import-table
```

> [!IMPORTANT]
> A scan only finds APIs if the DB describes the system the dump was taken on: same Windows build, same DLL versions, same DLL load addresses. The example DBs for Windows XP and Windows 7 come from analysis machines on which ASLR was switched off, so their DLLs are always loaded at the same addresses. With ASLR, the addresses change with every boot, and a DB has to be built on the machine during the boot the dump is taken in. See [API DBs](#api-dbs).

## What you can do with it

### Name the malware family of a dump

An ApiVector records which of 1024 selected APIs a sample uses. Malpedia publishes the vectors of its samples as a collection. Downloading it needs a Malpedia account, the `requests` package and the API token of the account in a file:

```bash
pip install 'apiscout[update]'
mkdir -p ~/.config/apiscout
# store the API token of your account as only line of ~/.config/apiscout/malpedia-token
apiscout update --db-dir .
```

`update` stores the collection as `<date>-apivectors-v<version>.csv` in the folder given. A scan can then list the families with the most similar API usage:

```bash
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json --collection 2026-11-09-apivectors-v26649.csv
```

The end of its output, shortened:

```text
Top 5 individual matches
win.trickbot    - 2021-10-05-v2000035/97b489b89e6818767adde8c8f42778c04beb1512db4e4d0b6649413a2e99e6ae - 1.000
win.trickbot    - 2017-07-24/2ebeef906142f328168e7e62e8be7fbaee48e3521853d76ea778005ada6e938a          - 0.492
```

`apiscout match` compares a vector you already have with a collection or with a second vector. Vectors contain characters that are special to the shell, so quote them:

```bash
apiscout match 'A22gQAAgABA6QACA9EAACA9gAIA9oCA4kAgRAABAAwA7CEARBADCggIAEAAJAIB.gBAEEIoAjEBIACTGgwdjTATJnJCCHpAgwNKeAJ^BFJuYAgCYQEYdn_^?' --collection 2026-11-09-apivectors-v26649.csv
```

`apiscout collect` builds a collection from your own folder of dumps, with one sub folder per family.

### See what a sample is about

`apiscout export` draws a vector as ApiQR diagram. Each of the 1024 APIs has a fixed place and a colour for its topic (among them GUI, system, execution, strings, network, files, devices, crypto, memory and registry), so samples with similar capabilities look alike. The HTML version names each API when the mouse is over it.

```bash
apiscout export 'A22gQAAgABA6QACA9EAACA9gAIA9oCA4kAgRAABAAwA7CEARBADCggIAEAAJAIB.gBAEEIoAjEBIACTGgwdjTATJnJCCHpAgwNKeAJ^BFJuYAgCYQEYdn_^?' --png vector.png --html vector.html
```

<img src="docs/images/apiqr.png" alt="ApiQR diagram of a TrickBot dump" width="256">

### Annotate a dump in IDA Pro or Ghidra

Both integrations name the API pointers, type them and apply the prototypes to the calls, so that the disassembly and the decompiler read like those of a file with an intact import table. See [IDA Pro](#ida-pro) and [Ghidra](#ghidra).

### Use the results in your own tools

`scan`, `match` and `dbs` print JSON with `--json`. `-` stands for standard input or output wherever a file is expected, so commands can be chained:

```bash
apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json --json | jq -r '.apis[].api' | sort -u
apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json --json | apiscout match - --collection 2026-11-09-apivectors-v26649.csv
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

`apiscout <command> --help` lists the options with their defaults and examples. Results go to standard output, progress and errors to standard error; `-q` leaves only results and errors. The exit code is 0 on success, 1 on an error and 2 for a wrong command line.

API DBs are taken from `--db` (repeatable). Without it, all DBs of one folder are used: `--db-dir`, else `$APISCOUT_DB_DIR`, else `./dbs`.

`apiscout update` reads the Malpedia token from `~/.config/apiscout/malpedia-token` (`$XDG_CONFIG_HOME` is honoured) or from a file given with `--token-file`. The token is never taken from the command line or the environment.

The scripts of earlier versions (`scout.py`, `match.py`, `export.py`, `collect.py`, `update.py`) are replaced by these commands, see the [changelog](CHANGELOG.md).

## API DBs

| File in [`dbs`](dbs) | System | ASLR offsets |
| :--- | :--- | :---: |
| `winxp_prof_sp3_example.json` | Windows XP Professional SP3, 32bit DLLs | no |
| `win7_prof-n_sp1_example.json` | Windows 7 Professional N SP1, 32bit and 64bit DLLs | no |
| `win10_prof_1803_example.json` | Windows 10 Pro 1803, 32bit and 64bit DLLs | yes |
| `win2022_server_21h2_example.json` | Windows Server 2022 21H2, 32bit and 64bit DLLs | yes |

The Windows XP and Windows 7 DBs were built on systems without ASLR and fit dumps from such systems. The Windows 10 and Windows Server 2022 DBs carry the load addresses of the boot they were built in. They show the format and serve the tests, but do not fit dumps from other machines.

The DB builder, the IDA plugin and the Ghidra script are not part of the Python package. They come with the repository:

```bash
git clone https://github.com/danielplohmann/apiscout
```

To build a DB for your own analysis system, run the DB builder on it. It needs Python and nothing else, and writes the DB as JSON file into the current folder:

```bash
cd apiscout/apiscout/db_builder
python DatabaseBuilder.py --auto
```

`--auto` takes the commonly used DLLs of the system folders and their ASLR offsets, `--paths` and `--filter` choose folders and DLLs. It also runs on other operating systems for a copy of the DLLs (`--os_name`, `--os_version`); the load addresses then come from the module list of a process on the target system (`--load_addresses`, lines of `<hex load address> <DLL path>`).

## IDA Pro

`ida_scout.py` from the repository works as plugin and as script (File > Script file...) with IDA 9.0 and newer. To use it as plugin, install it with the plugin manager (`hcli plugin install <path to the cloned repository>`) or link the repository into `$IDAUSR/plugins`; it is then available as Edit > Plugins > ApiScout (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd>).

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

Install ApiScout for the `python3` on the `PATH` (`pip install apiscout`), copy `GhidraScout.java` from the repository into a script directory of Ghidra and run it from the Script Manager (ticking its "In Tool" checkbox adds it as Tools > ApiScout). It asks for the folder with the API DBs once and scans the memory of the current program. Tested with Ghidra 12.2.

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

A release published on GitHub is built and uploaded to PyPI by `.github/workflows/release.yml`. It uses [trusted publishing](https://docs.pypi.org/trusted-publishers/), which has to be set up once in the PyPI project for this repository, the workflow `release.yml` and the environment `pypi`.

Questions and bug reports are welcome as [issues](https://github.com/danielplohmann/apiscout/issues). ApiScout is written by Daniel Plohmann and [contributors](https://github.com/danielplohmann/apiscout/graphs/contributors) and licensed under the [BSD 2-Clause License](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
