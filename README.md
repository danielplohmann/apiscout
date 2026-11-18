# ApiScout

ApiScout recovers the Windows API calls of malware from memory dumps.

A dumped process has no usable import table any more, but it still holds the addresses of the API functions it calls. ApiScout checks every pointer-sized value of a dump against a database of the API addresses of the system the dump was taken from. The result is the list of APIs the code uses, where it references them, and an **ApiVector**: a compact fingerprint of API usage that can be compared with those of other samples to find the malware family.

It comes as a command line tool, a Python library, a plugin for IDA Pro, a script for Ghidra and a plugin for Binary Ninja.

![IDA Pro listing the API references ApiScout found in a memory dump](https://raw.githubusercontent.com/danielplohmann/apiscout/master/docs/images/ida.png)

## Quick start

```bash
pip install apiscout
```

ApiScout needs Python 3.10 or newer, a memory dump and an API DB, which describes one Windows installation: which DLL exports which function at which address. The repository has example DBs for Windows XP SP3 and Windows 7 SP1. Most dumps of [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) were taken on these systems, so the example DBs fit them:

```bash
apiscout dbs download
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json
```

`dbs download` stores the example DBs in your user data folder (`~/.local/share/apiscout/dbs` on Linux), where `scan` finds them by name.

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

The base address of the dump is read from a file name that ends in `0x` and 8 to 16 hex digits. For any other name, pass it with `--base-addr 0x400000`.

No dump at hand? A Windows program will do for a first try. Its import table is read, and no API DB is needed. Programs that ship with Windows itself import through API sets (`api-ms-win-...`), which the vector does not cover, so pick a third-party one:

```bash
apiscout scan sample.exe --import-table
```

<details>
<summary>How to read the listing</summary>

| Column | Meaning |
| :--- | :--- |
| `offset` | Where the API address is stored in the dump. |
| `VA` | The API address found there. |
| `IT?` | Whether the location lies in the import table of the dump: `yes`, `no`, or `err` if the dump has no import table that can be read, which is normal for dumped code. |
| `#ref` | The location itself plus the `call` and `jmp` instructions that go through it. |
| `DLL` | The DLL, the address it is loaded at according to the DB, and whether it is the 32bit or 64bit one. |

A single API far away from all others, like the first row, is usually a chance hit: bytes that happen to equal an API address. `--filter 32` drops APIs that have no other API within 32 bytes.

`Confidence` (0 to 100) says how much a vector is worth as a fingerprint. It is low when only few or only very common APIs were found.

</details>

> [!IMPORTANT]
> A scan only finds APIs if the DB describes the system the dump was taken on: same DLL versions, same DLL load addresses. The example DBs for Windows XP and Windows 7 come from analysis machines with ASLR switched off, where DLLs are always loaded at the same addresses. With ASLR, the addresses change with every boot, and a DB has to be built on the machine during the boot the dump is taken in. See [API DBs](#api-dbs).

## Features

### Name the malware family of a dump

An ApiVector records which of 1024 selected APIs a sample uses. Malpedia publishes the vectors of its samples as a collection, and a scan can list the families whose API usage is most similar:

```bash
apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json --collection 2026-11-09-apivectors-v26649.csv
```

```text
[...]
Top 5 individual matches
win.trickbot    - 2021-10-05-v2000035/97b489b8[...]  - 1.000
win.trickbot    - 2017-07-24/2ebeef90[...]           - 0.492
```

`apiscout match` does the same for a vector you already have, and `apiscout collect` builds a collection from your own dumps.

<details>
<summary>Getting the collection from Malpedia</summary>

This needs a Malpedia account, the `requests` package and the API token of the account in a file:

```bash
pip install 'apiscout[update]'
mkdir -p ~/.config/apiscout
# store the API token as the only line of ~/.config/apiscout/malpedia-token
apiscout update --db-dir .
```

The collection is stored as `<date>-apivectors-v<version>.csv` in the folder given. The token is read from that file or from one given with `--token-file`, never from the command line or the environment.

</details>

### See what a sample is about

`apiscout export` draws a vector as an ApiQR diagram. Each of the 1024 APIs has a fixed place and a colour for its topic, among them GUI, system, execution, strings, network, files, devices, crypto, memory and registry. Samples with similar capabilities look alike. The HTML version names each API when the mouse is over it.

<img src="https://raw.githubusercontent.com/danielplohmann/apiscout/master/docs/images/apiqr.png" alt="ApiQR diagram of a TrickBot dump" width="256">

```bash
VECTOR=$(apiscout scan trickbot_dump_0x00400000 --db win7_prof-n_sp1_example.json --json | jq -r .apivector)
apiscout export "$VECTOR" --png vector.png --html vector.html
```

Vectors contain characters that are special to the shell. Quote them, or keep them in a variable as here.

### Annotate a dump in IDA Pro, Ghidra or Binary Ninja

The integrations name the API pointers, type them and apply the prototypes to the calls. The disassembly and the decompiler then read like those of a file with an intact import table. See [IDA Pro](#ida-pro), [Ghidra](#ghidra) and [Binary Ninja](#binary-ninja).

### Use the results in your own tools

`--json` prints machine-readable results. `-` reads the dump or the vector from standard input and writes a result to standard output, so commands can be chained ([jq](https://jqlang.org) picks values from JSON):

```bash
export APISCOUT_DB_DIR=~/apiscout-dbs    # the folder with your API DBs, instead of --db
apiscout scan dump_0x00400000 --json | jq -r '.apis[].api' | sort -u
apiscout scan dump_0x00400000 --json | apiscout match - --collection apivectors.csv
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
| `apiscout scan <dump>` | List the APIs referenced in a memory dump, with its ApiVector |
| `apiscout match <vector>` | Compare a vector with a second one or with a collection |
| `apiscout export <vector>` | Draw a vector as an ApiQR diagram |
| `apiscout collect <folder>` | Build a collection of ApiVectors from a folder of dumps |
| `apiscout update` | Download the current collection from Malpedia |
| `apiscout dbs` | Show the API DBs that are available |
| `apiscout dbs download` | Download the example API DBs of the repository |

`apiscout <command> --help` lists the options with examples.

- API DBs are given with `--db`, which can be repeated. Without it, all DBs of one folder are used: `--db-dir`, else `$APISCOUT_DB_DIR`, else `./dbs`, else the folder `dbs download` stores them in.
- Results go to standard output, progress and errors to standard error. `-q` leaves only results and errors.
- The exit code is 0 on success, 1 on an error and 2 for a wrong command line.

## API DBs

| File in [`dbs`](https://github.com/danielplohmann/apiscout/tree/master/dbs) | System | ASLR offsets |
| :--- | :--- | :---: |
| `winxp_prof_sp3_example.json` | Windows XP Professional SP3, 32bit DLLs | no |
| `win7_prof-n_sp1_example.json` | Windows 7 Professional N SP1, 32bit and 64bit DLLs | no |
| `win10_prof_1803_example.json` | Windows 10 Pro 1803, 32bit and 64bit DLLs | yes |
| `win2022_server_21h2_example.json` | Windows Server 2022 21H2, 32bit and 64bit DLLs | yes |
| `win11_pro_26h2_example.json` | Windows 11 Pro 26H2, 32bit and 64bit DLLs | yes |

`apiscout dbs download` fetches them from the release tag of the installed version and checks them against [`dbs/SHA256SUMS`](https://github.com/danielplohmann/apiscout/blob/master/dbs/SHA256SUMS). It stores them in `~/.local/share/apiscout/dbs` (Linux), `~/Library/Application Support/apiscout/dbs` (macOS) or `%LOCALAPPDATA%\apiscout\dbs` (Windows), or in `--db-dir`.

The DBs with ASLR offsets carry the load addresses of the boot they were built in. They show the format and serve the tests, but do not fit dumps from other machines.

To build a DB for your own analysis system, run the DB builder on it. It is part of the repository, needs nothing but Python 3.8 or newer and writes the DB as a JSON file into the current folder:

```bash
git clone https://github.com/danielplohmann/apiscout
cd apiscout/apiscout/db_builder
python DatabaseBuilder.py --auto
```

<details>
<summary>More options of the DB builder</summary>

- `--auto` takes the commonly used DLLs of the system folders and their ASLR offsets.
- `--paths` and `--filter` choose folders and DLLs.
- `--os_name` and `--os_version` build a DB from a copy of the DLLs on any operating system. This is the way for systems without a recent Python, such as Windows XP.
- `--load_addresses` then takes the load addresses from the module list of a process on the target system, a file with lines of `<hex load address> <DLL path>`.

</details>

## IDA Pro

`ida_scout.py` from the repository works as a plugin and as a script with IDA 9.0 and newer.

- **Plugin:** install it with `hcli plugin install <path to the cloned repository>` or link the repository into `$IDAUSR/plugins`. It is then available as Edit > Plugins > ApiScout (<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>A</kbd>).
- **Script:** File > Script file...

Load a memory dump as a binary file, with the address it was dumped from as loading offset and 0 as loading segment. After choosing the API DBs, the references found are listed in the dockable ApiScout view, as in the screenshot at the top of this page.

| Key | Action |
| :--- | :--- |
| <kbd>Enter</kbd> or double click | Jump to the reference |
| <kbd>A</kbd> | Annotate the selected APIs |
| <kbd>Shift</kbd>+<kbd>A</kbd> | Annotate all APIs of the view |
| <kbd>F</kbd> | Only show APIs with a neighbour within a given distance |
| <kbd>Ctrl</kbd>+<kbd>U</kbd> | Scan the database again |

Annotating an API names its location, types it as a pointer to the API's prototype and applies the prototype to the calls referencing it.

<details>
<summary>Batch mode</summary>

All references are annotated and the database is saved:

```bash
idat -A -TBinary -b<dump address / 16, hex> -pmetapc -S"ida_scout.py <API DB> [<API DB> ...]" <dump>
```

- An API DB can be given by its file name when it is in the plugin's `dbs` folder or was downloaded with `apiscout dbs download`; the options dialog lists the DBs of that folder, too.
- The segment base that `-b` sets is reset to 0 so that calls reference the API pointers.
- Without `-TBinary`, IDA loads a dump that starts with a PE header as file instead of as memory image.
- idat creates a 64bit database for binary files, so 32bit dumps are best prepared as database first.
- A database that was analysed with a segment base before is repaired as far as possible: functions that IDA split under the base stay split, switches it missed there are not recovered, and `noreturn` flags are determined again. The command is best run on the dump itself.

</details>

## Ghidra

`ghidra_scout.py` from the repository is a Python 3 script for Ghidra. It runs in PyGhidra, the CPython 3 support that comes with Ghidra, and calls the apiscout library directly.

1. Start Ghidra with `support/pyghidraRun` (`pyghidraRun.bat` on Windows) instead of `ghidraRun`. On the first start, it installs PyGhidra, by default into a virtual environment in the user settings folder of Ghidra, and prints the environment it uses, e.g. `Switching to Ghidra virtual environment: ~/.config/ghidra/ghidra_12.2_PUBLIC/venv`.
2. Install ApiScout into that environment, with its Python (3.10 or newer):

   ```bash
   ~/.config/ghidra/ghidra_12.2_PUBLIC/venv/bin/python3 -m pip install apiscout
   ```

   The folder is `%APPDATA%\ghidra\ghidra_<version>_PUBLIC\venv` on Windows (with `Scripts\python.exe`) and `~/Library/ghidra/ghidra_<version>_PUBLIC/venv` on macOS. When `pyghidraRun` is started in an activated virtual environment, it uses that one instead.
3. Copy `ghidra_scout.py` into a script directory of Ghidra, such as `~/ghidra_scripts`. Instead of steps 2 and 3, the folder of a clone of the repository can be added as script directory in the Bundle Manager of the Script Manager: the script then imports the `apiscout` package next to it.
4. Run it from the Script Manager (category ApiScoutForGhidra). Ticking its "In Tool" checkbox adds it as Tools > ApiScout.

The script asks once for the folder with the API DBs, for example `dbs` of the repository, and scans the memory of the current program. The references you select in its table (<kbd>Ctrl</kbd>+<kbd>A</kbd> selects all) are annotated like imports: a pointer with an external reference to the function of its library, with the prototype of Ghidra's Windows data type archive. Tested with Ghidra 12.2.

![Ghidra listing with API pointers annotated as external functions](https://raw.githubusercontent.com/danielplohmann/apiscout/master/docs/images/ghidra.png)

<details>
<summary>Headless</summary>

All references are annotated. `analyzeHeadless` can not run Python scripts, `pyghidraRun -H` takes the same arguments:

```bash
pyghidraRun -H <project folder> <project name> -import <dump> -loader BinaryLoader -loader-baseAddr <address> \
    -processor x86:LE:64:default -scriptPath <folder of ghidra_scout.py> \
    -postScript ghidra_scout.py <API DB> [<API DB> ...]
```

A 32bit dump needs `-processor x86:LE:32:default`.

</details>

## Binary Ninja

> [!NOTE]
> Verified with Binary Ninja 6.0.10905 Ultimate on macOS 27.2, in its user interface, and headless on Linux: memory dumps of Malpedia loaded as `Mapped` view, annotated with `win7_prof-n_sp1_example.json`. TrickBot (32bit, base 0x400000): 183 references found like `apiscout scan` does, 182 annotated, 179 of them with prototype, the remaining one is a chance hit inside code. Cobalt Strike (64bit, base 0x1c0000): all 196 annotated with prototype. The decompiler then shows e.g. `ReadProcessMemory(hProcess: arg2, lpBaseAddress: arg3, lpBuffer: arg4, nSize: arg5, lpNumberOfBytesRead: &numberOfBytesRead)` instead of `0x7dd8cfcc(arg2, arg3, arg4, arg5, &var_c)`. Menu, forms, report with its address links and undo (one step per annotation) were used in the user interface. Installing through the extension manager was tested on 6.0.10905 against Binary Ninja's mock extension server: it installs the whole repository with numpy and loads the plugin through the `__init__.py` at its root; a listing in the manager needs a submission to [community-plugins](https://github.com/Vector35/community-plugins), whose `validate_json.py` accepts `plugin.json`.

1. Install ApiScout for the Python of Binary Ninja: the `Install python3 module` action of the command palette with `apiscout`, or `pip install apiscout` with the interpreter set in the `python.interpreter` setting. It needs Python 3.10 or newer.
2. Copy or link the folder `binja_scout` of the repository into the `plugins` folder of the [user folder](https://docs.binary.ninja/guide/index.html#user-folder) (`~/.binaryninja/plugins` on Linux, `~/Library/Application Support/Binary Ninja/plugins` on macOS). From a checkout, the plugin also finds the `apiscout` package next to it. The extension manager needs neither step: it installs the repository with numpy.

Open a memory dump with Open with Options as `Mapped` view, with the address it was dumped from as image base and `windows-x86` or `windows-x86_64` as platform. A dump that starts with a PE header would otherwise be loaded as PE file. The commands are in the Plugins menu under ApiScout:

| Command | Action |
| :--- | :--- |
| Scan for API references... | Choose the API DBs and list the references found in the memory of the view |
| Show results | List the references of the last scan, with the outcome of their annotation |
| Annotate all | Annotate all references of the last scan |
| Annotate filtered... | Annotate the references with another one within a given distance |
| Scan and annotate all... | Both in one step |

The API DBs are offered from `$APISCOUT_DB_DIR` or the folder of `apiscout dbs download` and from the `dbs` folder of the repository (a name once), any other file can be typed or chosen as well. Every command that lists results opens the report in a new tab. Annotating a reference names its location as import address symbol and types it as pointer to the API's prototype from the type libraries of the view's platform, so that calls through it are shown as calls of the API. A function that the linear sweep found in a table of pointers and that nothing refers to is removed when a pointer is annotated over it; a location inside the code of any other function is skipped. `Zw*` APIs of ntdll get the prototype of their `Nt*` counterpart. A pointer of the other bitness, for example a 32bit API address in a 64bit view, is only named.

<details>
<summary>Headless</summary>

With a license for headless use, `scan_and_annotate` does the same from a script:

```python
import binaryninja
from apiscout.BinaryNinjaTools import scan_and_annotate

with binaryninja.load("dump.bndb") as bv:
    result = scan_and_annotate(bv, ["dbs/win7_prof-n_sp1_example.json"])
    bv.update_analysis_and_wait()
    print(result["annotated"], "of", len(result["rows"]), "API references annotated")
    bv.file.save_auto_snapshot()
```

A dump without PE header can also be loaded directly, e.g. with `options={"loader.platform": "windows-x86", "loader.imageBase": 0x400000}`. A dump with PE header is loaded as `Mapped` view with the load settings of the raw view:

```python
raw = binaryninja.BinaryView.open("trickbot_dump7_0x00400000")
settings = binaryninja.BinaryViewType["Mapped"].get_load_settings_for_data(raw)
settings.set_integer("loader.imageBase", 0x400000, raw)
settings.set_string("loader.platform", "windows-x86", raw)
raw.set_load_settings("Mapped", settings)
bv = binaryninja.load(raw, options={"loader.imageBase": 0x400000, "loader.platform": "windows-x86"})
```

 `distance=32` only annotates references with another one within 32 bytes.

</details>

## Background

- [ApiScout: Painless Windows API information recovery](http://byte-atlas.blogspot.com/2017/04/apiscout.html) describes the method.
- [ApiVectors](https://byte-atlas.blogspot.com/2018/04/apivectors.html) explains how the fingerprints are built and stored.
- [ApiScout: Robust Windows API Usage Recovery for Malware Characterization and Similarity Analysis](https://cyberjournal.cecyf.fr/index.php/cybin/en/article/download/20/15/50) (Botconf 2018) evaluates it over Malpedia.

## Development

[uv](https://docs.astral.sh/uv/) sets up the environment:

```bash
uv sync
uv run python -m unittest discover -s tests -p "test*.py" -t .
uv run ruff check && uv run ruff format --check && uv run ty check
```

The tests of the Binary Ninja plugin on memory dumps (TrickBot and Cobalt Strike samples of Malpedia) run when `APISCOUT_SAMPLES` names the folder with them, otherwise they are reported as skipped. `tests/testBinaryNinjaHeadless.py` runs the plugin in Binary Ninja itself on generated dumps when the Python of the tests can import `binaryninja` with a license for headless use.

Changes are listed in the [changelog](https://github.com/danielplohmann/apiscout/blob/master/CHANGELOG.md).

<details>
<summary>Releasing</summary>

1. Set the version in `pyproject.toml`, run `uv lock` and add the changelog entry.
2. Publish a GitHub release whose tag is the version, with or without a leading `v`.

The workflow `release.yml` then checks that the tag names the version, runs the tests, builds the wheel and the source distribution, tries both in a clean environment and uploads them to PyPI together with their attestations.

It uses [trusted publishing](https://docs.pypi.org/trusted-publishers/), so no token is stored. This needs two settings, once:

- On PyPI, a trusted publisher for the project with this repository, the workflow `release.yml` and the environment `pypi`.
- On GitHub, an environment named `pypi`, ideally with required reviewers, so that an upload has to be approved.

</details>

Questions, bug reports and pull requests are welcome on [GitHub](https://github.com/danielplohmann/apiscout/issues). ApiScout is licensed under the [BSD 2-Clause License](https://github.com/danielplohmann/apiscout/blob/master/LICENSE).

## Credits

ApiScout is written by Daniel Plohmann and [contributors](https://github.com/danielplohmann/apiscout/graphs/contributors). The idea has gone through multiple iterations until reaching this release.

- Thorsten Jenke and Steffen Enders for their previous endeavours and for evaluating a proof of concept of this method.
- Steffen Enders for his work on the visualization of ApiQR diagrams.
- Ero Carrera for pefile and Elias Bachaalany for the IDA Python AskUsingForm template.
- Andrea Garavaglia for the performance benchmarks that led to drastic speedups of the matching.
