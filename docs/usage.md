# Using ApiScout

## Scan a dump

Download an example database that matches the DLL versions in your dump, or [build your own](databases.md).

For a raw dump, pass its load address with `--base-addr`. ApiScout can also read it from names ending in `0x` followed by 8 to 16 hex digits, with or without a common dump extension such as `.bin`. For example, `dump_0x00400000.bin` starts at `0x400000`.

```bash
apiscout scan dump.bin --db dbs/win7_prof-n_sp1_example.json --base-addr 0x400000
```

ApiScout detects Windows minidumps by their `MDMP` signature. It scans each memory range at its own address and excludes hits inside known system DLL images. The text listing shows virtual addresses. JSON uses virtual addresses by default for minidumps, or offsets relative to `--base-addr` when supplied.

To read the imports of a PE file on disk, use `--import-table`. This mode needs no API database.

```bash
apiscout scan program.exe --import-table
```

### Try the test dump

From a checkout of the repository, run:

```bash
apiscout scan tests/example_dump.bin --db tests/minimal_db.json
```

The scan finds `InterlockedIncrement` and `WaitForSingleObjectEx`. Both fall outside the WinApi1024 list in this example, so the vector is empty.

### Read the results

| Column | Meaning |
| --- | --- |
| `offset` | Location of the API pointer in the dump |
| `VA` | Address stored in the pointer |
| `IT?` | Whether the pointer is in the import table. `err` means ApiScout could not read an import table. |
| `#ref` | The pointer itself plus the calls and jumps through it |
| `DLL` | DLL name, bitness, and load address if shown |

Some bytes in a dump can match an API address by chance. ApiScout scores each hit from 0 to 100 based on nearby API pointers, calls through the pointer, import-table membership, pointer alignment, and agreement across databases. The default threshold is 20. Use `--min-confidence 0` to disable that threshold, or `--filter 32` to require another API within 32 bytes. Run `apiscout scan --help` for the scoring rules.

The separate `Confidence` value printed with the ApiVector depends on how many APIs the vector contains and how common they are. The coverage line shows how many recovered APIs are represented in the WinApi1024 list.

### Look for API names and hashes

Use `--dynamic` to look for groups of API name strings and hashes in the dump. The scan checks ROR13, Metasploit block_api, CRC32, djb2, FNV-1a, and sdbm, including variants with an added or XORed key. It reports those hits separately and includes them in the ApiVector.

## Compare ApiVectors

Use `--collection` with a scan to rank samples in a collection by API similarity:

```bash
apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json --collection apivectors.csv
```

Use `apiscout match 'VECTOR' 'OTHER' --explain` to compare two existing vectors and see which APIs contribute to the score. Quote the vectors when passing them to the shell.

Build your own collection with `apiscout collect <folder>`. Organize the dumps into one subfolder per family. Collection scans use the same dump and DLL placement logic as single scans. They retain the historical proximity filter of 32 bytes and a minimum confidence of 0. Use `--filter 0 --min-confidence 20` to match the single-scan defaults. Use `--jobs` to cap parallel scans and `--refresh` with `--update` to rescan files whose paths already appear in the collection. `--skip-empty` keeps any dump with recovered APIs, including hits outside the vector catalog.

To download the collection published by [Malpedia](https://malpedia.caad.fkie.fraunhofer.de), install the optional dependency and put your API token in `~/.config/apiscout/malpedia-token`, or pass its path with `--token-file`.

```bash
python -m pip install 'apiscout[update]'
apiscout update
```

## Export an ApiQR

The ApiQR gives each of the 1,024 catalogued APIs a fixed position and uses colour to indicate its category, such as files, networking, or cryptography.

<img src="images/apiqr.png" alt="ApiQR diagram of a TrickBot dump" width="200">

```bash
VECTOR=$(apiscout scan dump_0x00400000 --db win7_prof-n_sp1_example.json --json | jq -r .apivector)
apiscout export "$VECTOR" --png vector.png --html vector.html
```

## Use JSON and standard input

For scans using multiple databases, each pointer record includes the database label in `api_db`.

```bash
apiscout scan dump_0x00400000 --json | jq -r '.apis[].api' | sort -u
apiscout scan dump_0x00400000 --json | apiscout match - --collection apivectors.csv
```

Use `apiscout <command> --help` for options and examples. Exit codes are 0 for success, 1 for errors, 2 for incorrect usage, and 130 for an interrupted command.

## Use Python

Run this example with a matching database and dump. Set the base address to where your dump was loaded.

```python
from apiscout.ApiScout import ApiScout

scout = ApiScout("dbs/win7_prof-n_sp1_example.json")
scout.setBaseAddress(0x400000)
with open("trickbot_dump_0x00400000", "rb") as f_dump:
    results = scout.crawl(f_dump.read())
for apis in results.values():
    for offset, api_address, dll, api, bitness, in_import_table, references, callers in apis:
        print(hex(0x400000 + offset), dll, api, references)
vector = scout.getPrimaryVector(scout.getWinApi1024Vectors(results))[1]["vector"]
```
