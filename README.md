# ApiScout

ApiScout finds Windows API references in memory dumps. Use it from the command line, from Python, or in IDA Pro, Ghidra, and Binary Ninja.

## Background

A memory dump can still contain resolved API addresses when its import table is missing or incomplete. ApiScout matches those addresses against a database of Windows DLL exports and shows where each reference was found. It also builds an **ApiVector** so you can compare samples by the APIs they reference.

## Quick start

Install ApiScout with Python 3.10 or newer.

```bash
python -m pip install apiscout
```

Save [`example_dump.bin`](https://raw.githubusercontent.com/danielplohmann/apiscout/v3.0.0/tests/example_dump.bin) and [`minimal_db.json`](https://raw.githubusercontent.com/danielplohmann/apiscout/v3.0.0/tests/minimal_db.json) in the same folder and run the scan there.

```bash
apiscout scan example_dump.bin --db minimal_db.json
```

The scan finds `InterlockedIncrement` at offset `0x100` and `WaitForSingleObjectEx` at `0x106`. The ApiVector is empty because both hits fall outside its catalog.

For your own dump, pick an [API database](#api-dbs) that matches its DLL versions. This example uses a Windows 7 database and a raw dump captured at `0x400000`.

```bash
apiscout dbs download win7_prof-n_sp1_example.json --db-dir ./dbs
apiscout scan dump.bin --db ./dbs/win7_prof-n_sp1_example.json --base-addr 0x400000
```

ApiScout reads DLL load addresses from Windows minidumps. If you have a separate module list, pass it with `--modules`.

## Usage

- **Find similar samples** with `apiscout match` or add `--collection` to a scan. Scores reflect weighted API overlap.
- **Visualize API usage** with `apiscout export`, which draws an ApiQR as PNG or HTML.
- **Script a scan** with `apiscout scan --json` or use the Python API.

Run `apiscout --help` for commands. See the [usage guide](https://github.com/danielplohmann/apiscout/blob/master/docs/usage.md) for output fields, confidence scores, collection setup, and Python examples.

## API DBs

Run `apiscout dbs` to list local databases. See the [database guide](https://github.com/danielplohmann/apiscout/blob/master/docs/databases.md) for available examples, DLL load addresses, and how to build a database for another Windows version.

## Integrations

- [IDA Pro](https://github.com/danielplohmann/apiscout/blob/master/docs/integrations.md#ida-pro)
- [Ghidra](https://github.com/danielplohmann/apiscout/blob/master/docs/integrations.md#ghidra)
- [Binary Ninja](https://github.com/danielplohmann/apiscout/blob/master/docs/integrations.md#binary-ninja)

![IDA Pro listing the API references ApiScout found in a memory dump](https://raw.githubusercontent.com/danielplohmann/apiscout/master/docs/images/ida.png)

## References

- [ApiScout: Painless Windows API information recovery](http://byte-atlas.blogspot.com/2017/04/apiscout.html)
- [ApiVectors](https://byte-atlas.blogspot.com/2018/04/apivectors.html)
- [ApiScout: Robust Windows API Usage Recovery for Malware Characterization and Similarity Analysis](https://cyberjournal.cecyf.fr/index.php/cybin/en/article/download/20/15/50) (Botconf 2018)

## Contributing

Report bugs or ask questions in [GitHub issues](https://github.com/danielplohmann/apiscout/issues). Use `uv` to set up the checkout and run the tests and checks.

```bash
uv sync
uv run python -m unittest discover -s tests -p "test*.py" -t .
uv run ruff check && uv run ruff format --check && uv run ty check
```

Set `APISCOUT_SAMPLES` to the folder with your Malpedia dumps to run the sample tests. The Binary Ninja tests run when `binaryninja` can be imported. See the [changelog](https://github.com/danielplohmann/apiscout/blob/master/CHANGELOG.md) and [release guide](https://github.com/danielplohmann/apiscout/blob/master/RELEASING.md).

## License and credits

ApiScout is written by Daniel Plohmann and [contributors](https://github.com/danielplohmann/apiscout/graphs/contributors) and licensed under the [BSD 2-Clause License](https://github.com/danielplohmann/apiscout/blob/master/LICENSE).

- Thorsten Jenke and Steffen Enders for their previous endeavours and for evaluating a proof of concept of this method.
- Steffen Enders for his work on the visualization of ApiQR diagrams.
- Ero Carrera for pefile and Elias Bachaalany for the IDA Python AskUsingForm template.
- Andrea Garavaglia for the performance benchmarks that led to drastic speedups of the matching.
