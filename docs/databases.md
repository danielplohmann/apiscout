# API databases

A database maps Windows DLL export addresses to API names. For a pointer scan, use a database built from the same DLL versions as the dump and make sure ApiScout has the correct load addresses.

## Download a database

| Database | System | Stored ASLR offsets |
| --- | --- | --- |
| `winxp_prof_sp3_example.json` | Windows XP Professional SP3, 32-bit | No |
| `win7_prof-n_sp1_example.json` | Windows 7 Professional N SP1, 32-bit and 64-bit | No |
| `win10_prof_1803_example.json` | Windows 10 Pro 1803, 32-bit and 64-bit | Yes |
| `win2022_server_21h2_example.json` | Windows Server 2022 21H2, 32-bit and 64-bit | Yes |
| `win11_pro_26h2_example.json` | Windows 11 Pro 26H2, 32-bit and 64-bit | Yes |

Run `apiscout dbs download` to fetch the examples, or pass a filename to download just one. The downloader verifies files against [`dbs/SHA256SUMS`](../dbs/SHA256SUMS). Its default download folder is `~/.local/share/apiscout/dbs` on Linux, `~/Library/Application Support/apiscout/dbs` on macOS, and `%LOCALAPPDATA%\apiscout\dbs` on Windows. Set `--db-dir` or `APISCOUT_DB_DIR` to choose another folder.

Pass a database path with `--db`. A bare filename also works if it is in the directory selected by `--db-dir`, `APISCOUT_DB_DIR`, or the default search. With neither override, the search checks `./dbs`, the download folder, and the checkout's `dbs` folder in order. Empty folders and folders with unrelated JSON do not hide later databases. Run `apiscout dbs` to see what the command finds.

## Set DLL load addresses

ASLR can change where a DLL loads between boots. Use `--modules FILE` to supply the load addresses for the dump. Put one DLL on each line as `<hex load address> <DLL path>`.

ApiScout prefers addresses from `--modules`, then the minidump module list. For raw dumps it can also find DLL images. Image addresses fill gaps unless the database already has an ASLR offset for that DLL. Use `--ignore-aslr` to ignore the stored offsets. DLLs that ApiScout cannot place keep their database addresses. The JSON output lists the placements in `placed_dlls`.

## Build a database

Run the builder on the Windows system used to capture the dump:

```bash
git clone https://github.com/danielplohmann/apiscout
cd apiscout
python -m apiscout.db_builder --auto
```

The builder uses the standard library and requires Python 3.10 or newer. The default output name includes the full Windows version, such as `10.0.19045_filtered.json`.

With `--paths`, the builder parses exports without loading the DLLs. Use `--load_addresses` to supply load addresses from a capture. On Windows, `--auto` loads the configured system DLLs to measure ASLR. To allow that behavior for trusted custom paths, pass `--load-dlls`. For older Windows versions, copy the DLLs to a supported system. Use `--paths` and `--filter` to choose which DLLs to include, `--os_name` and `--os_version` to describe the source system, and `--load_addresses` to supply its module list.

You can also build from DLLs on Microsoft's symbol server. The downloader looks up the files through [Winbindex](https://github.com/m417z/winbindex) and checks their SHA-256 hashes.

```bash
python -m apiscout.db_builder.DllDownloader --windows 11-24H2 --update KB5046617 --out win11
```

Run the downloader with `--list` to see available versions, or with `--windows 11-24H2 --list` to list updates for a version. `--update` also accepts a build like `26100.2605`. These databases contain no captured ASLR offsets. Supply load addresses with a minidump or a module list.

### Names for ordinal-only exports

Some DLLs export most functions by ordinal only. MFC's `mfc42.dll` and `mfc42u.dll` export thousands this way, and a database lists them as `None<ordinal>`. Both the builder and the downloader accept the module-definition (`.def`) file the DLL was linked with, which supplies the names: `--def32 MFC42.DEF` for the 32-bit DLL and `--def64` for the 64-bit one, because their names and ordinals differ. Visual C++ ships these files with the MFC sources. Use the one from the same MFC version, since names are looked up by ordinal.

The file applies to the DLL its `LIBRARY` line names, or else to the DLL named like the file. Exports that already have a name keep it. Both tools refuse a DEF file whose C++ names are decorated for the other bitness. A DEF file that names an export differently than the DLL does is not used for that DLL, with a warning.
