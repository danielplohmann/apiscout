# Relative IAT recovery (spike)

A scan mode that recovers Windows API references from a memory dump **without the module list, the DLL
load addresses, or an API DB of the exact Windows build**. Tracking issue: #65.

Today `apiscout scan` needs an API DB of the dumping system and, under ASLR, the real load addresses of the
DLLs: from `--modules`, the module list of a minidump, DLL images found in the dump, or the ASLR offsets
stored in the DB. This spike shows that the relative layout of the pointers in a dump is enough on its own.

Nothing here is wired into the package. The scripts are kept as they ran so that their numbers reproduce.

## Why it works

Three facts turn this into constraint solving instead of guessing:

1. **Differences are exact.** Two pointers into the same DLL differ by exactly the difference of the two
   export RVAs: `v_i - v_j = rva_i - rva_j`. The unknown base cancels.
2. **The low 16 bits are exact.** Windows places images on 64 KB boundaries, so `base & 0xFFFF == 0` and
   `va & 0xFFFF == rva & 0xFFFF`. Even with only 4 KB alignment, the results below degrade gracefully
   (`exp2.py`).
3. **One base per DLL per boot.** Every pointer into a DLL in one dump must be explained by the same base.

The solver: for an observed pointer `v0`, every export of every reference DLL whose RVA has the same low 16
bits is a candidate anchor, giving `base = v0 - rva`. A hypothesis `(DLL, build, base)` is scored by how
many other observed pointers land on an export of that DLL at that base. Accept at support >= 3. Index on
pairwise RVA deltas (base-invariant) for speed, and verify with the low 16 bits and the support count.

## Measured

All against the DBs in `dbs/`, synthetic dumps: real export RVAs, random 64 KB-aligned bases, imports
sampled uniformly from a DLL's exports.

**Identifiability** (`exp_geom.py`, Win7 x64, 194 DLLs, 54 411 exports): k pointers from one DLL.

| k | unique DLL | unique API name | true name among candidates |
| --- | --- | --- | --- |
| 1 | 8 % | 8 % | 100 % |
| 2 | 91 % | 88 % | 100 % |
| 3 | 99.7 % | 95.7 % | 100 % |
| 4 | 100 % | 98.7 % | 100 % |

The remaining name ambiguity is exports that share one RVA. In `winapi1024v1` this only touches
`memcpy` / `memmove` / `RtlCopyMemory` / `RtlMoveMemory` (`exp3.py`: 10 groups, all of them that set), so
ApiVectors should come out unchanged.

**Robustness** (`exp2.py`, `exp3.py`, `exp4_clustering.py`):

- 12 true pointers mixed with up to 24 foreign ones: precision and recall of the best hypothesis 100 %.
  No clean IAT and no zero dividers needed, which also covers import tables built at run time.
- 300 random pointer-sized values: 0 hypotheses at support >= 3.
- Clustering pointers by address before solving fails when DLLs are packed close together, as system DLLs
  are. Solving the raw, unsorted set instead covers 93-95 % of modules, 100 % of them correct. Modules that
  contribute only 1-2 pointers are the gap.

**Builds** (`exp5_delta_and_builds.py`, `e3_modern.py`): with the reference set holding several builds of
the same DLL, does a wrong build fit?

- XP vs. Win7, and the WinSxS CRT versions: different builds share almost no RVAs, and at k >= 4 a wrong
  build only fits for near-identical minor revisions, where the names then agree 100 %.
- All five shipped DBs together (XP, Win7, Win10 1803, Server 2022 21H2, Win11 26H2; 780 distinct 64-bit and
  884 distinct 32-bit DLL layouts), sampling from kernelbase, ntdll, user32, advapi32, ws2_32, wininet,
  shell32 and crypt32 of the three modern builds:

  | k | 64-bit: unique DLL + build | wrong build fits | true name wins the vote | 32-bit: unique DLL + build | true name wins |
  | --- | --- | --- | --- | --- | --- |
  | 2 | 38 % | 2.0 % | 89 % | 47 % | 87 % |
  | 3 | 95 % | 0 % | 100 % | 94 % | 99.3 % |
  | 4 | 98 % | 0 % | 100 % | 100 % | 100 % |

  These three builds are years apart (17134, 20348, 26100). Adjacent monthly builds of `kernelbase.dll`
  are the open question.

## Where it breaks

- **1-2 pointers into a DLL**: about 5 candidate names. Needs ranking (corpus frequency of each API,
  argument count at the call site on x86, co-occurring APIs) and output as a ranked list.
- **The DLL's build is not in the reference set**: the likely outcome is "no answer" rather than a wrong
  one, but this is unmeasured.
- **API sets and forwarders**: from Win8 on, `kernel32!Sleep` resolves into `kernelbase.dll`. Reference
  DBs must resolve forwarders and treat `kernel32!X` and `kernelbase!X` as one API.
- **Hooks and shims** (EDR trampolines, apphelp): pointers into injected modules stay unexplained. Report
  them, do not force a match.
- **API hashing without an address table**: out of scope; `apiscout` already detects API hashes.

## Next steps

1. **Adjacent-build test.** Collect `kernelbase`, `ntdll`, `kernel32`, `user32` and `advapi32` exports
   over many Win10/11 builds (Winbindex lists them with Microsoft symbol-server links) and rerun
   `e3_modern.py` on them. This decides whether one reference set can span many builds.
2. **Real dumps.** Run the solver blind over Malpedia `_dump` samples and compare against `apiscout scan`
   with the matching DB.
3. **Solver in the package.** A `scan` option that takes a set of API DBs of any builds and needs no
   module list. Output stays in today's format, plus a confidence per reference, the alternatives for
   ambiguous ones, and the DLL builds that fit.
4. **Fresh Win10/11 ground truth** with `capture_aslr_geometry.py` (below): dump with the module list
   recorded, then withhold it from the solver.

## Files

Run from the repository root, stdlib Python 3 only:

| File | What |
| --- | --- |
| `exp_geom.py` | identifiability vs. number of pointers per DLL |
| `exp2.py` | XP + Win7 reference set; 64 KB vs. 4 KB alignment; outlier robustness |
| `exp3.py` | API names sharing one RVA in `winapi1024v1`; null test with random values |
| `exp4_clustering.py` | address clustering vs. solving the raw pointer set |
| `exp5_delta_and_builds.py` | delta index selectivity; real build pairs |
| `e3_modern.py` | cross-build fits over all five shipped DBs |
| `capture_aslr_geometry.py` | Windows capture tool for ground-truth dumps; `selftest` runs on any OS |

`capture_aslr_geometry.py` records per boot the OS build, the allocation granularity, every module's base,
version, SHA-256 and symbol-server key, an API DB in apiscout's format, and Malpedia-named image dumps. Its
`geometry_check.txt` checks facts 2 and 3 above on the spot.
The options of the tool itself (`--tag`, `--exports`, `--argcounts`, `--out`) go before the sub command.

```
py -3 capture_aslr_geometry.py selftest
py -3 capture_aslr_geometry.py --exports --argcounts --tag "vmA boot1" survey   # once per boot
py -3 capture_aslr_geometry.py run --exe C:\Windows\System32\notepad.exe --wait 3 --kill
py -3 capture_aslr_geometry.py dump --pid 1234
```
