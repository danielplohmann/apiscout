# Experiment 7: adjacent builds

Open item 1 of the spike: can one reference set of export layouts span many Win10/11 builds, or does the
solver need the exact build?

**Result: it needs the exact build.** With every other build of the same DLL in the reference set, the solver
names 18-54 % of imports right and 15-65 % wrong, and nothing in the answer tells the wrong ones apart. With
the exact build in the set, 99-100 % are right, even among 150 near-identical layouts of one DLL.

## Data

`fetch_exports.py` takes the Winbindex index of a DLL, picks every build seen in a release still in the field
(Win10 22H2, Win11 22H2 to 26H1) and the first and last build of every older release (1507 on), x64 and x86,
downloads each from the Microsoft symbol server (key: TimeDateStamp + SizeOfImage), and keeps only the
export table. Binaries are parsed with the standard library and deleted.

| DLL | builds | distinct layouts x64 / x86 |
| --- | --- | --- |
| advapi32 | 357 | 47 / 56 |
| kernel32 | 402 | 58 / 63 |
| kernelbase | 385 | 124 / 154 |
| ntdll | 294 | 69 / 78 |
| user32 | 445 | 73 / 128 |

For 582 entries the symbol server returned another file than the one Winbindex lists, under the same key.
At least one was a kernel32 made only of forwarders. Only files whose SHA-256 matches Winbindex are used.

## Solver test

`adjacent_solve.py`: K imports drawn from a target layout's APIs that occur in `winapi1024v1`, placed at a
random 64 KB-aligned base, solved against a reference set. Three reference sets: the target itself among all
layouts (`self`, the control), all other layouts (`others`), and only layouts first seen before the target
(`older`, as a DB shipped earlier would be). Three solvers: one base per DLL with the best layout naming,
greedy over several bases as `blind_solve.solve` on real dumps, and a consensus rule that only names a value
when all strong layouts at the base agree.

x64, K = 30, greedy (full table for all modes, K = 10/30/100 and x86 in `adjacent_solve.txt`):

| DLL | self: correct | others: correct / wrong | older: correct / wrong |
| --- | --- | --- | --- |
| advapi32 | 100 % | 54 % / 23 % | 44 % / 19 % |
| kernel32 | 99.8 % | 41 % / 47 % | 32 % / 45 % |
| kernelbase | 100 % | 40 % / 39 % | 23 % / 39 % |
| ntdll | 100 % | 25 % / 55 % | 15 % / 52 % |
| user32 | 100 % | 25 % / 45 % | 14 % / 40 % |

x86 is the same or worse (kernelbase x86, others: 18 % correct, 62 % wrong). The consensus rule brings wrong
names down to 10-20 %, at 55-75 % abstentions, so it doesn't make adjacent builds safe either.

## Why

`adjacent.py` compares layouts pairwise: the share of a target's common APIs that one shift explains.

- **Exports move in blocks.** Between two consecutive builds, a DLL's exports move in a few contiguous
  blocks, each by a constant amount. Example, kernel32 x64 26100.1301 -> 26100.1591: 811 exports by -2000
  bytes, 641 by 0, 20 by -2432. The base is 64 KB-aligned, so only the block that didn't move fits it.
- **Shifted exports land on neighbours.** A moved function's old RVA is often a neighbouring export in the
  other build. kernel32's own exports are 16- and 32-byte thunks packed back to back (median gap 32 bytes,
  kernelbase: 224), so there nearly every shift of a slot hits another export.
- **Even neighbours share little.** Median share explained by one shift between builds under 6 weeks apart in
  the same release: advapi32 x64 85 %, ntdll x64 43 %, kernelbase x64 29 %, user32 x64 17 %.
- **Covering all builds takes almost all of them.** The fewest layouts so that every layout has one at
  >= 90 % coverage: kernelbase x64 112 of 124, user32 x64 66 of 73, ntdll x64 66 of 69.

`blockshift.py` tried a small offset per block on top of one aligned base. On kernel32 it was worse than
plain matching: with offsets free, many offsets reach support 3 by chance.

This also explains why the corpus results (`exp6_corpus/`) are good: Malpedia's dumps come from XP and Win7
snapshots whose DLLs match the shipped DBs exactly.

## Follow-up ideas

1. **A library of exact layouts instead of DBs.** The solver picks the right build among ~150 near-identical
   layouts, and needs no bases or ASLR data. Winbindex plus the symbol server provide every build: 5 DLLs gave
   105 MB of JSON, much less as packed RVA arrays.
2. **An index that scales to that library.** All common system DLLs x all builds x 2 architectures is tens of
   thousands of layouts. The low-16-bit index of `blind_solve.py` won't hold that; candidates: a first pass
   on a few stable exports per DLL family to pick the family and a short list of builds, then the full solve.
3. **Build identification as a product of its own.** The layout that fits names the exact Windows build and
   patch level of the dumped machine, which is useful for an analyst even without the API names.
4. **kernel32 thunks and forwarders.** Most kernel32 exports are thunks into kernelbase. Check which address
   an IAT entry for `kernel32!X` really holds on Win10/11 (thunk or kernelbase), since that decides which
   layout must be in the library.
5. **Delay imports.** Not measured so far. A delay-IAT slot holds a DLL address only after the first call,
   so a dump shows fewer pointers per DLL; the unresolved slots point at the image's own thunks, and the
   delay import descriptor gives names without any layout matching. Measure resolved vs. unresolved slots
   and recall on them over the `exp6_corpus/` dumps with a PE header.

## Files

| File | What |
| --- | --- |
| `fetch_exports.py` | Winbindex + symbol server -> one exports JSON per build |
| `adjacent.py` | pairwise shift coverage, decay over time, greedy reference set |
| `adjacent_solve.py` | leave-one-build-out solver test |
| `blockshift.py` | per-block offsets (negative result) |
| `adjacent_solve.txt`, `adjacent_pairs.txt` | the output the tables above are taken from |

```
python3 -I research/relative_iat/exp7_adjacent_builds/fetch_exports.py exports bin kernel32.dll kernelbase.dll ntdll.dll user32.dll advapi32.dll
python3 -I research/relative_iat/exp7_adjacent_builds/adjacent.py exports apiscout/data/winapi1024v1.txt
python3 -I research/relative_iat/exp7_adjacent_builds/adjacent_solve.py exports apiscout/data/winapi1024v1.txt research/relative_iat/exp6_corpus --k 10 30 100 --trials 3
```

`bin` receives the Winbindex indexes and, briefly, each binary. The exports JSON aren't committed (105 MB);
the fetch takes about an hour and is cached per file.
