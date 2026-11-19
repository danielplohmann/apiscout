# Experiment 6: the blind solver on real dumps

Open item 2 of the spike ("real dumps"): run the solver blind over Malpedia and a private case corpus of
`*_dump*_0x<base>` memory dumps, and compare against `apiscout scan` as it works today.

**Result on the held-out test split (1,565 Malpedia dumps with ground truth): 92.3 % of the references
recovered with the correct DLL and API name, at 99.6 % precision, without a module list and without the
DB's load addresses.** When the true build is removed from the reference set, 2.2 % of dumps still get an
answer.

## Setup

- **Corpus.** 3,932 distinct dumps (Malpedia plus a private case corpus), 20 MB at most each. Dumps are read
  as bytes only.
- **Ground truth.** `apiscout scan` as today: one scan per shipped DB (XP, Win7, Win10 1803, Server 2022,
  Win11 26H2) at the DB's own DLL bases, confidence >= 20. The DB with the most hits is the dump's build.
  Dumps with fewer than 5 such hits count as "no ground truth".
- **Blind.** `blind_solve.solve` over all five DBs, 32 and 64 bit, no bases. Every aligned pointer-sized
  value votes for each `(DLL layout, base)` it fits.
- **Leave-out.** The same, with the ground-truth build removed from the reference set.
- **Split.** Malpedia families with an odd SHA-256 of the family name form the test split, minus 263 dumps
  that were looked at while the rules were tuned. Everything else, the case corpus included, is dev. The
  rules were tuned on dev only. R8 was added after R7's test numbers were known (see below).

Malpedia's naming holds: `_dump_` is XP for 630 of 634 test dumps with ground truth, and `_dump7_` is Win7
for 924 of 931.

## Filter rules

The spike's rule (R0: support >= 3) recovers almost everything, but precision is about 10 %. Real dumps
hold millions of pointer-sized values, and dense export tables match them by chance: win32u syscall stubs,
kernel.appcore, mfc42 ordinals, msvcp60 data exports. Each rule adds to the one before it.

| Rule | Adds |
| --- | --- |
| R0 | support >= 3 (the spike) |
| R1 | hit ratio: share of the dump's distinct values in the DLL's export range that are exports |
| R2 | adjacency: at least half the hits have another hit within two pointers (IATs are tables) |
| R3 | one build and one bitness per dump, by vote |
| R4 | user-mode bases only |
| R5 | bitness from the PE header; the build must have a DLL with support >= 5 |
| R6 | a DLL can't overlap the dump's own range; dense layouts can't carry the build |
| R7 | replaces the ratio and the dense list with one binomial test per DLL: `log10 p <= -9`, chance per layout = its 4- or 16-aligned export density, window = support / ratio; build vote by summed `-log p`; support >= 5 anchor |
| **R8** | **an answer of only one DLL must have >= 50 % of its hits read by code (`ff15`/`ff25`)** |

### Held-out test (1,565 dumps with ground truth)

| Rule | Recall (DLL + name) | Precision | Extra hits | Dumps >= 90 % recall | Dumps without extras |
| --- | --- | --- | --- | --- | --- |
| R0 | 94.3 % | 9.8 % | 2,038,706 | 87.0 % | 1.4 % |
| R2 | 92.2 % | 35.1 % | 399,850 | 80.3 % | 19.7 % |
| R6 | 92.1 % | 97.1 % | 6,354 | 79.9 % | 80.1 % |
| R7 | 92.4 % | 97.4 % | 5,670 | 78.7 % | 81.3 % |
| **R8** | **92.3 %** | **99.6 %** | **890** | **78.5 %** | **82.1 %** |

Dev (1,666 dumps) under R8: recall 91.6 %, precision 99.0 %, 2,250 extra hits. Recall by DLL and by name
agree everywhere: when the DLL and base are right, the name is right.

### True build left out

| Rule | Dumps that still get an answer (test) | (dev) |
| --- | --- | --- |
| R3 | 79.0 % | 78.0 % |
| R7 | 6.3 % | 6.3 % |
| R8 | 2.2 % | 3.1 % |

The spike expected "no answer rather than a wrong one". That holds for 98 % of dumps under R8.

## Code reads as an independent check

The solver never looks at code. A real IAT is read by `call`/`jmp [mem]`: absolute in 32-bit code,
RIP-relative in 64-bit code. `verify.py` counts how many hit offsets such instructions read.

| Under R7 | Read by code (test) | (dev) |
| --- | --- | --- |
| Hits that match the ground truth | 87.2 % | 87.8 % |
| Extra hits | 0.3 % | 23.4 % |

On test the extras are noise. On dev, a part of the "extras" is real: in dumps where the best classic DB
found only 1-4 hits, the solver found another build at ASLR bases, and code reads it. Examples:
`win.keyhole` (classic: 4 hits with Win11; blind: 263 Win10 hits, 239 read by code) and
`win.berserk_stealer` (classic: 3; blind: 106 Win10, all read). So precision against this ground truth is
a lower bound.

A missing code read doesn't prove a hit wrong. A table filled at run time by `GetProcAddress` is read
through a register. 92 Qakbot dumps from one case answer Win7 `ws2_32`/`shlwapi`/`ole32`/`oleaut32` with
no code read, and their tables read as a coherent socket API set (`socket`, `connect`, `send`, `recv`,
`WSAStartup`, ...). The check is therefore one-sided, and R8 applies it only to single-DLL answers, the
class that held most false answers.

## Dumps without ground truth

Classic `apiscout` finds fewer than 5 hits in 404 dev and 297 test dumps.

- **Dev:** R8 answers 119. Of these, at least 18 are confirmed by code reads (>= 90 % read), for example
  `win.interlock` (`_dump10_`, Win10 x64, kernel32/msvcrt/ntdll at `0x7ff9...`, 124 of 128 hits read),
  `win.chrysalis`, `win.toughprogress`, `win.supper` and `win.andromeda`. 92 more are the Qakbot dynamic
  tables above.
- **Test:** R8 answers 1 (R7: 12). The ones R8 drops are single-DLL answers that code reads little or not at all.

These are the dumps the solver exists for: classic `apiscout` can't place them without a module list or
a DB of the exact build.

## Misses

Under R8, test misses 18,041 truth hits: 4,694 in DLLs with only 1-2 truth hits, and 13,347 in DLLs with
3 or more. Diagnosis on dev for the second group:

| Cause | Missed hits |
| --- | --- |
| No hypothesis at all: the hit ratio is below 0.3 (the window is full of other pointers into the DLL, e.g. return addresses on stacks in full-process dumps), or fewer than 3 distinct aligned values | 9,540 |
| Group exists but fails the significance test | 2,888 |
| The whole dump gets no answer | 1,543 |
| Other (partial recovery, other build won the vote, adjacency) | 1,574 |

A sample of the first row: about 60 % fail the ratio, about 40 % have fewer than 3 distinct aligned values
(duplicate pointers or unaligned hits, which classic scanning finds at every byte offset).

## Extending along the IAT run

R8 needs every DLL to carry itself: support >= 3 and a significant binomial test. Once a dump has an
anchored build, a neighbour in the same pointer table needs less. `ext_eval.py` adds pointers next to
accepted hits that fit a DLL of the winning build at a 64 KB-aligned user-mode base that doesn't fall inside
a DLL already placed. The variants are in its docstring. E4cr was chosen on dev (+4.1 points recall,
-0.6 points precision), then run once on test:

| Test, 1,565 dumps | Recall (DLL + name) | Precision | Extra hits | Dumps with extras |
| --- | --- | --- | --- | --- |
| R8 | 92.30 % | 99.59 % | 890 | 280 |
| E2: new DLLs with >= 2 pointers | 95.62 % | 99.02 % | 2,220 | 436 |
| E2r: E2, code reads one of them | 95.46 % | 99.46 % | 1,221 | 311 |
| E4c: E2 plus single pointers that code reads | 96.12 % | 98.62 % | 3,161 | 552 |
| **E4cr: E4c with E2r's check** | **95.96 %** | **99.06 %** | **2,144** | **436** |

- Code reads 89 % of E4cr's new correct hits and 68 % of its 1,254 new extras, against 0.3 % of R8's
  extras on test. So many of the new extras are probably real pointers the classic scan disagrees with,
  and the precision cost is probably smaller than shown. They are not checked by hand.
- The extension only grows existing answers. With the true build left out, the dumps that get an answer
  stay at 2.2 %; their wrong hits grow by 1,296.
- Without the read checks (E2, E4c) recall is about the same at up to twice the extras.

## Next

1. **Ratio from tables, not from the export range.** Count the window over values in pointer runs only, so
   that stack and heap pointers into a DLL don't dilute it. This targets the largest miss class.
2. **Move R8 + E4cr into the solver** if the scan option of the spike is built: the extension is cheap once
   the build is anchored.
3. The open items of the spike: adjacent Win10/11 builds, DLLs with 1-2 pointers, forwarders and API sets.

## Files

Run from the repository root with `PYTHONPATH=.` (needs `numpy`).

| File | What |
| --- | --- |
| `blind_solve.py` | the solver; also a CLI for one dump |
| `corpus_eval.py` | classic scan, blind solve and leave-out per dump, as JSON lines |
| `analyze.py` | rules R0-R8 and the tables above |
| `verify.py` | code-read check per answer |
| `ext_eval.py`, `ext_report.py` | IAT-run extension variants on top of R8 and their tables |

```
python3 research/relative_iat/exp6_corpus/corpus_eval.py out.jsonl inventory.txt --workers 3
python3 research/relative_iat/exp6_corpus/analyze.py test.jsonl
python3 research/relative_iat/exp6_corpus/verify.py test.jsonl --out verify_test.jsonl
python3 research/relative_iat/exp6_corpus/ext_eval.py test.jsonl ext_test.jsonl --workers 3
python3 research/relative_iat/exp6_corpus/ext_report.py ext_test.jsonl
```

An inventory is one dump path per line. A path containing `malpedia` counts as Malpedia. The per-dump
results (about 220 MB) aren't committed: they name paths of the private case corpus.
