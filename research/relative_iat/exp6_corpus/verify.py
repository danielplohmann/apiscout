"""Independent check of the R7 answers: are the hit offsets read by code (call/jmp [mem])?

A real IAT is read through ff15/ff25: absolute in 32-bit code, RIP-relative in 64-bit code. The solver never looks at
code, so the share of hit offsets that code reads is an independent signal. It is calibrated on dumps with ground truth
(truth hits vs extra hits) and then applied to dumps where only the blind solver answers.
usage: verify.py dev.jsonl|test.jsonl [--out per_dump.jsonl]
"""
import argparse
import collections
import json
import sys

import numpy as np

import analyze  # noqa: E402

def code_read_offsets(path, base, bits):
    data = np.frombuffer(open(path, "rb").read(), dtype=np.uint8)
    n = len(data)
    if n < 6:
        return set()
    hit = (data[:-5] == 0xFF) & ((data[1:-4] == 0x15) | (data[1:-4] == 0x25))
    pos = np.nonzero(hit)[0]
    pos = pos[pos + 6 <= n]
    raw = data[(pos + 2)[:, None] + np.arange(4)].copy().view("<u4").ravel().astype(np.int64)
    if bits == 32:
        tgt = raw - base
    else:
        tgt = raw.astype(np.uint32).view(np.int32).astype(np.int64) + pos + 6
    tgt = tgt[(tgt >= 0) & (tgt < n)]
    return set(tgt.tolist())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--out")
    a = ap.parse_args()
    agg = collections.defaultdict(lambda: [0, 0])  # class -> [read, total]
    per_dump = []
    for line in open(a.jsonl):
        r = json.loads(line)
        if "error" in r or not int(r["base"], 16):
            continue
        g = analyze.rule7(r["groups"], r["path"], analyze.dump_range(r))
        if not g:
            continue
        bits = g[0]["bits"]
        reads = code_read_offsets(r["path"], int(r["base"], 16), bits)
        truth = {int(s.split("/")[0]) for s in r["truth_offs"] if s.endswith("/%d" % bits)}
        offs = [o for x in g for o in x["offs"]]
        dlls = sorted({x["dll"] for x in g})
        cls = "truth_dump" if r["truth_tag"] else "no_truth"
        for o in offs:
            k = (cls + (":hit" if o in truth else ":extra")) if cls == "truth_dump" else "no_truth"
            agg[k][0] += o in reads
            agg[k][1] += 1
        nread = sum(o in reads for o in offs)
        per_dump.append(dict(path=r["path"], kind=r["kind"], cls=cls, truth_tag=r["truth_tag"], truth_n=r["truth_n"],
                             tag=g[0]["tag"], bits=bits, dlls=dlls, hits=len(offs), read=nread,
                             extra=sum(o not in truth for o in offs),
                             extra_read=sum(o not in truth and o in reads for o in offs),
                             bases={x["dll"]: x["base"] for x in g}))
    for k, (rd, n) in sorted(agg.items()):
        print(f"{k:20s} {rd:7d}/{n:7d} read by code = {100*rd/max(n,1):5.1f}%")
    def dist(rows, label):
        b = collections.Counter()
        for d in rows:
            f = d["read"] / d["hits"]
            b["0" if f == 0 else "<25" if f < .25 else "<50" if f < .5 else ">=50"] += 1
        print(f"{label:28s} n={len(rows):4d}  " + "  ".join(f"{k}:{b[k]}" for k in ("0", "<25", "<50", ">=50")))
    td = [d for d in per_dump if d["cls"] == "truth_dump"]
    nt = [d for d in per_dump if d["cls"] == "no_truth"]
    dist(td, "truth dumps, share read")
    dist(nt, "no-truth dumps, share read")
    dist([d for d in nt if len(d["dlls"]) == 1], "  of them single-DLL")
    dist([d for d in nt if len(d["dlls"]) > 1], "  of them multi-DLL")
    if a.out:
        with open(a.out, "w") as f:
            for d in per_dump:
                f.write(json.dumps(d) + "\n")

if __name__ == "__main__":
    sys.exit(main())
