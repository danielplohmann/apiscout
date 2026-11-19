"""Blind relative-IAT solver over a real dump (issue #65, open item "real dumps").

Every aligned pointer-sized value of the dump votes for each (DLL layout, base) it fits: an export RVA with the
same low 16 bits gives base = value - rva, which must be 64 KB aligned. A hypothesis' support is the number of
distinct values explaining it. The DB's own base addresses are never used.

usage: blind_solve.py DUMP BITS DBDIR [--exclude TAG ...] [--minsup N] [--truth TRUTH.json]
"""
import argparse
import bisect
import collections
import json
import os
import struct
import sys
import time

DBS = [("xp", "winxp_prof_sp3_example.json"), ("w7", "win7_prof-n_sp1_example.json"),
       ("w10", "win10_prof_1803_example.json"), ("s22", "win2022_server_21h2_example.json"),
       ("w11", "win11_pro_26h2_example.json")]


def load_refs(dbdir, bits, exclude):
    refs, seen = [], set()
    for tag, fname in DBS:
        if tag in exclude:
            continue
        for dll in json.load(open(os.path.join(dbdir, fname)))["dlls"].values():
            if dll["bitness"] != bits:
                continue
            name = dll["filepath"].lower().replace("/", "\\").split("\\")[-1]
            by_rva = collections.defaultdict(set)
            for e in dll["exports"]:
                if e["name"]:
                    by_rva[e["address"]].add(e["name"])
            if not by_rva:
                continue
            key = (name, frozenset(by_rva))
            if key in seen:
                continue
            seen.add(key)
            refs.append(dict(tag=tag, name=name, version=dll.get("version"), by_rva=by_rva,
                             lo=min(by_rva), hi=max(by_rva)))
    # low-16 index over all layouts: low16 -> [(ref index, rva)]
    low = collections.defaultdict(list)
    for i, ref in enumerate(refs):
        for rva in ref["by_rva"]:
            low[rva & 0xFFFF].append((i, rva))
    return refs, low


def dump_values(path, bits):
    data = open(path, "rb").read()
    size = bits // 8
    fmt = "<%d%s" % (len(data) // size, "I" if bits == 32 else "Q")
    vals = struct.unpack_from(fmt, data[: len(data) // size * size])
    offsets = collections.defaultdict(list)
    for i, v in enumerate(vals):
        offsets[v].append(i * size)
    return offsets


def solve(values, refs, low, minsup, bits, minratio):
    max_va = 1 << bits
    sorted_vals = sorted(values)
    votes = collections.defaultdict(set)
    for v in values:
        if v < 0x10000:
            continue
        for i, rva in low.get(v & 0xFFFF, ()):
            base = v - rva
            if base > 0 and not base & 0xFFFF and base + rva < max_va:
                votes[(i, base)].add(v)
    hyps = {}
    for (i, base), s in votes.items():
        if len(s) < minsup:
            continue
        # distinct dump values inside the export range of the hypothesised DLL: an IAT points only at exports
        window = bisect.bisect_right(sorted_vals, base + refs[i]["hi"]) - bisect.bisect_left(sorted_vals, base + refs[i]["lo"])
        ratio = len(s) / window
        if ratio >= minratio:
            hyps[(i, base)] = (s, ratio)
    assign = {}
    used = []
    for (i, base), (s, ratio) in sorted(hyps.items(), key=lambda x: (-x[1][1] * len(x[1][0]), -len(x[1][0]))):
        free = [v for v in s if v not in assign]
        if len(free) < minsup:
            continue
        used.append((i, base, len(free), round(ratio, 2)))
        for v in free:
            assign[v] = (i, base)
    return assign, used, len(hyps)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("bits", type=int)
    ap.add_argument("dbdir")
    ap.add_argument("--exclude", nargs="*", default=[])
    ap.add_argument("--minsup", type=int, default=3)
    ap.add_argument("--minratio", type=float, default=0.0)
    ap.add_argument("--minadj", type=float, default=0.0)
    ap.add_argument("--truth", help="apiscout scan --json of the same dump with the matching DB")
    ap.add_argument("--out")
    a = ap.parse_args()
    t0 = time.time()
    refs, low = load_refs(a.dbdir, a.bits, set(a.exclude))
    offsets = dump_values(a.dump, a.bits)
    assign, used, nhyp = solve(offsets.keys(), refs, low, a.minsup, a.bits, a.minratio)
    found = {}
    for v, (i, base) in assign.items():
        ref = refs[i]
        for off in offsets[v]:
            found[off] = dict(value=v, dll=ref["name"], tag=ref["tag"], base=base,
                              names=sorted(ref["by_rva"][v - base]))
    if a.minadj:
        # API pointers sit in tables: drop hypotheses whose hits mostly have no other hit within 8 bytes
        size = a.bits // 8
        groups = collections.defaultdict(list)
        for off, f in found.items():
            groups[(f["tag"], f["dll"], f["base"])].append(off)
        keep = set()
        for key, offs in groups.items():
            adj = sum(1 for o in offs if any(o + d * size in found for d in (-2, -1, 1, 2))) / len(offs)
            if adj >= a.minadj:
                keep.add(key)
        found = {o: f for o, f in found.items() if (f["tag"], f["dll"], f["base"]) in keep}
        used = [u for u in used if (refs[u[0]]["tag"], refs[u[0]]["name"], u[1]) in keep]
    res = dict(dump=os.path.basename(a.dump), exclude=a.exclude, layouts=len(refs), distinct_values=len(offsets),
               hypotheses_at_minsup=nhyp, accepted=[dict(dll=refs[i]["name"], tag=refs[i]["tag"], base=hex(b),
                                                         support=s, ratio=q) for i, b, s, q in used],
               hits=len(found), seconds=round(time.time() - t0, 1))
    if a.truth:
        t = json.load(open(a.truth))
        truth = {x["offset"]: (x["dll"].split("(")[0].lower(), x["api"]) for x in t["apis"]}
        tp_dll = tp_name = 0
        for off, (dll, api) in truth.items():
            f = found.get(off)
            if f and f["dll"] == dll:
                tp_dll += 1
                tp_name += api in f["names"]
        extra = [off for off in found if off not in truth]
        res["truth"] = dict(n=len(truth), recall_dll=tp_dll, recall_name=tp_name, extra_hits=len(extra),
                            extra_sample=[dict(offset=hex(o), **{k: (hex(v) if k in ("value", "base") else v)
                                                                 for k, v in found[o].items()})
                                          for o in sorted(extra)[:8]],
                            missed=[(hex(o), d, n) for o, (d, n) in sorted(truth.items()) if o not in found][:8])
    print(json.dumps(res, indent=1))
    if a.out:
        json.dump(dict(res, found={hex(k): v for k, v in sorted(found.items())}), open(a.out, "w"), indent=1)


if __name__ == "__main__":
    sys.exit(main())
