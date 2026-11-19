"""IAT-run extension on top of R8. usage: ext_eval.py dev.jsonl|test.jsonl out.jsonl [--workers N]

Starting from R8's answer, neighbours of accepted hits are added from the winning build only. Hits of the
answer's own DLLs at their solved base are always taken (the solver already holds nearly all of them).
E2:   new DLLs: >= 2 distinct values fitting one (DLL, base) within 32 slots of an accepted hit, two of them
      within 2 slots of each other.
E2r:  E2, and code reads (ff15/ff25) at least one of the new DLL's pointers.
E2v3: E2 with >= 3 distinct values.
E4c:  E2, plus single pointers within 2 slots of the run that exactly one (DLL, base) fits and code reads.
E4cr: E4c with E2r's read check for new DLLs (the variant chosen on dev).
Ground truth is rescanned with the truth DB to get per-offset DLL and API names.
"""
import argparse, collections, json, multiprocessing, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze as A, blind_solve as B, corpus_eval as C

G = {}

def init():
    C.init(0.3, 0.5)
    G["build"] = {}
    tags = [t for t, _ in B.DBS]
    for t in tags:
        for bits in (32, 64):
            refs, low = B.load_refs(C.DBDIR, bits, set(tags) - {t})
            byname = collections.defaultdict(list)
            for i, r in enumerate(refs):
                byname[r["name"]].append(i)
            arr = {i: np.fromiter(r["by_rva"], dtype=np.int64) for i, r in enumerate(refs)}
            G["build"][(t, bits)] = (refs, low, byname, arr)

def umode(base, bits):
    return 0x10000 <= base < (0x80000000 if bits == 32 else 0x7FFFFFFF0000)

def extend(vals, groups, variant, reads=frozenset()):
    tag, bits = groups[0]["tag"], groups[0]["bits"]
    refs, low, byname, arr = G["build"][(tag, bits)]
    size = bits // 8
    n = len(vals)
    known = {}
    for g in groups:
        known.setdefault(g["dll"], int(g["base"], 16))
    acc = {}
    for g in groups:
        for o in g["offs"]:
            acc[o // size] = None
    new = {}

    def fit_known(v):
        for dll, b in known.items():
            rva = v - b
            for i in byname.get(dll, ()):
                if rva in refs[i]["by_rva"]:
                    return (dll, i, rva)
        return None

    def grow():
        frontier = list(acc)
        while frontier:
            s = frontier.pop()
            for d in (-2, -1, 1, 2):
                t = s + d
                if 0 <= t < n and t not in acc:
                    v = int(vals[t])
                    if v:
                        f = fit_known(v)
                        if f:
                            acc[t] = new[t] = f
                            frontier.append(t)

    if variant == "E3":
        for dll, b in known.items():
            for i in byname.get(dll, ()):
                m = np.isin(vals.astype(np.int64) - b, arr[i]) & (vals != 0)
                for t in np.nonzero(m)[0].tolist():
                    if t not in acc:
                        acc[t] = new[t] = (dll, i, int(vals[t]) - b)
        return new, known
    grow()
    if variant.startswith(("E2", "E4")):
        spans = [(b, b + refs[byname[d][0]]["hi"]) for d, b in known.items() if byname.get(d)]
        pending = collections.defaultdict(dict)
        slots = sorted({t for s in acc for t in range(max(0, s - 32), min(n, s + 33))} - set(acc))
        for t in slots:
            v = int(vals[t])
            if v < 0x10000:
                continue
            for i, rva in low.get(v & 0xFFFF, ()):
                name = refs[i]["name"]
                base = v - rva
                if name in known or base & 0xFFFF or not umode(base, bits):
                    continue
                if any(lo <= base <= hi for lo, hi in spans):
                    continue
                pending[(name, i, base)][t] = rva
        cands = []
        for (name, i, base), hs in pending.items():
            ts = sorted(hs)
            need = 3 if variant == "E2v3" else 2
            if variant in ("E2r", "E4cr") and not any(t * size in reads for t in ts):
                continue
            if len({vals[t] for t in ts}) >= need and any(b - a <= 2 for a, b in zip(ts, ts[1:])):
                cands.append((len(ts), name, i, base, hs))
        for _, name, i, base, hs in sorted(cands, key=lambda c: -c[0]):
            if name in known or any(t in acc for t in hs):
                continue
            known[name] = base
            for t, rva in hs.items():
                acc[t] = new[t] = (name, i, rva)
        grow()
    if variant in ("E4", "E4c", "E4cr"):
        # one pointer next to the table: accept it when exactly one (DLL, base) of the build fits it
        for _ in range(8):
            spans = [(b, b + refs[byname[d][0]]["hi"]) for d, b in known.items() if byname.get(d)]
            added = False
            for t in sorted({s + d for s in acc for d in (-2, -1, 1, 2)} - set(acc)):
                if not 0 <= t < n or t in acc:
                    continue
                v = int(vals[t])
                if v < 0x10000:
                    continue
                if variant in ("E4c", "E4cr") and t * size not in reads:
                    continue
                fits = {}
                for i, rva in low.get(v & 0xFFFF, ()):
                    name, base = refs[i]["name"], v - rva
                    if name in known or base & 0xFFFF or not umode(base, bits):
                        continue
                    if any(lo <= base <= hi for lo, hi in spans):
                        continue
                    fits[(name, base)] = (i, rva)
                if len(fits) == 1:
                    (name, base), (i, rva) = fits.popitem()
                    known[name] = base
                    acc[t] = new[t] = (name, i, rva)
                    added = True
            grow()
            if not added:
                break
    return new, known

def evaluate(line):
    r = json.loads(line)
    if "error" in r:
        return None
    out = dict(path=r["path"], truth_n=r["truth_n"], truth_tag=r["truth_tag"])
    dump = A.dump_range(r)
    data = open(r["path"], "rb").read()
    truth = {}
    if r["truth_tag"]:
        scout = C.G["scouts"][r["truth_tag"]]
        scout.setBaseAddress(int(r["base"], 16))
        res = scout.crawl(data)
        res = scout.filterByConfidence(res, 20, scout.getConfidences(res))
        for entries in res.values():
            for e in entries:
                truth[(e[0], e[4])] = (e[2].split("(")[0].lower().rsplit("_0x", 1)[0], e[3])
    for key, gs in (("std", r["groups"]), ("lo", r.get("groups_lo", []))):
        g = A.rule8(gs, r["path"], dump)
        if not g:
            out[key] = None
            continue
        bits = g[0]["bits"]
        size = bits // 8
        vals = np.frombuffer(data[: len(data) // size * size], dtype="<u4" if bits == 32 else "<u8")
        base_hits = sum(x["hits"] for x in g)
        base_ok = sum(x["ok_dll"] for x in g)
        o = dict(tag=g[0]["tag"], bits=bits, hits=base_hits, ok=base_ok)
        refs = G["build"][(g[0]["tag"], bits)][0]
        reads = A.code_reads(r["path"], dump[0], bits) if dump else set()
        for var in ("E2", "E2r", "E2v3", "E4c", "E4cr"):
            new, known = extend(vals, g, var, reads)
            ok_d = ok_n = ok_read = ex_read = 0
            newdll = collections.Counter()
            for t, (dll, i, rva) in new.items():
                tr = truth.get((t * size, bits))
                if tr and tr[0] == dll:
                    ok_d += 1
                    ok_n += tr[1] in refs[i]["by_rva"][rva]
                    ok_read += t * size in reads
                else:
                    ex_read += t * size in reads
                if dll not in {x["dll"] for x in g}:
                    newdll[dll] += 1
            o[var] = dict(new=len(new), ok_dll=ok_d, ok_name=ok_n, ok_read=ok_read, ex_read=ex_read, newdlls=dict(newdll))
        out[key] = o
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl"); ap.add_argument("out"); ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    with open(a.out, "w") as f, multiprocessing.Pool(a.workers, init) as pool:
        for i, rec in enumerate(pool.imap_unordered(evaluate, open(a.jsonl), chunksize=4)):
            if rec:
                f.write(json.dumps(rec) + "\n")
            if i % 300 == 0:
                print(i, flush=True)

if __name__ == "__main__":
    main()
