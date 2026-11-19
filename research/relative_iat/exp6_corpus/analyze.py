"""Summarise corpus_eval.py output under the filter rules R0-R8 (R8 is the final one). usage: analyze.py dev.jsonl|test.jsonl"""
import argparse
import os
import collections
import json


import struct

BEST = 8
DBDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "dbs")
_DENSE = None


def dense_layouts():
    """(tag, dll, bits) whose median gap between export RVAs is at most 16 bytes, such as syscall-stub DLLs"""
    global _DENSE
    if _DENSE is None:
        import os
        from blind_solve import DBS
        _DENSE = set()
        for tag, fname in DBS:
            for dll in json.load(open(os.path.join(DBDIR, fname)))["dlls"].values():
                rvas = sorted({e["address"] for e in dll["exports"] if e["name"]})
                if len(rvas) < 20:
                    continue
                gaps = sorted(b - a for a, b in zip(rvas, rvas[1:]))
                if gaps[len(gaps) // 2] <= 16:
                    name = dll["filepath"].lower().replace("/", "\\").split("\\")[-1]
                    _DENSE.add((tag, name, dll["bitness"]))
    return _DENSE
ANCHOR = 5
RATIO = 0.7
_PE_BITS = {}


def pe_bits(path):
    """32 or 64 from the PE header at the start of the dump, None if it has none"""
    if path not in _PE_BITS:
        bits = None
        try:
            with open(path, "rb") as f:
                head = f.read(0x1000)
            if head[:2] == b"MZ":
                lfanew = struct.unpack_from("<I", head, 0x3C)[0]
                if lfanew + 6 <= len(head) and head[lfanew:lfanew + 4] == b"PE\0\0":
                    machine = struct.unpack_from("<H", head, lfanew + 4)[0]
                    bits = {0x14C: 32, 0x8664: 64}.get(machine)
        except OSError:
            pass
        _PE_BITS[path] = bits
    return _PE_BITS[path]


def dump_range(r):
    base = int(r["base"], 16)
    return (base, base + r["size"]) if base else None


def rule_pass(groups, rule, path=None, dump=None):
    if rule >= 8:
        return rule8(groups, path, dump)
    if rule >= 7:
        return rule7(groups, path, dump)
    g = [x for x in groups if x["support"] >= 3]
    if rule >= 6 and dump:
        # a DLL can not overlap the memory region the dump was taken from
        lo, hi = dump
        g = [x for x in g if not (int(x["base"], 16) < hi and lo < int(x["base"], 16) + x.get("span", 0x10000))]
    if rule >= 5 and path and pe_bits(path):
        g = [x for x in g if x["bits"] == pe_bits(path)]
    if rule >= 4:
        # user-mode DLL bases only: 32-bit below 2 GB, 64-bit canonical user space; applied before the build vote
        g = [x for x in g if 0x10000 <= int(x["base"], 16) < (0x80000000 if x["bits"] == 32 else 0x7FFFFFFF0000)]
    if rule >= 1:
        g = [x for x in g if x["ratio"] >= RATIO]
    if rule >= 2:
        g = [x for x in g if x["adj"] >= 0.5]
    rule_pass_pre = list(g)
    if rule >= 3 and g:
        # one build and one bitness per dump: those of the most hits among the remaining groups
        by = collections.Counter()
        for x in g:
            by[(x["tag"], x["bits"])] += x["hits"]
        tag, bits = by.most_common(1)[0][0]
        g = [x for x in g if x["tag"] == tag and x["bits"] == bits]
        if rule >= 6:
            dense = dense_layouts()
            anchors = [x for x in rule_pass_pre if (x["tag"], x["dll"], x["bits"]) not in dense]
            if not anchors or max(x["support"] for x in anchors) < ANCHOR:
                return []
            # the build vote again, counting only DLLs that can anchor it
            by = collections.Counter()
            for x in rule_pass_pre:
                if (x["tag"], x["dll"], x["bits"]) not in dense:
                    by[(x["tag"], x["bits"])] += x["hits"]
            tag, bits = by.most_common(1)[0][0]
            g = [x for x in rule_pass_pre if x["tag"] == tag and x["bits"] == bits]
            return g
        if rule >= 5 and max(x["support"] for x in g) < ANCHOR:
            # no DLL of the build is carried by enough pointers: answer nothing rather than guess
            g = []
    return g


def pct(a, b):
    return f"{100 * a / b:5.1f}%" if b else "  n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--min-truth", type=int, default=5)
    ap.add_argument("--anchor", type=int, default=5)
    ap.add_argument("--ratio", type=float, default=0.5)
    ap.add_argument("--sig", type=float, default=-9.0)
    a = ap.parse_args()
    global ANCHOR, RATIO, SIG
    ANCHOR, RATIO, SIG = a.anchor, a.ratio, a.sig
    recs = [json.loads(line) for line in open(a.jsonl)]
    errors = [r for r in recs if "error" in r]
    recs = [r for r in recs if "error" not in r]
    print(f"dumps evaluated: {len(recs)}  errors: {len(errors)}  by corpus: {dict(collections.Counter(r['corpus'] for r in recs))}")
    for e in errors[:3]:
        print("  error", e["path"], e["error"][:120])
    with_truth = [r for r in recs if r["truth_n"] >= a.min_truth]
    no_truth = [r for r in recs if r["truth_n"] < a.min_truth]
    print(f"with ground truth (classic >= {a.min_truth} hits): {len(with_truth)}   without: {len(no_truth)}")

    print("\nnaming vs best classic DB (rows: file kind, cols: truth build)")
    tab = collections.defaultdict(collections.Counter)
    for r in recs:
        tab[r["kind"]][r["truth_tag"] if r["truth_n"] >= a.min_truth else "none"] += 1
    cols = ["xp", "w7", "w10", "s22", "w11", "none"]
    print("  kind     " + "".join(f"{c:>7}" for c in cols))
    for kind in sorted(tab):
        print(f"  {kind:8} " + "".join(f"{tab[kind][c]:7}" for c in cols))

    print("\nblind solver on dumps with ground truth (micro-averaged over hits)")
    print("  rule  recall_dll recall_name  precision_dll  extra_hits  dumps>=90%recall  dumps_0_extra")
    for rule in range(9):
        n_truth = ok_dll = ok_name = hits = 0
        good_dumps = clean_dumps = 0
        for r in with_truth:
            g = rule_pass(r["groups"], rule, r["path"], dump_range(r))
            od = sum(x["ok_dll"] for x in g)
            h = sum(x["hits"] for x in g)
            n_truth += r["truth_n"]
            ok_dll += od
            ok_name += sum(x["ok_name"] for x in g)
            hits += h
            good_dumps += od >= 0.9 * r["truth_n"]
            clean_dumps += h == od
        print(f"  R{rule}    {pct(ok_dll, n_truth):>9}  {pct(ok_name, n_truth):>10}  {pct(ok_dll, hits):>13}  {hits - ok_dll:10}"
              f"  {pct(good_dumps, len(with_truth)):>16}  {pct(clean_dumps, len(with_truth)):>13}")

    print("\nextra hits under the best rule, by whether they agree with the truth build (same build = plausibly real, classic missed)")
    same = other = 0
    ex_dlls = collections.Counter()
    for r in with_truth:
        for x in rule_pass(r["groups"], BEST, r["path"], dump_range(r)):
            e = x["hits"] - x["ok_dll"]
            if e:
                if x["tag"] == r["truth_tag"]:
                    same += e
                else:
                    other += e
                ex_dlls[f"{x['tag']}/{x['dll']}"] += e
    print(f"  same build: {same}  other build: {other}  top: {ex_dlls.most_common(8)}")

    print("\nmisses under the best rule: DLLs of the truth hits the solver did not recover")
    miss = collections.Counter()
    small = big = 0
    for r in with_truth:
        g = rule_pass(r["groups"], BEST, r["path"], dump_range(r))
        got = collections.Counter()
        for x in g:
            got[x["dll"]] += x["ok_dll"]
        for dll, n in r["truth_dlls"].items():
            m = n - got.get(dll, 0)
            if m > 0:
                miss[dll] += m
                if n <= 2:
                    small += m
                else:
                    big += m
    print(f"  in DLLs with 1-2 truth hits: {small}   in DLLs with >=3: {big}   top: {miss.most_common(8)}")

    print("\ntrue build left out of the reference set (dumps with ground truth)")
    for rule in (3, 6, 7, 8):
        any_hit = wrong = 0
        for r in with_truth:
            g = rule_pass(r.get("groups_lo", []), rule, r["path"], dump_range(r))
            h = sum(x["hits"] for x in g)
            if h:
                any_hit += 1
                wrong += h - sum(x["ok_dll"] for x in g)
        print(f"  R{rule}: dumps with any answer {any_hit}/{len(with_truth)} ({pct(any_hit, len(with_truth))}),"
              f" hits not matching the truth DLL: {wrong}")

    print("\ndumps without ground truth: what the blind solver (best rule) reports")
    got = [r for r in no_truth if rule_pass(r["groups"], BEST, r["path"], dump_range(r))]
    print(f"  {len(got)}/{len(no_truth)} get an answer; builds: "
          f"{collections.Counter(rule_pass(r['groups'], BEST, r["path"], dump_range(r))[0]['tag'] for r in got).most_common()}")
    sizes = collections.Counter()
    for r in got:
        h = sum(x["hits"] for x in rule_pass(r["groups"], BEST, r["path"], dump_range(r)))
        sizes["1-9" if h < 10 else "10-49" if h < 50 else "50+"] += 1
    print(f"  hits per dump: {dict(sizes)}")
    print("  sample:")
    for r in sorted(got, key=lambda r: -sum(x["hits"] for x in rule_pass(r["groups"], BEST, r["path"], dump_range(r))))[:6]:
        g = rule_pass(r["groups"], BEST, r["path"], dump_range(r))
        print(f"    {r['path'].split('/')[-2]:28} {r['kind']:7} classic={r['truth_n']:3} blind={sum(x['hits'] for x in g):4} "
              f"{[(x['tag'], x['dll'], x['base'], x['hits']) for x in g][:4]}")



# ---- R7: one significance test instead of the ratio threshold and the dense list ----
import math

_CHANCE = None


def layout_chance():
    """(tag, dll, bits) -> worst-case chance that a 4- or 16-aligned value inside the export range is an export"""
    global _CHANCE
    if _CHANCE is None:
        import os
        from blind_solve import DBS
        _CHANCE = {}
        for tag, fname in DBS:
            for dll in json.load(open(os.path.join(DBDIR, fname)))["dlls"].values():
                rvas = {e["address"] for e in dll["exports"] if e["name"]}
                if not rvas:
                    continue
                span = max(rvas) - min(rvas) + 1
                c4 = sum(1 for r in rvas if r % 4 == 0) / max(1, span // 4)
                c16 = sum(1 for r in rvas if r % 16 == 0) / max(1, span // 16)
                name = dll["filepath"].lower().replace("/", "\\").split("\\")[-1]
                key = (tag, name, dll["bitness"])
                _CHANCE[key] = max(_CHANCE.get(key, 0), min(1.0, max(c4, c16)))
    return _CHANCE


def log10_binom_sf(k, n, p):
    """log10 P(X >= k) for X ~ Bin(n, p)"""
    if k <= 0:
        return 0.0
    if p >= 1.0:
        return 0.0
    p = max(p, 1e-12)
    if k > n:
        return -math.inf
    lp, lq = math.log(p), math.log1p(-p)
    terms = []
    for i in range(k, n + 1):
        t = math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lp + (n - i) * lq
        terms.append(t)
        if len(terms) > 50 and t < terms[0] - 50:
            break
    m = max(terms)
    return (m + math.log(sum(math.exp(t - m) for t in terms))) / math.log(10)


SIG = -9.0


def significance(x):
    window = max(x["support"], round(x["support"] / x["ratio"]))
    c = layout_chance().get((x["tag"], x["dll"], x["bits"]), 1.0)
    return log10_binom_sf(x["support"], window, c)


def rule7(groups, path=None, dump=None):
    g = [x for x in groups if x["support"] >= 3 and x["adj"] >= 0.5]
    g = [x for x in g if 0x10000 <= int(x["base"], 16) < (0x80000000 if x["bits"] == 32 else 0x7FFFFFFF0000)]
    if dump:
        lo, hi = dump
        g = [x for x in g if not (int(x["base"], 16) < hi and lo < int(x["base"], 16) + 0x10000)]
    if path and pe_bits(path):
        g = [x for x in g if x["bits"] == pe_bits(path)]
    g = [dict(x, sig=significance(x)) for x in g]
    g = [x for x in g if x["sig"] <= SIG]
    if not g:
        return []
    by = collections.Counter()
    for x in g:
        by[(x["tag"], x["bits"])] += -x["sig"]
    tag, bits = by.most_common(1)[0][0]
    g = [x for x in g if x["tag"] == tag and x["bits"] == bits]
    if max(x["support"] for x in g) < ANCHOR:
        return []
    return g



# ---- R8: an answer of a single DLL must be confirmed by code reading its hits ----
_READS = {}
READ_SHARE = 0.5


def code_reads(path, base, bits):
    if (path, bits) not in _READS:
        from verify import code_read_offsets
        _READS[(path, bits)] = code_read_offsets(path, base, bits)
    return _READS[(path, bits)]


def rule8(groups, path=None, dump=None):
    g = rule7(groups, path, dump)
    if len({x["dll"] for x in g}) != 1:
        return g
    if not (path and dump):
        return []
    reads = code_reads(path, dump[0], g[0]["bits"])
    offs = [o for x in g for o in x["offs"]]
    return g if sum(o in reads for o in offs) >= READ_SHARE * len(offs) else []

if __name__ == "__main__":
    main()
