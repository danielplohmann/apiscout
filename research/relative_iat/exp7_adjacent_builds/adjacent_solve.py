"""Leave-one-build-out solver test: IATs sampled from one build, solved against the layouts of all other builds.

For each target layout T of a DLL: K imports drawn from T's common APIs (winapi1024 names), placed at a random
64 KB-aligned base. Reference set: every other distinct layout of the same DLL and arch (optionally only older
ones, as a DB shipped earlier would be). Solved with blind_solve.solve (support >= 3). Each import is counted as
correct (a fitting hypothesis names it right), wrong (only wrong names) or missed.
usage: adjacent_solve.py EXPORTS_DIR WINAPI1024 RIAT_DIR [--k 10 30 100] [--trials 5]
"""
import argparse, collections, random, sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exdir"); ap.add_argument("w1024"); ap.add_argument("riat")
    ap.add_argument("--k", type=int, nargs="+", default=[10, 30, 100])
    ap.add_argument("--trials", type=int, default=5)
    a = ap.parse_args()
    sys.path.insert(0, a.riat)
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    import blind_solve as B
    from adjacent import load
    random.seed(7)
    common = {l.split(";")[2].split("!")[1] for l in open(a.w1024)}
    is_common = lambda n: n in common or (n[-1:] in "AW" and n[:-1] in common)
    data = load(a.exdir)
    print("dll arch refset  k   one base: correct wrong missed | consensus: correct wrong abstain | greedy: correct wrong missed")
    for (dll, arch), builds in sorted(data.items()):
        bits = 64 if arch == "x64" else 32
        refs_all = []
        for b in builds:
            by_rva = collections.defaultdict(set)
            for n, r in b["exports"].items():
                by_rva[r].add(n)
            refs_all.append(dict(tag=b["sha256"][:12], name=dll, by_rva=by_rva, lo=min(by_rva), hi=max(by_rva),
                                 first=b["first_seen"] or ""))
        for refset in ("self", "others", "older"):
            for k in a.k:
                tot = collections.Counter()
                for ti, T in enumerate(builds):
                    names = [n for n in T["exports"] if is_common(n)]
                    if len(names) < k:
                        continue
                    refs = [r for j, r in enumerate(refs_all) if refset == "self" or (j != ti and (refset == "others" or r["first"] < refs_all[ti]["first"]))]
                    if not refs:
                        continue
                    low = collections.defaultdict(list)
                    for i, ref in enumerate(refs):
                        for rva in ref["by_rva"]:
                            low[rva & 0xFFFF].append((i, rva))
                    for _ in range(a.trials):
                        pick = random.sample(names, k)
                        base = random.randrange(1, (0x7FF000000000 if bits == 64 else 0x7F000000) // 0x10000) * 0x10000
                        vals = {base + T["exports"][n]: n for n in pick}
                        # greedy, several bases allowed: blind_solve.solve as on real dumps (support >= 3)
                        assign, _, _ = B.solve(vals.keys(), refs, low, 3, bits, 0.0)
                        for v, n in vals.items():
                            if v not in assign:
                                tot["g_missed"] += 1
                            else:
                                i, bb = assign[v]
                                tot["g_correct" if n in refs[i]["by_rva"][v - bb] else "g_wrong"] += 1
                        # one DLL, one base: the (layout, base) with the most support picks the base, as in the
                        # solver; values are then named greedily by layouts at that base in order of support
                        hyp = collections.defaultdict(set)
                        for v in vals:
                            for i, rva in low.get(v & 0xFFFF, ()):
                                hyp[(i, v - rva)].add(v)
                        (i0, b), s0 = max(hyp.items(), key=lambda x: len(x[1]), default=((None, None), ()))
                        if len(s0) < 3:
                            tot["missed"] += k
                            tot["u_missed"] += k
                            tot["no_base"] += 1
                            continue
                        tot["right_base"] += b == base
                        at_b = sorted(((len(sv), i) for (i, bb), sv in hyp.items() if bb == b and len(sv) >= 3), reverse=True)
                        strong = [i for n_, i in at_b if n_ >= 0.5 * at_b[0][0]]
                        for v, n in vals.items():
                            got = next((refs[i]["by_rva"][v - b] for _, i in at_b if (v - b) in refs[i]["by_rva"]), None)
                            if got is None:
                                tot["missed"] += 1
                            else:
                                tot["correct" if n in got else "wrong"] += 1
                            # consensus: every strong layout that has an export there gives the same name set
                            sets = {frozenset(refs[i]["by_rva"][v - b]) for i in strong if (v - b) in refs[i]["by_rva"]}
                            if len(sets) == 1:
                                tot["u_correct" if n in next(iter(sets)) else "u_wrong"] += 1
                            else:
                                tot["u_missed"] += 1
                s = (tot["correct"] + tot["wrong"] + tot["missed"]) or 1
                runs = tot["right_base"] + tot["no_base"] + 0
                print(f"{dll:14s} {arch} {refset:6s} {k:4d}   {100*tot['correct']/s:5.1f}%  {100*tot['wrong']/s:5.1f}%  {100*tot['missed']/s:5.1f}%"
                      f"  | consensus {100*tot['u_correct']/s:5.1f}%  {100*tot['u_wrong']/s:5.1f}%  {100*tot['u_missed']/s:5.1f}%"
                      f"  | greedy {100*tot['g_correct']/s:5.1f}%  {100*tot['g_wrong']/s:5.1f}%  {100*tot['g_missed']/s:5.1f}%"
                      f"   ({s})  right base in {tot['right_base']} runs, no base in {tot['no_base']}", flush=True)

if __name__ == "__main__":
    main()
