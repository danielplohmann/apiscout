"""Adjacent-build test (spike item 1): does the export layout of one build explain the IAT pointers of another?

A reference build R explains a pointer to API x of target build T at base b' when rva_R(x) = rva_T(x) + d for one
shift d that holds for the whole hypothesis (the base is unknown, so a constant shift is free). coverage(T, R) is
the largest share of T's APIs explained by one d. A pointer is named wrong when rva_T(x) + d hits another export of R.
APIs: all named exports of T that are no forwarders, and the 'common' subset whose names occur in winapi1024v1.
usage: adjacent.py EXPORTS_DIR WINAPI1024
"""
import collections, datetime, glob, json, os, sys

def load(exdir):
    layouts = collections.defaultdict(dict)  # (dll, arch) -> {layout key: build}
    for f in glob.glob(os.path.join(exdir, "*.json")):
        b = json.load(open(f))
        if not b["exports"] or not b.get("sha_ok", True):
            # the symbol server can hand out another file under the same key; only files matching Winbindex count
            continue
        key = frozenset(b["exports"].items())
        g = layouts[(b["dll"], b["arch"])]
        old = g.get(key)
        if old is None or (b["first_seen"] or "9") < (old["first_seen"] or "9"):
            if old:
                b["releases"] = sorted(set(b["releases"]) | set(old["releases"]))
            g[key] = b
        else:
            old["releases"] = sorted(set(old["releases"]) | set(b["releases"]))
    return {k: sorted(v.values(), key=lambda b: b["first_seen"] or "") for k, v in layouts.items()}

def coverage(T, R, names):
    ex_t, ex_r = T["exports"], R["exports"]
    shifts = collections.Counter(ex_r[n] - ex_t[n] for n in names if n in ex_r)
    if not shifts:
        return 0.0, 0.0, 0
    d, n_ok = shifts.most_common(1)[0]
    rva_r = collections.defaultdict(set)
    for n, r in ex_r.items():
        rva_r[r].add(n)
    wrong = sum(1 for n in names if ex_r.get(n, None) != ex_t[n] + d and rva_r.get(ex_t[n] + d))
    return n_ok / len(names), wrong / len(names), d

def months(a, b):
    if not a or not b:
        return None
    da, db = (datetime.date.fromisoformat(x) for x in (a, b))
    return abs((da - db).days) / 30.4

def branch(b):
    return b["release"]

def main():
    exdir, w1024 = sys.argv[1], sys.argv[2]
    common_names = set()
    for line in open(w1024):
        api = line.split(";")[2].split("!")[1]
        common_names.add(api)
    def is_common(n):
        return n in common_names or (n[-1:] in "AW" and n[:-1] in common_names)
    data = load(exdir)
    out = {}
    for (dll, arch), builds in sorted(data.items()):
        print(f"\n=== {dll} {arch}: {len(builds)} distinct layouts "
              f"({builds[0]['first_seen']} .. {builds[-1]['first_seen']})")
        rows = []
        for T in builds:
            all_n = list(T["exports"])
            com_n = [n for n in all_n if is_common(n)]
            for R in builds:
                if R is T:
                    continue
                ca, wa, _ = coverage(T, R, all_n)
                cc, wc, _ = coverage(T, R, com_n) if com_n else (0, 0, 0)
                rows.append(dict(t=T["sha256"][:12], r=R["sha256"][:12], tb=branch(T), rb=branch(R),
                                 gap=months(T["first_seen"], R["first_seen"]), r_older=(R["first_seen"] or "") < (T["first_seen"] or ""),
                                 cov_all=ca, wrong_all=wa, cov_com=cc, wrong_com=wc, ncom=len(com_n)))
        out[f"{dll}_{arch}"] = rows
        # 1. best other layout per target, as a reference set would offer it
        best = collections.defaultdict(lambda: (0, 0))
        best_prev = collections.defaultdict(lambda: (0, 0))
        for r in rows:
            if r["cov_com"] > best[r["t"]][0]:
                best[r["t"]] = (r["cov_com"], r["wrong_com"])
            if r["r_older"] and r["cov_com"] > best_prev[r["t"]][0]:
                best_prev[r["t"]] = (r["cov_com"], r["wrong_com"])
        def dist(b, label):
            v = [b[T["sha256"][:12]][0] for T in builds]
            buckets = [sum(x >= th for x in v) for th in (0.99, 0.9, 0.5)]
            w = max((b[T["sha256"][:12]][1] for T in builds), default=0)
            print(f"  {label:44s} >=99%: {buckets[0]:3d}  >=90%: {buckets[1]:3d}  >=50%: {buckets[2]:3d}  of {len(v)}   max wrong {100*w:.1f}%")
        dist(best, "best other layout explains common APIs")
        dist(best_prev, "best OLDER layout explains common APIs")
        # 2. decay with distance in time, same release vs. other release
        print("  months apart     same release: median cov_com (pairs)     other release: median cov_com (pairs)")
        for lo, hi in ((0, 1.5), (1.5, 3.5), (3.5, 6.5), (6.5, 12.5), (12.5, 24.5), (24.5, 999)):
            line = f"  {lo:4.1f}-{hi:<5}  "
            for same in (True, False):
                v = sorted(r["cov_com"] for r in rows if r["gap"] is not None and lo <= r["gap"] < hi and (r["tb"] == r["rb"]) == same)
                line += f"      {100*v[len(v)//2]:5.1f}% ({len(v):5d})" if v else "          n/a        "
                line += "             "
            print(line)
        # 3. greedy reference set: fewest layouts so that every layout has one at >= 90 % common coverage (itself counts)
        cov = collections.defaultdict(set)
        for T in builds:
            cov[T["sha256"][:12]].add(T["sha256"][:12])
        for r in rows:
            if r["cov_com"] >= 0.9:
                cov[r["r"]].add(r["t"])
        left, chosen = {T["sha256"][:12] for T in builds}, []
        while left:
            r = max(cov, key=lambda k: len(cov[k] & left))
            chosen.append(r)
            left -= cov[r]
        rel = {T["sha256"][:12]: (T["release"], T["first_seen"]) for T in builds}
        print(f"  reference set for >= 90% common coverage of every layout: {len(chosen)} of {len(builds)}: "
              + ", ".join(f"{rel[c][0]}@{rel[c][1]}" for c in chosen[:12]) + (" ..." if len(chosen) > 12 else ""))
    json.dump(out, open(os.path.join(os.path.dirname(exdir.rstrip("/")), "adjacent_pairs.json"), "w"))

if __name__ == "__main__":
    main()
