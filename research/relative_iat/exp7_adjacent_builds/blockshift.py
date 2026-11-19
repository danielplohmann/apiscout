"""Block-shift naming: one aligned base per DLL, plus a small offset delta per block of the reference layout.

Between monthly builds a DLL's exports move in a few contiguous blocks, each by a constant amount. Given the base
b (from the ordinary solver), a hypothesis (layout i, delta) names value v as the export at v - b - delta. Its
support is the number of values it explains; its interval is the RVA range those values span in layout i. A value
goes to the supported hypothesis whose interval contains it, the most supported one first.
"""
import bisect, collections

def name_values(vals, b, refs, window=0x10000, minsup=3):
    sorted_rvas = [sorted(r["by_rva"]) for r in refs]
    hyp = collections.defaultdict(set)
    for v in vals:
        x = v - b
        for i, rv in enumerate(sorted_rvas):
            lo = bisect.bisect_left(rv, x - window)
            hi = bisect.bisect_right(rv, x + window)
            for rva in rv[lo:hi]:
                hyp[(i, x - rva)].add(v)
    good = {h: s for h, s in hyp.items() if len(s) >= minsup}
    interval = {(i, d): (min(v - b - d for v in s), max(v - b - d for v in s)) for (i, d), s in good.items()}
    out = {}
    for v in vals:
        x = v - b
        cands = [(h, len(s)) for h, s in good.items() if v in s]
        if not cands:
            continue
        inside = [(h, n) for h, n in cands if interval[h][0] <= x - h[1] <= interval[h][1]]
        (i, d), _ = max(inside or cands, key=lambda c: (c[1], -abs(c[0][1])))
        out[v] = refs[i]["by_rva"][x - d]
    return out
