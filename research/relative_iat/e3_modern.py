"""E3-lite: cross-build fits among the five shipped DBs (XP, 7, 10 1803, Server 2022, 11 26H2)."""
import json, random, collections, sys
random.seed(1)
DBS = [("xp","winxp_prof_sp3_example.json"),("w7","win7_prof-n_sp1_example.json"),("w10","win10_prof_1803_example.json"),
       ("s22","win2022_server_21h2_example.json"),("w11","win11_pro_26h2_example.json")]
TARGETS = ["kernelbase.dll","ntdll.dll","user32.dll","advapi32.dll","ws2_32.dll","wininet.dll","shell32.dll","crypt32.dll"]
refs = {32: [], 64: []}
seen = set()
for tag, f in DBS:
    for v in json.load(open("dbs/" + f))["dlls"].values():
        name = v["filepath"].lower().split("\\")[-1]
        by_rva = collections.defaultdict(set)
        for e in v["exports"]:
            if e["name"]: by_rva[e["address"]].add(e["name"])
        if not by_rva: continue
        key = (v["bitness"], name, frozenset(by_rva))
        if key in seen: continue   # byte-identical layout already in the set
        seen.add(key)
        low = collections.defaultdict(list)
        for r in by_rva: low[r & 0xFFFF].append(r)
        refs[v["bitness"]].append(dict(tag=tag, name=name, version=v["version"], by_rva=by_rva, low=low))

def hypotheses(bits, rvas):
    d = [r - rvas[0] for r in rvas]
    out = []
    for ref in refs[bits]:
        for a in ref["low"].get(rvas[0] & 0xFFFF, ()):
            if all(a + x in ref["by_rva"] for x in d):
                out.append((ref, [ref["by_rva"][a + x] for x in d]))
    return out

KS = [1, 2, 3, 4, 6, 8]
TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 else 150
for bits in (64, 32):
    print(f"\n=== {bits}-bit, reference set: {len(refs[bits])} distinct DLL layouts from 5 DBs")
    print("   k  uniqDLL+build%  wrongBuildFits%  namesAgreeWhenWrongFits%  uniqNameAfterVote%  trueInVote%")
    truths = [r for r in refs[bits] if r["tag"] in ("w10","s22","w11") and r["name"] in TARGETS]
    for k in KS:
        uniq = wrong = agree = wrongn = uname = truein = 0
        for _ in range(TRIALS):
            t = random.choice(truths)
            rvas = random.sample(sorted(t["by_rva"]), k)
            truenames = [t["by_rva"][r] for r in rvas]
            hyps = hypotheses(bits, rvas)
            if len(hyps) == 1: uniq += 1
            others = [h for h in hyps if h[0] is not t]
            same_dll_other_build = [h for h in others if h[0]["name"] == t["name"]]
            if same_dll_other_build:
                wrong += 1
                wrongn += 1
                if all(all(h[1][i] & truenames[i] for i in range(k)) for h in same_dll_other_build): agree += 1
            # name-level vote over every fitting hypothesis, per slot
            ok_u = ok_t = True
            for i in range(k):
                votes = collections.Counter(n for h in hyps for n in h[1][i])
                top = max(votes.values())
                best = {n for n, c in votes.items() if c == top}
                ok_u &= len(best) == 1
                ok_t &= bool(best & truenames[i])
            uname += ok_u; truein += ok_t
        p = lambda x, n=TRIALS: f"{100*x/n:6.1f}" if n else "   n/a"
        print(f"  {k:2d}  {p(uniq):>14}  {p(wrong):>15}  {p(agree, wrongn):>24}  {p(uname):>18}  {p(truein):>11}")
