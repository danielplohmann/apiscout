"""Tables for ext_eval.py output. usage: ext_report.py ext_dev.jsonl"""
import json, sys, collections
rows = [json.loads(l) for l in open(sys.argv[1])]
wt = [r for r in rows if r["truth_n"] >= 5]
nt = [r for r in rows if r["truth_n"] < 5]
N = sum(r["truth_n"] for r in wt)
def line(label, ok, okn, hits, dumps_extra):
    print(f"  {label:6s} recall_dll {100*ok/N:5.2f}%  recall_name {100*okn/N:5.2f}%  precision {100*ok/hits:5.2f}%  extra {hits-ok:6d}  dumps_with_extra {dumps_extra}")
print(f"dumps with truth: {len(wt)}, truth hits {N}")
base_ok = sum(r["std"]["ok"] for r in wt if r["std"]); base_h = sum(r["std"]["hits"] for r in wt if r["std"])
# R8 name recall equals dll recall within 0.1 point; approximate base name hits by dll hits
line("R8", base_ok, base_ok, base_h, sum(1 for r in wt if r["std"] and r["std"]["hits"] > r["std"]["ok"]))
for v in ("E2", "E2r", "E2v3", "E4c", "E4cr"):
    ok = base_ok + sum(r["std"][v]["ok_dll"] for r in wt if r["std"])
    okn = base_ok + sum(r["std"][v]["ok_name"] for r in wt if r["std"])
    h = base_h + sum(r["std"][v]["new"] for r in wt if r["std"])
    de = sum(1 for r in wt if r["std"] and r["std"]["hits"] + r["std"][v]["new"] > r["std"]["ok"] + r["std"][v]["ok_dll"])
    line(v, ok, okn, h, de)
    wrong = collections.Counter()
    for r in wt:
        if r["std"]:
            for d, c in r["std"][v]["newdlls"].items():
                wrong[d] += c
    lo = sum(r["lo"][v]["new"] for r in wt if r.get("lo"))
    ntn = sum(r["std"][v]["new"] for r in nt if r["std"])
    okr = sum(r["std"][v]["ok_read"] for r in wt if r["std"]); exr = sum(r["std"][v]["ex_read"] for r in wt if r["std"])
    nok = ok - base_ok; nex = h - base_h - nok
    print(f"         new correct {nok} ({100*okr/max(nok,1):.0f}% read by code)   new extra {nex} ({100*exr/max(nex,1):.0f}% read by code)")
    print(f"         leave-out: new hits on wrong answers {lo}   no-truth dumps: new hits {ntn}")
