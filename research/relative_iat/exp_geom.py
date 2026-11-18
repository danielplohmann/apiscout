import json, collections, random, statistics, sys
random.seed(1337)
d=json.load(open('dbs/win7_prof-n_sp1_example.json'))
BITS=64
refs={}   # key -> dict(rvaset, byrva, byres)
for kk,v in d['dlls'].items():
    if v['bitness']!=BITS: continue
    byrva=collections.defaultdict(set)
    for e in v['exports']:
        byrva[e['address']].add(e['name'])
    byres=collections.defaultdict(list)
    for r in byrva: byres[r & 0xFFFF].append(r)
    byres12=collections.defaultdict(list)
    for r in byrva: byres12[r & 0xFFF].append(r)
    refs[kk]=dict(name=kk.split('_')[2].lower(), byrva=byrva, rvaset=set(byrva),
                  byres=byres, byres12=byres12)
print("reference DLLs:",len(refs),"distinct rva-slots:",sum(len(r['rvaset']) for r in refs.values()))

def solve(V, gran=0x10000):
    """return list of (dllkey, base) hypotheses consistent with all VAs in V"""
    v0=V[0]; out=[]
    for kk,r in refs.items():
        cand = r['byres'][v0 & 0xFFFF] if gran==0x10000 else r['byres12'][v0 & 0xFFF]
        rs=r['rvaset']
        for rva in cand:
            B=v0-rva
            if B<=0 or (B & (gran-1)): continue
            ok=True
            for v in V[1:]:
                if (v-B) not in rs: ok=False; break
            if ok: out.append((kk,B))
    return out

COMMON=['kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','msvcrt.dll','gdi32.dll',
        'ws2_32.dll','shell32.dll','ole32.dll','oleaut32.dll','shlwapi.dll','wininet.dll',
        'crypt32.dll','psapi.dll','version.dll','urlmon.dll','netapi32.dll','userenv.dll']
common_keys=[kk for kk,r in refs.items() if r['name'] in COMMON]
print("common-DLL refs:",len(common_keys), sorted({refs[k]['name'] for k in common_keys}))

def trial(keys, k, gran=0x10000):
    kk=random.choice([x for x in keys if len(refs[x]['rvaset'])>=k])
    r=refs[kk]
    rvas=random.sample(sorted(r['rvaset']), k)
    base=random.randrange(0x10000000, 0x7FF00000000, 0x10000)
    V=[base+x for x in rvas]
    hyps=solve(V, gran)
    # name-level ambiguity for slot0 across all hypotheses
    names=set(); dllnames=set()
    for hk,B in hyps:
        names |= refs[hk]['byrva'][V[0]-B]
        dllnames.add(refs[hk]['name'])
    truenames=r['byrva'][rvas[0]]
    return dict(nhyp=len(hyps), ndll=len(dllnames), nname=len(names),
                correct_dll=(r['name'] in dllnames), true_in=bool(truenames & names),
                uniq_name=(len(names)==1), true_alias=len(truenames))

for label,keys in [("common-DLLs",common_keys),("all-194-DLLs",list(refs))]:
    print(f"\n=== {label} (64-bit, 64KB base granularity) ===")
    print(f"{'k':>3} {'med#hyp':>8} {'mean#hyp':>9} {'med#names':>10} {'p90#names':>10} {'uniqDLL%':>9} {'uniqName%':>10} {'trueIn%':>8}")
    for k in [1,2,3,4,5,6,8,12,20]:
        T=[trial(keys,k) for _ in range(300)]
        h=[t['nhyp'] for t in T]; n=[t['nname'] for t in T]
        print(f"{k:>3} {statistics.median(h):8.1f} {statistics.mean(h):9.1f} {statistics.median(n):10.1f} "
              f"{sorted(n)[269]:10d} {100*statistics.mean([t['ndll']==1 for t in T]):9.1f} "
              f"{100*statistics.mean([t['uniq_name'] for t in T]):10.1f} {100*statistics.mean([t['true_in'] for t in T]):8.1f}")
