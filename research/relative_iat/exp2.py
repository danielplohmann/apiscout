import json, collections, random, statistics
random.seed(7)
w7=json.load(open('dbs/win7_prof-n_sp1_example.json'))
xp=json.load(open('dbs/winxp_prof_sp3_example.json'))

def build(dbs, bitness):
    refs={}
    for tag,db in dbs:
        for kk,v in db['dlls'].items():
            if v['bitness']!=bitness: continue
            byrva=collections.defaultdict(set)
            for e in v['exports']: byrva[e['address']].add(e['name'])
            byres=collections.defaultdict(list); byres12=collections.defaultdict(list)
            for r in byrva: byres[r&0xFFFF].append(r); byres12[r&0xFFF].append(r)
            refs[tag+"|"+kk]=dict(tag=tag,name=kk.split('_')[2].lower(),byrva=byrva,
                rvaset=set(byrva),byres=byres,byres12=byres12)
    return refs

def solve(refs,V,gran=0x10000):
    v0=V[0]; out=[]
    for kk,r in refs.items():
        cand=r['byres'][v0&0xFFFF] if gran==0x10000 else r['byres12'][v0&0xFFF]
        rs=r['rvaset']
        for rva in cand:
            B=v0-rva
            if B<=0 or (B&(gran-1)): continue
            if all((v-B) in rs for v in V[1:]): out.append((kk,B))
    return out

def ransac(refs,V,minsup,gran=0x10000):
    """base hypotheses supported by >=minsup of the observed slots (anchor over all slots)"""
    best=collections.defaultdict(int)
    for v0 in V:
        for kk,r in refs.items():
            cand=r['byres'][v0&0xFFFF] if gran==0x10000 else r['byres12'][v0&0xFFF]
            rs=r['rvaset']
            for rva in cand:
                B=v0-rva
                if B<=0 or (B&(gran-1)): continue
                s=sum(1 for v in V if (v-B) in rs)
                if s>=minsup: best[(kk,B)]=s
    return best

print("### A) 32-bit, reference = WinXP-SP3 + Win7-SP1 (two versions per DLL)")
refs32=build([("w7",w7),("xp",xp)],32)
print("refs:",len(refs32), "  rva-slots:",sum(len(r['rvaset']) for r in refs32.values()))
COMMON={'kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','msvcrt.dll','gdi32.dll','ws2_32.dll','shell32.dll','ole32.dll','oleaut32.dll','shlwapi.dll','wininet.dll','crypt32.dll'}
w7common=[k for k,r in refs32.items() if r['tag']=='w7' and r['name'] in COMMON]
print("query pool (w7 common dlls):",len(w7common))
print(f"{'k':>3} {'med#hyp':>8} {'uniqDLLname%':>13} {'uniqAPIname%':>13} {'trueIn%':>8} {'xpAlsoFits%':>12}")
for k in [2,3,4,5,8,16]:
    R=[]
    for _ in range(250):
        kk=random.choice(w7common); r=refs32[kk]
        rvas=random.sample(sorted(r['rvaset']),k)
        B=random.randrange(0x10000000,0x70000000,0x10000)
        V=[B+x for x in rvas]
        h=solve(refs32,V)
        names=set(); dn=set(); tags=set()
        for hk,hb in h:
            names|=refs32[hk]['byrva'][V[0]-hb]; dn.add(refs32[hk]['name']); tags.add(refs32[hk]['tag'])
        R.append((len(h),len(dn)==1,len(names)==1,bool(r['byrva'][rvas[0]]&names),'xp' in tags))
    print(f"{k:>3} {statistics.median([x[0] for x in R]):8.1f} {100*statistics.mean([x[1] for x in R]):13.1f} "
          f"{100*statistics.mean([x[2] for x in R]):13.1f} {100*statistics.mean([x[3] for x in R]):8.1f} {100*statistics.mean([x[4] for x in R]):12.1f}")

print("\n### B) sensitivity: base alignment assumption (64-bit, all dlls)")
refs64=build([("w7",w7)],64)
for gran,lab in [(0x10000,"64KB (Windows image ASLR)"),(0x1000,"4KB (page-only)")]:
    out=[]
    for k in [2,3,4]:
        R=[]
        for _ in range(150):
            kk=random.choice(list(refs64)); r=refs64[kk]
            if len(r['rvaset'])<k: continue
            rvas=random.sample(sorted(r['rvaset']),k)
            B=random.randrange(0x10000000,0x7FF00000000,gran)
            V=[B+x for x in rvas]
            h=solve(refs64,V,gran)
            dn={refs64[hk]['name'] for hk,_ in h}
            R.append((len(h),len(dn)==1))
        out.append(f"k={k}: med#hyp={statistics.median([x[0] for x in R]):.0f} uniqDLL={100*statistics.mean([x[1] for x in R]):.0f}%")
    print(f"  {lab:30s} " + "  ".join(out))

print("\n### C) robustness: noisy 'custom IAT' run (64-bit, k=12 true + outliers), RANSAC")
allrv=[(kk,rv) for kk,r in refs64.items() for rv in r['rvaset']]
print(f"{'outliers':>9} {'minsup':>7} {'recall%':>8} {'precision%':>11} {'wrongDLL%':>10}")
for nout in [0,4,12,24]:
    for minsup in [4,6]:
        rec=[];prec=[];wr=[]
        for _ in range(60):
            kk=random.choice([k for k,r in refs64.items() if len(r['rvaset'])>=12]); r=refs64[kk]
            rvas=random.sample(sorted(r['rvaset']),12)
            B=random.randrange(0x10000000,0x7FF00000000,0x10000)
            V=[B+x for x in rvas]
            for _ in range(nout):
                ok,orv=random.choice(allrv)
                V.append(random.randrange(0x10000000,0x7FF00000000,0x10000)+orv)
            random.shuffle(V)
            hy=ransac(refs64,V,minsup)
            if not hy: rec.append(0);prec.append(0);wr.append(0);continue
            (bk,bb),sup=max(hy.items(),key=lambda x:x[1])
            hit={v for v in V if (v-B) in r['rvaset'] and v-B in [x for x in rvas]}
            resolved={v for v in V if (v-bb) in refs64[bk]['rvaset']}
            true=set(V[:0])|set(B+x for x in rvas)
            rec.append(len(resolved&true)/12); prec.append(len(resolved&true)/max(1,len(resolved)))
            wr.append(refs64[bk]['name']!=r['name'])
        print(f"{nout:>9} {minsup:>7} {100*statistics.mean(rec):8.1f} {100*statistics.mean(prec):11.1f} {100*statistics.mean(wr):10.1f}")
