import json, collections, random, statistics, os
random.seed(11)
w7=json.load(open('dbs/win7_prof-n_sp1_example.json'))
refs={}
for kk,v in w7['dlls'].items():
    if v['bitness']!=64: continue
    byrva=collections.defaultdict(set)
    for e in v['exports']: byrva[e['address']].add(e['name'])
    byres=collections.defaultdict(list)
    for r in byrva: byres[r&0xFFFF].append(r)
    refs[kk]=dict(name=kk.split('_')[2].lower(),byrva=byrva,rvaset=set(byrva),byres=byres)

# ---- D) ApiVector-relevance of RVA aliasing ----
p='apiscout/data/winapi1024v1.txt'
if os.path.exists(p):
    vec=[l.strip() for l in open(p) if l.strip() and not l.startswith('#')]
    print("winapi1024 entries:",len(vec), vec[:3])
    vnames=set()
    for l in vec:
        parts=l.replace(';','!').split('!')
        vnames.add(parts[-2])
    amb_pairs=0; amb_apis=set(); grp_ex=[]
    for kk,r in refs.items():
        for rva,names in r['byrva'].items():
            inv=names & vnames
            if len(names)>1 and inv:
                if len(inv)>1:
                    amb_pairs+=1; amb_apis|=inv; grp_ex.append((r['name'],sorted(names)))
                else:
                    amb_apis|=inv  # ambiguous but only one vector API in group -> resolvable by prior
    print(f"vector APIs sitting in a multi-name RVA group: {len(amb_apis)}")
    print(f"RVA groups containing >=2 DIFFERENT vector APIs (truly harmful): {amb_pairs}")
    for n,g in grp_ex[:10]: print("   ",n,g[:6])

# ---- E) null test: spurious hypotheses from random pointer-sized noise ----
def ransac(V,minsup):
    out={}
    Vs=set(V)
    for v0 in V:
        for kk,r in refs.items():
            for rva in r['byres'][v0&0xFFFF]:
                B=v0-rva
                if B<=0 or (B&0xFFFF): continue
                if (kk,B) in out: continue
                s=sum(1 for v in Vs if (v-B) in r['rvaset'])
                if s>=minsup: out[(kk,B)]=s
    return out
print("\n### null test: N random 64KB-aligned-noise values, spurious (dll,base) hypotheses")
for N in [100,300]:
    V=[random.randrange(0x10000000,0x7FF00000000,0x10000)+random.randrange(0,0x200000) for _ in range(N)]
    h=ransac(V,3)
    hist=collections.Counter(h.values())
    print(f"  N={N}: hypotheses with support>=3: {len(h)}  support hist {dict(sorted(hist.items()))}")
