"""F) Can we recover same-DLL groupings without zero dividers?
   Realistic ASLR base layouts: 'packed' (Windows fills its image bitmap tightly)
   vs 'scattered'. Compares gap-splitting, MSB-mask bucketing, and no clustering."""
import json, collections, random, statistics
random.seed(4242)
w7=json.load(open('dbs/win7_prof-n_sp1_example.json'))
refs={}
for kk,v in w7['dlls'].items():
    if v['bitness']!=64 or not v['exports']: continue
    byrva=collections.defaultdict(set)
    for e in v['exports']: byrva[e['address']].add(e['name'])
    refs[kk]=dict(name=kk.split('_')[2].lower(),byrva=byrva,rvaset=set(byrva),
                  size=(max(byrva)+0xFFFF)&~0xFFFF,
                  byres=collections.defaultdict(list))
    for r in byrva: refs[kk]['byres'][r&0xFFFF].append(r)
NAMES=['kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','ws2_32.dll','shell32.dll',
       'ole32.dll','shlwapi.dll','crypt32.dll','wininet.dll','gdi32.dll','psapi.dll']
pool=[k for k,r in refs.items() if r['name'] in NAMES]
print("module sizes (MB):", {refs[k]['name']:round(refs[k]['size']/2**20,2) for k in pool})

def layout(keys, regime):
    bases={}
    if regime=='packed':
        cur=0x7FF800000000
        for k in keys:
            bases[k]=cur
            cur += (refs[k]['size'] + random.choice([0,0,0x10000,0x100000,0x400000])) & ~0xFFFF
    else:
        for k in keys:
            bases[k]=random.randrange(0x7FF800000000,0x7FFFF0000000,0x10000)
    return bases

def make_case(regime, nmod=8):
    keys=random.sample(pool,nmod)
    bases=layout(keys,regime)
    truth={}; V=[]
    for k in keys:
        n=random.choice([1,2,3,4,5,6,8,10,15,25])
        for rva in random.sample(sorted(refs[k]['rvaset']),min(n,len(refs[k]['rvaset']))):
            v=bases[k]+rva; V.append(v); truth[v]=k
    random.shuffle(V)
    return V, truth

def purity(clusters, truth):
    tot=sum(len(c) for c in clusters); good=0
    for c in clusters:
        cnt=collections.Counter(truth[v] for v in c); good+=cnt.most_common(1)[0][1]
    pure=sum(1 for c in clusters if len({truth[v] for v in c})==1)
    mods=collections.defaultdict(set)
    for i,c in enumerate(clusters):
        for v in c: mods[truth[v]].add(i)
    intact=sum(1 for m,s in mods.items() if len(s)==1)/len(mods)
    return good/tot, pure/len(clusters), intact

def gap_split(V,T):
    S=sorted(V); out=[[S[0]]]
    for a,b in zip(S,S[1:]):
        if b-a>T: out.append([])
        out[-1].append(b)
    return out
def mask_bucket(V,shift):
    g=collections.defaultdict(list)
    for v in V: g[v>>shift].append(v)
    return list(g.values())

print(f"\n{'regime':9} {'method':22} {'purity':>7} {'pureClusters':>13} {'modulesIntact':>14}")
for regime in ['packed','scattered']:
    cases=[make_case(regime) for _ in range(60)]
    rows=[('gap-split T=1MB',lambda V:gap_split(V,1<<20)),
          ('gap-split T=16MB',lambda V:gap_split(V,16<<20)),
          ('gap-split T=64MB',lambda V:gap_split(V,64<<20)),
          ('MSB mask >>24 (16MB)',lambda V:mask_bucket(V,24)),
          ('MSB mask >>26 (64MB)',lambda V:mask_bucket(V,26)),
          ('MSB mask >>28 (256MB)',lambda V:mask_bucket(V,28))]
    for lab,fn in rows:
        M=[purity(fn(V),t) for V,t in cases]
        print(f"{regime:9} {lab:22} {100*statistics.mean(x[0] for x in M):6.1f}% "
              f"{100*statistics.mean(x[1] for x in M):12.1f}% {100*statistics.mean(x[2] for x in M):13.1f}%")

# ---- no clustering at all: global RANSAC over the raw value set ----
def global_solve(V,minsup=3):
    Vs=set(V); hyp={}
    for v0 in V:
        for kk,r in refs.items():
            for rva in r['byres'][v0&0xFFFF]:
                B=v0-rva
                if B<=0 or (B&0xFFFF) or (kk,B) in hyp: continue
                s=sum(1 for v in Vs if (v-B) in r['rvaset'])
                if s>=minsup: hyp[(kk,B)]=s
    assign={}
    for (kk,B),s in sorted(hyp.items(),key=lambda x:-x[1]):
        for v in V:
            if v not in assign and (v-B) in refs[kk]['rvaset']: assign[v]=(kk,B,s)
    return assign,hyp
print("\n### no clustering: global support>=3 sweep over the raw value set")
for regime in ['packed','scattered']:
    acc=[];cov=[];nh=[]
    for _ in range(20):
        V,truth=make_case(regime)
        a,h=global_solve(V)
        nh.append(len(h)); cov.append(len(a)/len(V))
        ok=sum(1 for v,(kk,B,s) in a.items() if refs[kk]['name']==refs[truth[v]]['name'])
        acc.append(ok/max(1,len(a)))
    print(f"  {regime:10} coverage={100*statistics.mean(cov):5.1f}%  DLL-correct={100*statistics.mean(acc):5.1f}%  #hypotheses={statistics.mean(nh):.1f}")
