"""G) delta-index: indexability + how much the absolute low-16 bits still add.
   H) build discrimination on REAL same-DLL-different-build pairs."""
import json, collections, random, statistics, itertools
random.seed(99)
DBS={t:json.load(open(f'dbs/{f}')) for t,f in
     [('w7','win7_prof-n_sp1_example.json'),('xp','winxp_prof_sp3_example.json')]}
def mods(tag,bitness):
    out={}
    for kk,v in DBS[tag]['dlls'].items():
        if v['bitness']!=bitness or not v['exports']: continue
        byrva=collections.defaultdict(set)
        for e in v['exports']: byrva[e['address']].add(e['name'])
        byname={}
        for e in v['exports']: byname.setdefault(e['name'],e['address'])
        out[tag+'|'+kk]=dict(name=kk.split('_')[2].lower(),ver=kk.split('_')[1],
            byrva=byrva,rvaset=set(byrva),byname=byname,
            byres=collections.defaultdict(list))
        for r in byrva: out[tag+'|'+kk]['byres'][r&0xFFFF].append(r)
    return out
R64=mods('w7',64)

# ================= G) delta index =================
print("### G) pairwise-delta index over 64-bit Win7 DLLs")
COMMON={'kernel32.dll','user32.dll','advapi32.dll','ntdll.dll','msvcrt.dll','ws2_32.dll',
        'shell32.dll','ole32.dll','oleaut32.dll','shlwapi.dll','wininet.dll','crypt32.dll','gdi32.dll'}
sub={k:r for k,r in R64.items() if r['name'] in COMMON}
didx=collections.defaultdict(list)
for k,r in sub.items():
    rv=sorted(r['rvaset'])
    for i in range(len(rv)):
        for j in range(i+1,len(rv)):
            didx[rv[j]-rv[i]].append((k,rv[i]))
print(f"  {len(sub)} DLLs, {sum(len(r['rvaset']) for r in sub.values())} rva-slots -> {sum(len(v) for v in didx.values())} indexed deltas, {len(didx)} distinct")
cnt=[len(v) for v in didx.values()]
print(f"  candidates per delta lookup: median={statistics.median(cnt):.0f} mean={statistics.mean(cnt):.1f} p95={sorted(cnt)[int(.95*len(cnt))]} max={max(cnt)}")
# how selective is ONE delta vs. delta+low16 of the anchor?
tot_d=[];tot_dr=[]
for _ in range(400):
    k=random.choice(list(sub)); r=sub[k]
    a,b=random.sample(sorted(r['rvaset']),2); a,b=min(a,b),max(a,b)
    cands=didx[b-a]
    tot_d.append(len(cands))
    tot_dr.append(sum(1 for kk,rv in cands if rv&0xFFFF==a&0xFFFF))
print(f"  one observed pair: delta-only candidates median={statistics.median(tot_d):.0f} mean={statistics.mean(tot_d):.1f}")
print(f"                     + low-16 filter  median={statistics.median(tot_dr):.0f} mean={statistics.mean(tot_dr):.1f}"
      f"  -> extra pruning x{statistics.mean(tot_d)/max(1e-9,statistics.mean(tot_dr)):.1f}")

# ================= H) real build-to-build discrimination =================
print("\n### H) same DLL, different real builds")
groups=collections.defaultdict(list)
for tag in DBS:
    for bit in (32,64):
        for k,r in mods(tag,bit).items():
            groups[(bit,r['name'])].append((tag,r))
pairs=[]
for (bit,nm),lst in groups.items():
    for (t1,r1),(t2,r2) in itertools.combinations(lst,2):
        if r1['ver']==r2['ver'] and t1==t2: continue
        pairs.append((bit,nm,t1,r1,t2,r2))
def fits(r,V):
    v0=V[0]; out=[]
    for rva in r['byres'][v0&0xFFFF]:
        B=v0-rva
        if B&0xFFFF: continue
        if all((v-B) in r['rvaset'] for v in V[1:]): out.append(B)
    return out
print(f"{'DLL':16} {'bit':>3} {'buildA':>15} {'buildB':>15} {'common':>7} {'sameRVA':>8} {'same%64k':>9} | k=4 B-fits  nameOK")
rows=[]
for bit,nm,t1,r1,t2,r2 in sorted(pairs,key=lambda x:x[1]):
    common=set(r1['byname'])&set(r2['byname'])
    if len(common)<50: continue
    same=sum(1 for n in common if r1['byname'][n]==r2['byname'][n])
    samer=sum(1 for n in common if (r1['byname'][n]&0xFFFF)==(r2['byname'][n]&0xFFFF))
    fit=0; nameok=0; trials=200
    for _ in range(trials):
        rvas=random.sample(sorted(r1['rvaset']),4)
        B=random.randrange(0x10000000,0x70000000,0x10000)
        V=[B+x for x in rvas]
        bs=fits(r2,V)
        if bs:
            fit+=1
            n1=r1['byrva'][rvas[0]]; n2=set()
            for b in bs: n2|=r2['byrva'][V[0]-b]
            if n1&n2: nameok+=1
    rows.append((nm,bit,t1+':'+r1['ver'],t2+':'+r2['ver'],len(common),100*same/len(common),100*samer/len(common),100*fit/trials,(100*nameok/fit if fit else float('nan'))))
for x in rows:
    print(f"{x[0]:16} {x[1]:>3} {x[2]:>15} {x[3]:>15} {x[4]:>7} {x[5]:7.1f}% {x[6]:8.1f}% | {x[7]:8.1f}%  {x[8]:5.1f}%")

# discrimination curve: how many slots to tell buildA from buildB
print("\n### H2) slots needed to rule out the wrong build (real build pairs)")
print(f"{'DLL':16} {'pair':>28} " + " ".join(f"k={k:<2}" for k in [1,2,3,4,6,8]))
for bit,nm,t1,r1,t2,r2 in sorted(pairs,key=lambda x:x[1]):
    common=set(r1['byname'])&set(r2['byname'])
    if len(common)<200: continue
    line=[]
    for k in [1,2,3,4,6,8]:
        ruled=0
        for _ in range(150):
            rvas=random.sample(sorted(r1['rvaset']),k)
            B=random.randrange(0x10000000,0x70000000,0x10000)
            if not fits(r2,[B+x for x in rvas]): ruled+=1
        line.append(f"{100*ruled/150:4.0f}%")
    print(f"{nm:16} {t1+':'+r1['ver']+' vs '+t2+':'+r2['ver']:>28} " + " ".join(line))
