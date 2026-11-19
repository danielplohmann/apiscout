"""Collect export tables of Windows DLL builds: Winbindex index -> MS symbol server -> exports JSON.

Binaries are only parsed for their export directory (stdlib, no loading) and deleted after.
usage: fetch_exports.py OUTDIR BINDIR dll [dll ...] [--workers N]
"""
import argparse, concurrent.futures as cf, gzip, hashlib, json, os, struct, sys, urllib.request

MODERN = {"22H2", "11-22H2", "11-23H2", "11-24H2", "11-25H2", "11-26H1"}
UA = {"User-Agent": "Microsoft-Symbol-Server/10.0.0.0"}

def pe_exports(data):
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[lfanew:lfanew + 4] == b"PE\0\0"
    machine, nsec = struct.unpack_from("<HH", data, lfanew + 4)
    optsize = struct.unpack_from("<H", data, lfanew + 20)[0]
    opt = lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (96 if magic == 0x10B else 112)
    exp_rva, exp_size = struct.unpack_from("<II", data, dd)
    secs = []
    for i in range(nsec):
        s = opt + optsize + 40 * i
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        secs.append((va, max(vsize, rsize), raw))
    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return rva - va + raw
        raise ValueError(hex(rva))
    def cstr(rva):
        o = off(rva)
        return data[o:data.index(b"\0", o)].decode("latin1")
    e = off(exp_rva)
    base, nfun, nnames, afun, anames, aords = struct.unpack_from("<IIIIII", data, e + 16)
    funcs = struct.unpack_from("<%dI" % nfun, data, off(afun))
    names = struct.unpack_from("<%dI" % nnames, data, off(anames)) if nnames else ()
    ords = struct.unpack_from("<%dH" % nnames, data, off(aords)) if nnames else ()
    exports, forwards, named_idx = {}, {}, set()
    for n, o in zip(names, ords):
        rva = funcs[o]
        name = cstr(n)
        named_idx.add(o)
        if exp_rva <= rva < exp_rva + exp_size:
            forwards[name] = cstr(rva)
        elif rva:
            exports[name] = rva
    ordinal_only = sorted(funcs[i] for i in range(nfun) if i not in named_idx and funcs[i] and not exp_rva <= funcs[i] < exp_rva + exp_size)
    return machine, exports, forwards, ordinal_only

def select(index):
    """every file seen in a modern release, and the first and last file of each older release"""
    chosen = {}
    by_rel = {}
    for sha, v in index.items():
        fi = v.get("fileInfo", {})
        if fi.get("machineType") not in (332, 34404) or "timestamp" not in fi or "virtualSize" not in fi:
            continue
        for rel, kbs in v.get("windowsVersions", {}).items():
            dates = [kb.get("updateInfo", {}).get("releaseDate") for kb in kbs.values() if isinstance(kb, dict)]
            dates = [d for d in dates if d]
            date = min(dates) if dates else None
            if rel in MODERN:
                chosen[sha] = v
            elif date:
                by_rel.setdefault((rel, fi["machineType"]), []).append((date, sha))
    for items in by_rel.values():
        items.sort()
        for _, sha in (items[0], items[-1]):
            chosen[sha] = index[sha]
    return chosen

def first_seen(v):
    out = []
    for rel, kbs in v.get("windowsVersions", {}).items():
        for kb in kbs.values():
            if isinstance(kb, dict) and kb.get("updateInfo", {}).get("releaseDate"):
                out.append((kb["updateInfo"]["releaseDate"], rel))
    return min(out) if out else (None, sorted(v.get("windowsVersions", {}))[0])

def fetch(dll, sha, v, outdir, bindir):
    fi = v["fileInfo"]
    arch = "x64" if fi["machineType"] == 34404 else "x86"
    out = os.path.join(outdir, f"{dll}_{arch}_{sha[:12]}.json")
    if os.path.exists(out):
        return "cached"
    key = "%08X%x" % (fi["timestamp"], fi["virtualSize"])
    url = f"https://msdl.microsoft.com/download/symbols/{dll}/{key}/{dll}"
    data = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120).read()
    sha_ok = hashlib.sha256(data).hexdigest() == sha
    if not sha_ok:
        # the server can hold another copy of the same build (same TimeDateStamp and SizeOfImage, which make up
        # the key); accept it only if the PE header carries exactly that key
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        ts = struct.unpack_from("<I", data, lfanew + 8)[0]
        soi = struct.unpack_from("<I", data, lfanew + 24 + 56)[0]
        if (ts, soi) != (fi["timestamp"], fi["virtualSize"]):
            return "key mismatch"
    machine, exports, forwards, ordinal_only = pe_exports(data)
    date, rel = first_seen(v)
    json.dump(dict(dll=dll, arch=arch, sha256=sha, sha_ok=sha_ok, version=fi.get("version", "").split(" ")[0], release=rel,
                   first_seen=date, releases=sorted(v.get("windowsVersions", {})), exports=exports,
                   forwards=forwards, ordinal_only=ordinal_only), open(out, "w"))
    return "ok" if sha_ok else "ok, other copy"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir"); ap.add_argument("bindir"); ap.add_argument("dlls", nargs="+")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    for dll in a.dlls:
        idx_path = os.path.join(a.bindir, dll + ".json.gz")
        if not os.path.exists(idx_path):
            req = urllib.request.Request(f"https://winbindex.m417z.com/data/by_filename_compressed/{dll}.json.gz",
                                         headers={"User-Agent": "Mozilla/5.0"})
            open(idx_path, "wb").write(urllib.request.urlopen(req, timeout=120).read())
        chosen = select(json.load(gzip.open(idx_path)))
        res = {}
        with cf.ThreadPoolExecutor(a.workers) as ex:
            futs = {ex.submit(fetch, dll, sha, v, a.outdir, a.bindir): sha for sha, v in chosen.items()}
            for f in cf.as_completed(futs):
                try:
                    r = f.result()
                except Exception as exc:  # noqa: BLE001
                    r = "error " + type(exc).__name__
                res[r] = res.get(r, 0) + 1
        print(dll, len(chosen), res, flush=True)

if __name__ == "__main__":
    sys.exit(main())
