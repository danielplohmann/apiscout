"""Corpus evaluation of the blind relative-IAT solver (issue #65, open item "real dumps").

Per dump:
  classic  - apiscout as today: one scan per shipped DB at the DB's own DLL bases, hits with confidence >= 20.
             The DB with the most hits is the ground truth ("truth DB"); its tag is the dump's build as far as the
             shipped DBs can tell.
  blind    - blind_solve over all five DBs, 32 and 64 bit, no bases, no module list.
  blind_lo - the same with the truth build left out of the reference set.

usage: corpus_eval.py OUT.jsonl INVENTORY [INVENTORY ...] [--workers N] [--max-mb N] [--minratio R] [--minadj A]
Dumps are read only as bytes and never executed. Identical contents are evaluated once.
"""
import argparse
import collections
import hashlib
import json
import multiprocessing
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blind_solve  # noqa: E402

DBDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "dbs")
TAGS = [t for t, _ in blind_solve.DBS]
G = {}


def init(minratio, minadj):
    from apiscout.ApiScout import ApiScout

    G["scouts"] = {}
    for tag, fname in blind_solve.DBS:
        s = ApiScout()
        s.loadDbFile(os.path.join(DBDIR, fname))
        G["scouts"][tag] = s
    G["refs"] = {}
    for bits in (32, 64):
        G["refs"][(bits, None)] = blind_solve.load_refs(DBDIR, bits, set())
        for tag in TAGS:
            G["refs"][(bits, tag)] = blind_solve.load_refs(DBDIR, bits, {tag})
    G["minratio"], G["minadj"] = minratio, minadj


def classic(binary, base):
    out = {}
    for tag, scout in G["scouts"].items():
        scout.setBaseAddress(base)
        res = scout.crawl(binary)
        res = scout.filterByConfidence(res, 20, scout.getConfidences(res))
        hits = {}
        for entries in res.values():
            for e in entries:
                # offset, api address, dll, api, bitness
                hits[(e[0], e[4])] = (e[2].split("(")[0].lower().rsplit("_0x", 1)[0], e[3])
        out[tag] = hits
    return out


def blind_groups(binary, truth, exclude_tag=None):
    """every accepted hypothesis of both bitnesses as a group with its stats and its agreement with the truth"""
    import struct

    groups = []
    for bits in (32, 64):
        refs, low = G["refs"][(bits, exclude_tag)]
        size = bits // 8
        n = len(binary) // size
        vals = struct.unpack_from("<%d%s" % (n, "I" if bits == 32 else "Q"), binary[: n * size])
        offsets = collections.defaultdict(list)
        for i, v in enumerate(vals):
            offsets[v].append(i * size)
        assign, used, _ = blind_solve.solve(offsets.keys(), refs, low, 3, bits, G["minratio"])
        hits = collections.defaultdict(list)
        for v, (i, b) in assign.items():
            for off in offsets[v]:
                hits[(i, b)].append((off, v))
        all_offs = {off for hs in hits.values() for off, _ in hs}
        for i, b, sup, ratio in used:
            ref = refs[i]
            hs = hits[(i, b)]
            adj = sum(1 for o, _ in hs if any(o + d * size in all_offs for d in (-2, -1, 1, 2))) / len(hs)
            ok_dll = ok_name = 0
            for o, v in hs:
                t = truth.get((o, bits))
                if t and t[0] == ref["name"]:
                    ok_dll += 1
                    ok_name += t[1] in ref["by_rva"][v - b]
            groups.append(dict(bits=bits, tag=ref["tag"], dll=ref["name"], base=hex(b), support=sup,
                               ratio=ratio, adj=round(adj, 2), hits=len(hs), ok_dll=ok_dll, ok_name=ok_name,
                               offs=sorted(o for o, _ in hs)))
    return groups


def evaluate(item):
    path, corpus = item
    t0 = time.time()
    try:
        binary = open(path, "rb").read()
        name = os.path.basename(path)
        m = re.search(r"_dump(\d*)_0x([0-9a-fA-F]+)", name)
        base = int(m.group(2), 16) if m else 0
        rec = dict(path=path, corpus=corpus, size=len(binary), kind="dump" + (m.group(1) if m else "?"), base=hex(base),
                   mz=binary[:2] == b"MZ")
        cl = classic(binary, base)
        rec["classic_counts"] = {t: len(h) for t, h in cl.items()}
        truth_tag = max(TAGS, key=lambda t: len(cl[t]))
        truth = cl[truth_tag] if cl[truth_tag] else {}
        rec["truth_tag"] = truth_tag if truth else None
        rec["truth_n"] = len(truth)
        rec["truth_dlls"] = dict(collections.Counter(d for d, _ in truth.values()))
        rec["truth_offs"] = sorted("%d/%d" % k for k in truth)
        rec["groups"] = blind_groups(binary, truth)
        if truth:
            rec["groups_lo"] = blind_groups(binary, truth, exclude_tag=truth_tag)
        rec["seconds"] = round(time.time() - t0, 2)
    except Exception as exc:  # noqa: BLE001
        rec = dict(path=path, corpus=corpus, error=repr(exc))
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("inventories", nargs="+")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--max-mb", type=float, default=20)
    ap.add_argument("--minratio", type=float, default=0.3)
    ap.add_argument("--minadj", type=float, default=0.5)
    a = ap.parse_args()
    items, seen, skipped = [], set(), collections.Counter()
    for inv in a.inventories:
        corpus = "malpedia" if "malpedia" in inv else "cases"
        for line in open(inv):
            p = line.strip()
            if not p:
                continue
            try:
                size = os.path.getsize(p)
            except OSError:
                skipped["unreadable"] += 1
                continue
            if size > a.max_mb * 1e6:
                skipped["too large"] += 1
                continue
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            if h in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(h)
            items.append((p, corpus))
    print(f"{len(items)} dumps, skipped {dict(skipped)}", flush=True)
    done = 0
    with open(a.out, "w") as out, multiprocessing.Pool(a.workers, init, (a.minratio, a.minadj)) as pool:
        for rec in pool.imap_unordered(evaluate, items, chunksize=4):
            out.write(json.dumps(rec) + "\n")
            done += 1
            if done % 200 == 0:
                print(f"{done}/{len(items)}", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    main()
