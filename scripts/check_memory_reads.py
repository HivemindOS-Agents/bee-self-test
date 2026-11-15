#!/usr/bin/env python3
"""Answer or abstain at read time (the 15 Nov proposal bundle, Part 2): the eight acceptance fixtures, run in both
directions. A wrong CURRENT and a needless ABSTAIN both fail; the run prints both counts and exits 1 unless both are 0.

The rule's one home is HivemindOS's shared core (core/agent-memory-read.ts agentMemoryVerdict), which the agents
service runs before a recalled value may steer a step. This is its second copy, for anyone to run without HivemindOS:
the fixtures are the same bytes as the core's tests/agent-memory-read-fixtures.json, pinned below and there by sha256,
and both copies must pass them, so the two cannot drift without one failing.

  check_memory_reads.py fixtures/memory-read/fixtures.json

Only reads the file. No network."""
import hashlib, json, sys

FIXTURES_SHA256 = "df6bd1280785c8455171db27f9858336a4399eb7e28be3741affe4096c3dcaf5"

def ref(r):
    return f"{r['id']}@{r['version']}"

def same(a, b):
    norm = lambda v: v.strip().lower() if isinstance(v, str) else v
    return json.dumps(norm(a), sort_keys=True) == json.dumps(norm(b), sort_keys=True)

def abstain(reason, r):
    return {"verdict": "ABSTAIN", "reason": reason, "record": ref(r) if r else None}

def verdict(query, records):
    on = [r for r in records if r["claim"] == query["claim"]]
    if not on:
        return abstain("weak-hit", None)
    live = [r for r in on if r["status"] != "retired"]
    superseded = {r["supersedes"] for r in live if r.get("supersedes")}
    d = query.get("asOfDate")
    if isinstance(d, (int, float)):
        picked = [r for r in live if r["asOf"] <= d and (r["validTo"] is None or d < r["validTo"])]
    else:
        picked = [r for r in live if ref(r) not in superseded and r["validTo"] is None]
    if not picked:
        if not isinstance(d, (int, float)) and live:
            return abstain("superseded-read", live[-1])
        return abstain("weak-hit" if live else "source-not-match", on[-1])
    distinct = [r for i, r in enumerate(picked) if next(j for j, o in enumerate(picked) if same(o["value"], r["value"])) == i]
    if len(distinct) > 1:
        return abstain("conflict", picked[-1])
    r = picked[-1]
    if r["label"] == "UNKNOWN":
        return abstain("unknown-label", r)
    if r["status"] in ("changed", "unverifiable") or any(c["result"] != "MATCH" for c in r["checks"]):
        return abstain("source-not-match", r)
    if not r["citations"]:
        return abstain("no-citation", r)
    if r.get("weak"):
        return abstain("weak-hit", r)
    return {"verdict": "CURRENT", "reason": None, "record": ref(r)}

def main(path):
    raw = open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != FIXTURES_SHA256:
        print(f"fixtures are not the pinned file: {digest}")
        return 1
    wrong_current = needless_abstain = failed = 0
    for f in json.loads(raw)["fixtures"]:
        got, want = verdict(f["query"], f["records"]), f["expect"]
        ok = got["verdict"] == want["verdict"] and (not want.get("reason") or got["reason"] == want["reason"]) and (not want.get("record") or got["record"] == want["record"])
        if got["verdict"] == "CURRENT" and want["verdict"] == "ABSTAIN":
            wrong_current += 1
        if got["verdict"] == "ABSTAIN" and want["verdict"] == "CURRENT":
            needless_abstain += 1
        print(f"{'ok  ' if ok else 'FAIL'} {f['name']}: {got['verdict']}{' / ' + got['reason'] if got['reason'] else ''} {got['record'] or ''}")
        # A CURRENT on the wrong version is a wrong CURRENT; an ABSTAIN for the wrong reason still fails.
        if not ok and got["verdict"] == want["verdict"] == "CURRENT":
            wrong_current += 1
        failed += 0 if ok else 1
    print(json.dumps({"wrongCurrent": wrong_current, "needlessAbstain": needless_abstain}))
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/memory-read/fixtures.json"))
