#!/usr/bin/env python3
"""HB-061's kept-rule bar and its three-round stop (20 Nov 2026 update, Part 6; 21 Nov update, Part 4).

A gotcha is what one site did in reply to one request in one run. The host makes it a KEPT RULE only when:
  1. it was seen in at least two separate runs;
  2. one mechanical detector matches every sighting: the same request (site, method, path) got the same status;
  3. an agent with a different holder made the same request and got the same answer (the disproof attempt failed).
A later run in which the same request went through REJECTS it, with that run as its counterexample. The host decides
this in code and writes the result under "## Kept rules" in each agent's LESSONS.md, every claim with a link to a
judgement file (work/<step>.judgement.json#<trace item>) in the repository of the agent that ran it.

This reads those public files and checks each line against the judgement files it cites. Keyless and read-only.

    python3 scripts/kept_rules.py --self-test       # the fixtures only, no network
    python3 scripts/kept_rules.py DIR...            # clones of hivepunk-<n> (LESSONS.md and repairs/ are read; the
                                                    # judgement files a line cites are fetched from raw.githubusercontent)

A "Kept" line must: cite at least two runs (two judgement files); have every cited trace item be that request with
that status; and name a confirming agent other than the one whose file it is, whose own cited item is that request
with that status. A "Rejected" line must cite an item that is that request with a status from 200 to 399.
Whether two agents have different holders is the chain's to say and is not read here: a line is flagged only when the
confirming agent is the same agent.

An honest-failure row (repairs/<repair-id>--e<k>.honest-failure.json) must: say `verified_by: none`; list at least 3
rounds, each with a run and a cause; and carry the sha256 of its own JSON without that field. A row whose rounds were
all funds refusals or all host limits (labels.py) is not counted as an honest failure and is said on its own line.

Exit 0 when nothing is wrong, 1 when something is, 2 when a file could not be read.
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labels  # noqa: E402

RUNS = 2
ROUNDS = 3
HEADING = "## Kept rules"
KEPT = re.compile(r"^- Kept: (?P<host>\S+) (?P<method>[A-Z]+) (?P<path>\S+) → (?P<status>\d{3}) · seen in (?P<n>\d+) runs \((?P<runs>[^)]*)\) · the same answer for (?P<tried>.+)$")
REJECTED = re.compile(r"^- Rejected: (?P<host>\S+) (?P<method>[A-Z]+) (?P<path>\S+) → (?P<status>\d{3}) · disproved by (?P<by>.+?): the same request answered (?P<got>\d{3})(?: \((?P<link>\S+)\))?$")
LINK = re.compile(r"https://github\.com/(?P<org>[A-Za-z0-9_.-]+)/hivepunk-(?P<agent>\d+)/blob/main/(?P<file>work/[^#\s)]+\.judgement\.json)#(?P<item>[A-Za-z0-9_.:-]+)")


def decide(c):
    """The bar, as the host's core/agent-kept-rule.ts agentKeptDecide has it. c: {detector, proposer{agent, owner},
    firstAt, sightings[{step, host, method, path, status}], attempts[{agent, owner, at, status, disproved}]}."""
    disproved = sorted((a for a in c["attempts"] if a["disproved"] and a["at"] > c["firstAt"]), key=lambda a: a["at"])
    if disproved:
        return "rejected", f"the same request answered {disproved[0]['status']}"
    runs = len({s["step"] for s in c["sightings"]})
    if runs < RUNS:
        return "candidate", f"seen in {runs} separate run(s); it needs {RUNS}"
    d = c.get("detector")
    if not d:
        return "candidate", "no mechanical detector"
    if any((s["host"], s["method"], s["path"], s["status"]) != (d["host"], d["method"], d["path"], d["status"]) for s in c["sightings"]):
        return "candidate", "its detector misses a sighting"
    owner = (c["proposer"].get("owner") or "").lower() or None
    others = [a for a in c["attempts"] if not a["disproved"] and owner and (a.get("owner") or "").lower() not in ("", owner)]
    if not others:
        return "candidate", "no agent with a different holder has made the same request yet"
    return "kept", "kept"


def links(text):
    return [m.groupdict() for m in LINK.finditer(text)]


def item_of(judgement, item):
    return next((t for t in (judgement or {}).get("trace") or [] if t.get("id") == item), None)


def same_request(t, host, method, path):
    return t is not None and str(t.get("host", "")).lower() == host.lower() and str(t.get("method", "GET")).upper() == method and t.get("path") == path


def kept_line_problems(line, agent, fetch):
    """What is wrong with one line of an agent's Kept rules section. fetch(org, agent, file) -> judgement or None."""
    m = KEPT.match(line)
    if m:
        host, method, path, status = m["host"], m["method"], m["path"], int(m["status"])
        p, runs = [], links(m["runs"])
        if len({r["file"] for r in runs}) < RUNS:
            p.append(f"cites {len({r['file'] for r in runs})} run(s); a kept rule needs {RUNS}")
        for r in runs:
            t = item_of(fetch(r["org"], r["agent"], r["file"]), r["item"])
            if not same_request(t, host, method, path) or t.get("status") != status:
                p.append(f"its detector misses {r['file']}#{r['item']} ({'no such item' if t is None else t.get('status')})")
        tried = links(m["tried"])
        others = [t for t in tried if t["agent"] != agent]
        if not others:
            p.append("no other agent is named as having made the same request")
        for r in others:
            t = item_of(fetch(r["org"], r["agent"], r["file"]), r["item"])
            if not same_request(t, host, method, path) or t.get("status") != status:
                p.append(f"HivePunk {r['agent']}'s item is not the same request with the same answer ({r['file']}#{r['item']})")
        return p
    m = REJECTED.match(line)
    if m:
        if not m["link"]:
            return ["a rejected rule cites no counterexample"]
        r = links(m["link"])
        t = item_of(fetch(r[0]["org"], r[0]["agent"], r[0]["file"]), r[0]["item"]) if r else None
        if not same_request(t, m["host"], m["method"], m["path"]) or not (200 <= (t.get("status") or 0) < 400):
            return [f"its counterexample is not the same request going through ({m['link']})"]
        return []
    return ["a line under Kept rules that is neither Kept nor Rejected"] if line.startswith("- ") else []


def kept_section(text):
    start = text.find(HEADING)
    if start < 0:
        return []
    end = text.find("\n## ", start + len(HEADING))
    return [l.strip() for l in text[start:end if end > 0 else len(text)].splitlines() if l.startswith("- ")]


def honest_failure_problems(row):
    p = []
    if row.get("kind") != "honest-failure":
        p.append("not an honest-failure row")
    if row.get("verified_by") != "none":
        p.append("verified_by is not none")
    rounds = row.get("rounds") or []
    if len(rounds) < ROUNDS:
        p.append(f"{len(rounds)} round(s); it is written after {ROUNDS}")
    if any(not r.get("run") or not r.get("cause") for r in rounds):
        p.append("a round has no run or no cause")
    body = {k: v for k, v in row.items() if k != "sha256"}
    if hashlib.sha256(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() != row.get("sha256"):
        p.append("its sha256 is not the hash of its own JSON")
    return p


def honest_view(rows):
    """The honest-failure rows that count: a row whose rounds were all funds refusals or all host limits (labels.py)
    is not the agent's failure, and is said on its own line instead."""
    counted, funds, host = labels.split(rows)
    first = lambda r: min((x.get("at") for x in r.get("rounds") or [] if x.get("at")), default=None)
    return {"honestFailures": counted, "paused": labels.paused_line(funds, at=first), "blocked": labels.blocked_line(host, at=first)}


def fetcher():
    cache = {}

    def fetch(org, agent, file):
        key = (org, agent, file)
        if key not in cache:
            try:
                url = f"https://raw.githubusercontent.com/{org}/hivepunk-{agent}/main/{file}"
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "bee-self-test"}), timeout=30) as response:
                    cache[key] = json.load(response)
            except (OSError, ValueError):
                cache[key] = None
        return cache[key]
    return fetch


def self_test():
    bad = []
    D = {"host": "github.com", "method": "GET", "path": "/HivemindOS-Agents/bee-scouts/issues/:id", "status": 429}
    A, B = "0xaaaa000000000000000000000000000000000001", "0xbbbb000000000000000000000000000000000002"
    s = lambda step, status=429: {"step": step, **{k: D[k] for k in ("host", "method", "path")}, "status": status}
    a = lambda agent, owner, at, status=429: {"agent": agent, "owner": owner, "at": at, "status": status, "disproved": status != 429}
    c = lambda sightings, attempts, detector=D: {"detector": detector, "proposer": {"agent": "632", "owner": B}, "firstAt": 100, "sightings": sightings, "attempts": attempts}
    for name, cand, want in [
        ("seen in one run", c([s("s1")], [a("86", A, 200)]), "candidate"),
        ("no mechanical detector", c([s("s1"), s("s2")], [a("86", A, 200)], None), "candidate"),
        ("a detector that misses a sighting", c([s("s1"), s("s2", 503)], [a("86", A, 200)]), "candidate"),
        ("no different holder yet", c([s("s1"), s("s2")], []), "candidate"),
        ("the same holder's agent is not a different holder", c([s("s1"), s("s2")], [a("1071", B.upper(), 200)]), "candidate"),
        ("a holder that could not be read", c([s("s1"), s("s2")], [a("86", None, 200)]), "candidate"),
        ("disproved: the same request went through later", c([s("s1"), s("s2")], [a("86", A, 200), a("547", A, 300, 200)]), "rejected"),
        ("a pass before it was first seen disproves nothing", c([s("s1"), s("s2")], [a("86", A, 200), a("547", A, 50, 200)]), "kept"),
        ("two runs, a detector, a different holder's same answer", c([s("s1"), s("s2")], [a("86", A, 200)]), "kept"),
    ]:
        if decide(cand)[0] != want:
            bad.append(f"{name}: got {decide(cand)}, want {want}")
    # Lines of a Kept rules section, checked against the judgement files they cite.
    base = "https://github.com/HivemindOS-Agents"
    files = {
        ("632", "work/s1.judgement.json"): {"trace": [{"id": "t1", **D}]},
        ("632", "work/s2.judgement.json"): {"trace": [{"id": "t4", **D}, {"id": "t5", **D, "status": 200}]},
        ("86", "work/s3.judgement.json"): {"trace": [{"id": "t2", **D}]},
        ("547", "work/s9.judgement.json"): {"trace": [{"id": "d1", **D, "status": 200}, {"id": "d2", **D, "status": 503}]},
    }
    fetch = lambda org, agent, file: files.get((agent, file))
    what = "github.com GET /HivemindOS-Agents/bee-scouts/issues/:id → 429"
    runs = f"{base}/hivepunk-632/blob/main/work/s1.judgement.json#t1, {base}/hivepunk-632/blob/main/work/s2.judgement.json#t4"
    tried = f"HivePunk 86, another holder's agent ({base}/hivepunk-86/blob/main/work/s3.judgement.json#t2)"
    for name, line, want in [
        ("a kept rule with two runs and another agent's same answer", f"- Kept: {what} · seen in 2 runs ({runs}) · the same answer for {tried}", []),
        ("one run cited", f"- Kept: {what} · seen in 2 runs ({base}/hivepunk-632/blob/main/work/s1.judgement.json#t1) · the same answer for {tried}", ["cites 1 run(s); a kept rule needs 2"]),
        ("a cited item with another status", f"- Kept: {what} · seen in 2 runs ({runs.replace('#t4', '#t5')}) · the same answer for {tried}", ["its detector misses work/s2.judgement.json#t5 (200)"]),
        ("a cited item that is not there", f"- Kept: {what} · seen in 2 runs ({runs.replace('#t4', '#t8')}) · the same answer for {tried}", ["its detector misses work/s2.judgement.json#t8 (no such item)"]),
        ("confirmed only by itself", f"- Kept: {what} · seen in 2 runs ({runs}) · the same answer for HivePunk 632, another holder's agent ({base}/hivepunk-632/blob/main/work/s2.judgement.json#t4)", ["no other agent is named as having made the same request"]),
        ("the other agent's item is not the same answer", f"- Kept: {what} · seen in 2 runs ({runs}) · the same answer for HivePunk 547, another holder's agent ({base}/hivepunk-547/blob/main/work/s9.judgement.json#d1)", ["HivePunk 547's item is not the same request with the same answer (work/s9.judgement.json#d1)"]),
        ("a rejected rule with its counterexample", f"- Rejected: {what} · disproved by HivePunk 547: the same request answered 200 ({base}/hivepunk-547/blob/main/work/s9.judgement.json#d1)", []),
        ("a counterexample that did not go through", f"- Rejected: {what} · disproved by HivePunk 547: the same request answered 200 ({base}/hivepunk-547/blob/main/work/s9.judgement.json#d2)", [f"its counterexample is not the same request going through ({base}/hivepunk-547/blob/main/work/s9.judgement.json#d2)"]),
        ("a rejected rule with no counterexample", f"- Rejected: {what} · disproved by its own later run: the same request answered 200", ["a rejected rule cites no counterexample"]),
        ("some other line", "- A rule the agent wrote itself", ["a line under Kept rules that is neither Kept nor Rejected"]),
    ]:
        got = kept_line_problems(line, "632", fetch)
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    text = f"# Lessons\n\n## Failures\n\n- Failed: x\n\n{HEADING}\n\nA gotcha below becomes a kept rule only when …\n\n- Kept: {what} · seen in 2 runs ({runs}) · the same answer for {tried}\n\nCandidates waiting: 3 for a second run.\n\n## Gotchas (what sites did)\n\n- github.com: GET x → 429\n"
    if len(kept_section(text)) != 1 or kept_section("# Lessons\n\n## Failures\n\n- Failed: x\n"):
        bad.append(f"the section's lines: got {kept_section(text)}")
    # The honest-failure row: three rounds, verified_by none, and the hash of its own JSON.
    row = {"v": 1, "kind": "honest-failure", "agent": "547", "tool": "x", "repair": "rp-547-t-x", "episode": 1, "change": "547/x/e1",
           "rounds": [{"round": n, "at": f"2026-11-21T0{n}:00:00.000Z", "run": f"https://x/runs/{n}", "cause": "FAIL: missing the patch"} for n in (1, 2, 3)],
           "verified_by": "none", "text": "3 verify rounds of tools/x/ failed with no pass between them. Nothing from this change is verified or shipped. Causes: FAIL: missing the patch"}
    signed = dict(row, sha256=hashlib.sha256(json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
    for name, r, want in [
        ("a row after three rounds", signed, []),
        ("two rounds", dict(signed, rounds=signed["rounds"][:2]), ["2 round(s); it is written after 3", "its sha256 is not the hash of its own JSON"]),
        ("a row that says it was verified", dict(signed, verified_by="runner"), ["verified_by is not none", "its sha256 is not the hash of its own JSON"]),
        ("a row edited after it was written", dict(signed, text="It shipped."), ["its sha256 is not the hash of its own JSON"]),
    ]:
        got = honest_failure_problems(r)
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    total = 9 + 10 + 1 + 4
    for line in bad:
        print("FAIL", line)
    print(f"kept rules self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    if not sys.argv[1:]:
        print(__doc__)
        sys.exit(2)
    fetch, report, unread, total = fetcher(), [], 0, 0
    for repo in sys.argv[1:]:
        n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
        try:
            text = open(os.path.join(repo, "LESSONS.md"), encoding="utf-8").read() if os.path.exists(os.path.join(repo, "LESSONS.md")) else ""
            lines = kept_section(text)
            problems = [f"{line[:90]}: {p}" for line in lines for p in kept_line_problems(line, n, fetch)]
            waiting = re.search(r"^Candidates waiting: .*$", text, re.M)
            raw = []
            folder = os.path.join(repo, "repairs")
            for name in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
                if name.endswith(".honest-failure.json"):
                    row = json.load(open(os.path.join(folder, name)))
                    raw.append(dict(row, file=name))
                    problems += [f"{name}: {p}" for p in honest_failure_problems(row)]
            view = honest_view(raw)
            rows = [{"file": r["file"], "rounds": len(r.get("rounds") or []), "change": r.get("change")} for r in view["honestFailures"]]
        except (OSError, ValueError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
            continue
        total += len(problems)
        report.append({"agent": n, "section": HEADING in text, "kept": sum(1 for l in lines if l.startswith("- Kept:")), "rejected": sum(1 for l in lines if l.startswith("- Rejected:")),
                       "waiting": waiting.group(0) if waiting else None, "honestFailures": rows, "problems": problems, "paused": view["paused"], "blocked": view["blocked"]})
    print(json.dumps({"agents": report}, indent=2))
    labels.print_lines(report)
    print(f"kept rules: {sum(r['kept'] for r in report)} kept, {sum(r['rejected'] for r in report)} rejected, {sum(len(r['honestFailures']) for r in report)} honest-failure rows, {total} problems", file=sys.stderr)
    sys.exit(2 if unread else 1 if total else 0)
