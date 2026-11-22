#!/usr/bin/env python3
"""HB-067 A (22 Nov 2026 update, section 5 A): nothing stays prose or observe without a date.

Each rule the rule map marks prose or partly, and each host check that only observes, reports or runs in shadow
(listed in shadow.json at this repository's root), carries
    lifecycle: {stage, since, decideBy, check, metric}
and decideBy is at most 14 days after since. By decideBy the host records one decision from its own numbers:
enforce, retired (moved to PLAYBOOK guidance) or extend (once, with a reason, and a new decideBy). The rule map is
read the way scripts/rule_map_check.py reads it; while it lives in bee-scouts with no lifecycle of its own, a
lifecycle for its rule ids in shadow.json's `rules` section is accepted.

Problems:
  no-lifecycle       a prose or partly rule, or a shadow check, with no lifecycle
  window-too-long    decideBy more than 14 days after since (after an extend, after the extend)
  past-decide-by     today is after decideBy and no enforce or retired decision is recorded
  extended-twice     more than one extend decision, or an extend with no reason
  coded-but-observe  the rule map says coded, and the lifecycle still says prose, partly or observe with no decision
  prose-grew         the rule map has more prose rules than shadow.json last recorded
  coded-but-silent   an agent that has written logs/preflight/ stopped while logs/work/ goes on, more than 2 days
Entries within 2 days of their decideBy are listed as `due`, which is not a problem.

    python3 scripts/rule_lifecycle.py --self-test                 # the fixtures only, no network
    python3 scripts/rule_lifecycle.py [--map MAP.json] [--shadow shadow.json] [--today YYYY-MM-DD] [DIR...]
                                                                  # the rule map live from bee-scouts unless --map;
                                                                  # DIRs are clones of hivepunk-<n> (logs/ is read)

Shadow mode, report-only. Exit 0 when nothing is wrong, 1 when something is, 2 when a file could not be read.
"""
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MAP_URL = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/templates/rule_map.json"
MAX_DAYS = 14
SILENT_DAYS = 2
DUE_DAYS = 2
OBSERVING = ("prose", "partly", "observe", "shadow", "report-only")
FINAL = ("enforce", "retired")
DATE = re.compile(r"(\d{4}-\d\d-\d\d)")


def day(text):
    return datetime.date.fromisoformat(str(text)[:10])


def lifecycle_problems(lc, decisions, today, max_days=MAX_DAYS):
    """The window problems of one lifecycle and its decisions."""
    p = []
    for key in ("stage", "since", "decideBy", "check", "metric"):
        if not lc.get(key):
            p.append(f"no-lifecycle: its lifecycle has no {key}")
    if p:
        return p
    extends = [d for d in decisions if d.get("decision") == "extend"]
    final = [d for d in decisions if d.get("decision") in FINAL]
    if len(extends) > 1:
        p.append(f"extended-twice: {len(extends)} extends")
    elif any(not (d.get("reason") or "").strip() for d in extends):
        p.append("extended-twice: an extend with no reason")
    since = max([day(lc["since"])] + [day(d["at"]) for d in extends if d.get("at")])
    by = day(extends[-1]["decideBy"]) if extends and extends[-1].get("decideBy") else day(lc["decideBy"])
    if (by - since).days > max_days:
        p.append(f"window-too-long: {since} to {by} is {(by - since).days} days")
    if lc["stage"] in OBSERVING and not final and today > by:
        p.append(f"past-decide-by: decideBy {by}, no decision")
    return p


def due(lc, decisions, today):
    if not lc or any(d.get("decision") in FINAL for d in decisions) or lc.get("stage") not in OBSERVING or not lc.get("decideBy"):
        return False
    extends = [d for d in decisions if d.get("decision") == "extend" and d.get("decideBy")]
    by = day(extends[-1]["decideBy"]) if extends else day(lc["decideBy"])
    return 0 <= (by - today).days <= DUE_DAYS


def problems(rule_map, shadow, today, silent=()):
    """rule_map: the rule map as rule_map_check.py reads it; shadow: shadow.json; silent: coded-but-silent findings.
    Returns ({id: [problems]}, [ids due])."""
    found, dues = {}, []
    max_days = shadow.get("maxWindowDays", MAX_DAYS)
    kept = {r["id"]: r for r in shadow.get("rules") or [] if r.get("id")}
    entries = rule_map.get("rules") or []
    for r in entries:
        rid, status = r.get("id"), r.get("status")
        own = kept.get(rid) or {}
        lc = r.get("lifecycle") or own.get("lifecycle")
        decisions = r.get("decisions") or own.get("decisions") or []
        p = []
        if status in ("prose", "partly"):
            p = ["no-lifecycle"] if not lc else lifecycle_problems(lc, decisions, today, max_days)
        elif status == "coded" and lc and lc.get("stage") in ("prose", "partly", "observe") and not any(d.get("decision") in FINAL for d in decisions):
            p = [f"coded-but-observe: the rule map says coded, its lifecycle still says {lc['stage']}"]
        if p:
            found[f"rule {rid}"] = p
        if lc and due(lc, decisions, today):
            dues.append(f"rule {rid}")
    for c in shadow.get("checks") or []:
        lc, decisions = c.get("lifecycle"), c.get("decisions") or []
        p = ["no-lifecycle"] if not lc else lifecycle_problems(lc, decisions, today, max_days)
        if p:
            found[f"check {c.get('id')}"] = p
        if lc and due(lc, decisions, today):
            dues.append(f"check {c.get('id')}")
    prose = sum(1 for r in entries if r.get("status") == "prose")
    recorded = (shadow.get("ruleMap") or {}).get("prose")
    if recorded is not None and prose > recorded:
        found["rule map"] = [f"prose-grew: {recorded} prose rules recorded, {prose} now"]
    for agent, why in silent:
        found[f"hivepunk-{agent}"] = [f"coded-but-silent: {why}"]
    return found, dues


def last_dates(names):
    dates = [m.group(1) for n in names for m in [DATE.match(os.path.basename(n))] if m]
    return max(dates) if dates else None


def listing(repo, folder):
    """The file names in a folder of a clone, from its tree when it has no checkout."""
    if os.path.isdir(os.path.join(repo, folder)):
        return os.listdir(os.path.join(repo, folder))
    out = subprocess.run(["git", "-C", repo, "ls-tree", "--name-only", "HEAD", folder + "/"], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise OSError(out.stderr.strip()[:200])
    return out.stdout.split()


def coded_but_silent(preflight, work):
    """Why an agent's preflight logs are silent, or None. preflight and work: the file names in each folder."""
    p, w = last_dates(preflight), last_dates(work)
    if not p or not w:
        return None
    gap = (day(w) - day(p)).days
    return f"last preflight log {p}, last work log {w} ({gap} days)" if gap > SILENT_DAYS else None


def self_test():
    bad = []
    today = datetime.date(2026, 11, 22)
    lc = lambda stage="observe", since="2026-11-21", by="2026-11-28": {"stage": stage, "since": since, "decideBy": by, "check": "x.py", "metric": "would-block count"}
    rmap = lambda *rules: {"rules": [{"id": rid, "status": st, "text": "t", **extra} for rid, st, extra in rules]}
    shadow = lambda checks=(), rules=(), prose=1: {"maxWindowDays": 14, "ruleMap": {"prose": prose}, "checks": list(checks), "rules": list(rules)}
    check = lambda cid, life, decisions=(): {"id": cid, "lifecycle": life, "decisions": list(decisions)}
    cases = [
        ("a partly rule with no lifecycle", rmap(("R3", "partly", {})), shadow(), {"rule R3": ["no-lifecycle"]}),
        ("a prose rule with its lifecycle in shadow.json", rmap(("R8", "prose", {})), shadow(rules=[{"id": "R8", "lifecycle": lc("prose", "2026-11-22", "2026-12-06")}]), {}),
        ("a lifecycle in the rule map itself", rmap(("R8", "prose", {"lifecycle": lc("prose", "2026-11-22", "2026-12-06")})), shadow(), {}),
        ("a coded rule needs none", rmap(("R1", "coded", {})), shadow(prose=0), {}),
        ("a shadow check with no lifecycle", rmap(), shadow([check("watchdog", None)], prose=0), {"check watchdog": ["no-lifecycle"]}),
        ("a window of 15 days", rmap(), shadow([check("c", lc(since="2026-11-15", by="2026-11-30"))], prose=0), {"check c": ["window-too-long: 2026-11-15 to 2026-11-30 is 15 days"]}),
        ("past its decideBy with no decision", rmap(), shadow([check("c", lc(since="2026-11-07", by="2026-11-21"))], prose=0), {"check c": ["past-decide-by: decideBy 2026-11-21, no decision"]}),
        ("past its decideBy, enforced", rmap(), shadow([check("c", lc(since="2026-11-07", by="2026-11-21"), [{"decision": "enforce", "at": "2026-11-21"}])], prose=0), {}),
        ("extended once with a reason", rmap(), shadow([check("c", lc(since="2026-11-07", by="2026-11-21"), [{"decision": "extend", "at": "2026-11-21", "decideBy": "2026-12-01", "reason": "two fixture false positives"}])], prose=0), {}),
        ("extended twice", rmap(), shadow([check("c", lc(since="2026-11-01", by="2026-11-14"), [{"decision": "extend", "at": "2026-11-14", "decideBy": "2026-11-20", "reason": "a"}, {"decision": "extend", "at": "2026-11-20", "decideBy": "2026-11-30", "reason": "b"}])], prose=0),
         {"check c": ["extended-twice: 2 extends"]}),
        ("an extend with no reason", rmap(), shadow([check("c", lc(since="2026-11-07", by="2026-11-21"), [{"decision": "extend", "at": "2026-11-21", "decideBy": "2026-12-01"}])], prose=0), {"check c": ["extended-twice: an extend with no reason"]}),
        ("coded while its lifecycle says observe", rmap(("R9", "coded", {})), shadow(rules=[{"id": "R9", "lifecycle": lc("partly", "2026-11-22", "2026-12-06")}], prose=0), {"rule R9": ["coded-but-observe: the rule map says coded, its lifecycle still says partly"]}),
        ("more prose rules than recorded", rmap(("R8", "prose", {"lifecycle": lc("prose", "2026-11-22", "2026-12-06")}), ("R10", "prose", {"lifecycle": lc("prose", "2026-11-22", "2026-12-06")})), shadow(prose=1), {"rule map": ["prose-grew: 1 prose rules recorded, 2 now"]}),
    ]
    for name, m, s, want in cases:
        got, _ = problems(m, s, today)
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    # 667's preflight logs stopped on 15 Nov while its work logs ran to 21 Nov; the other four wrote both to 20 or 21 Nov.
    if coded_but_silent(["2026-11-14.jsonl", "2026-11-15.jsonl"], ["2026-11-20.jsonl", "2026-11-21.jsonl"]) != "last preflight log 2026-11-15, last work log 2026-11-21 (6 days)":
        bad.append("667's preflight logs are silent")
    if coded_but_silent(["2026-11-20.jsonl"], ["2026-11-22.jsonl"]) or coded_but_silent([], ["2026-11-22.jsonl"]):
        bad.append("2 days apart is not silent, and an agent that never wrote one is not")
    got, dues = problems(rmap(), shadow([check("c", lc(since="2026-11-21", by="2026-11-23"))], prose=0), today, [("667", "x")])
    if dues != ["check c"] or got != {"hivepunk-667": ["coded-but-silent: x"]}:
        bad.append(f"due and silent: got {got}, {dues}")
    # This repository's own shadow.json is valid on its own terms.
    own = json.load(open(os.path.join(HERE, "..", "shadow.json")))
    got, _ = problems({"rules": [{"id": r["id"], "status": r["status"]} for r in own["rules"]]}, own, datetime.date(2026, 11, 22))
    if got:
        bad.append(f"shadow.json: {got}")
    total = len(cases) + 4
    for line in bad:
        print("FAIL", line)
    print(f"rule lifecycle self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    map_path, shadow_path, today, repos, it = None, os.path.join(HERE, "..", "shadow.json"), datetime.datetime.now(datetime.timezone.utc).date(), [], iter(argv)
    for a in it:
        if a == "--map":
            map_path = next(it)
        elif a == "--shadow":
            shadow_path = next(it)
        elif a == "--today":
            today = day(next(it))
        else:
            repos.append(a)
    try:
        shadow = json.load(open(shadow_path))
        if map_path:
            rule_map = json.load(open(map_path))
        else:
            with urllib.request.urlopen(urllib.request.Request(MAP_URL, headers={"User-Agent": "bee-self-test-rule-lifecycle"}), timeout=20) as r:
                rule_map = json.load(r)
    except (OSError, ValueError) as error:
        print(f"rule lifecycle: could not read the rule map or shadow.json: {error}", file=sys.stderr)
        return 2
    silent, unread, logs = [], 0, []
    for repo in repos:
        n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
        try:
            pre, work = listing(repo, "logs/preflight"), listing(repo, "logs/work")
        except (OSError, subprocess.SubprocessError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
            continue
        logs.append({"agent": n, "lastPreflight": last_dates(pre), "lastWork": last_dates(work)})
        why = coded_but_silent(pre, work)
        if why:
            silent.append((n, why))
    found, dues = problems(rule_map, shadow, today, silent)
    counts = {s: sum(1 for r in rule_map.get("rules") or [] if r.get("status") == s) for s in ("coded", "partly", "prose")}
    print(json.dumps({"today": str(today), "ruleMap": counts, "checks": len(shadow.get("checks") or []), "logs": logs, "due": dues, "problems": found}, indent=2))
    for key, p in found.items():
        for line in p:
            print(f"PROBLEM {key}: {line}", file=sys.stderr)
    total = sum(len(p) for p in found.values())
    print(f"rule lifecycle: {total} problems, {len(dues)} due within {DUE_DAYS} days ({counts['prose']} prose and {counts['partly']} partly rules, {len(shadow.get('checks') or [])} shadow checks, {len(logs)} agents)", file=sys.stderr)
    return 2 if unread else 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
