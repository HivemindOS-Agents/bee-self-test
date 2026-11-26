#!/usr/bin/env python3
"""HB-065's check (21 Nov 2026 update, Parts 2 and 3): repair receipts, escalations and where failures go.

The host writes a receipt into an agent's own repository when one of its repairs ends: repairs/<repair-id>--e<k>.json,
once, never edited, and repairs/<repair-id>--e<k>.recheck.json seven days later. Its open repairs stay in
bee-scouts/health/<n>.json. This reads those public files and says what is wrong with them. Keyless and read-only;
nothing in an agent repository is run.

    python3 scripts/repair_receipts.py --self-test          # the fixtures only, no network
    python3 scripts/repair_receipts.py DIR...               # clones of hivepunk-<n> (their repairs/, LESSONS.md and
                                                            # watchdog/ are read; health/<n>.json is read live)
    python3 scripts/repair_receipts.py DIR... --health HDIR # the same, with health/<n>.json read from HDIR/<n>.json

A receipt must:
  R1  say how it ended as one of fixed-verified, outcome-verified, outcome-unverified, administrative
  R2  fixed-verified: link the runner run or the rescore (a publication read back needs none); a runner close also
      names at least one fix commit
  R3  outcome-verified: link the done step publicly; without a link it is outcome-unverified, which is allowed and
      counted
  R4  administrative: say why (closedBy), or be marked removedWithoutClosure with its reason
  R5  name who received its escalation, when it was escalated (a receipt marked `backfilled`, written after the fact
      from the health file's public history, records an escalation as it was and may name nobody). An episode that
      closed within 24 hours of its escalation, before H1 asks for a receiver, may name nobody either
  R6  name a known source (runner, host-step, frozen, watchdog, lesson)
  R7  carry no key, seed phrase or token
  R8  never be edited: one commit a file, when the clone has history
A recheck must name a receipt beside it, say held or recurred, and be written no earlier than that receipt's recheckDue.

A health file must:
  H1  name a receiver on every ESCALATED repair within 24 hours of its escalation
  H2  keep an open step repair's counters moving: no LESSONS failure of that play more than 20 minutes newer than
      its lastObservedAt. A failure the file lists under `policySkips` (HB-062), or whose line went to `skip`,
      `policy_skip` or `stopped_on_rule`, is not a failed attempt and is not counted here either; nor is a funds pause
      or a host limit (labels.py), which are said on their own line per agent instead.

LESSONS.md, once the host writes them: every failure line ends "Went to: <bucket>", one of the eight buckets.
`unrouted` lines are listed, since a line no bucket took has no owner.

The watchdog (report-only, as the watchdog is): a finding with severity "repair" older than 24 hours whose subject
has no repair, and a D22 finding (a claimed file not committed) on a tool whose repair is RELEASED.

Every file read here is a security setting (HB-136, HB-138; scripts/security_input.py). A receipt, recheck, health
file or watchdog/latest.json that is empty, only commas or whitespace, or does not parse to its shape STOPs with
empty_security_setting or unparseable_security_setting; so does a latest.json with no `findings` key, a health file
with no `repairs` list, and an absent latest.json or health file, which have no default. A STOP names its file and the
rest of that agent's report is kept, with the file under `stops`. Two inputs have a documented default when absent,
and say `default_used` and list themselves under `unread`: repairs/ (the host writes a receipt only when a repair
ends) and LESSONS.md (above: "once the host writes them").

Exit 0 when nothing is wrong, 1 when something is, 2 when a file stopped the run or could not be read.
"""
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labels  # noqa: E402
import security_input as si  # noqa: E402

RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/health/{n}.json"
CLOSE_KINDS = ("fixed-verified", "outcome-verified", "outcome-unverified", "administrative")
SOURCES = ("runner", "host-step", "frozen", "watchdog", "lesson")
BUCKETS = ("skip", "stopped_on_rule", "policy_skip", "repair", "no_funds", "host_cause", "no_input", "unrouted")
OPEN = ("OPEN", "REPAIR_ATTEMPTED", "VALIDATION_PASSED", "RECURRENCE_DETECTED", "PARKED", "ESCALATED")
SECRET = re.compile(r"private[_ ]?key|seed phrase|mnemonic|api[_-]?key|bearer |secret[_-]?key|0x[0-9a-f]{64}\b", re.I)
RECEIVER_HOURS = 24
WATCHDOG_GRACE_HOURS = 24
LESSON = re.compile(r"^- Failed: (?P<play>.*?) · Reason: (?P<reason>.*?) · (?P<at>\d{4}-\d\d-\d\d \d\d:\d\d) UTC(?P<rest>.*)$")
PLAY = {
    "Publish a small open dataset": "publish-dataset", "Research a token, protocol or project": "research",
    "Propose a fix or an improvement": "propose", "See what other agents are doing": "agents",
    "Build a small tool in its own repository": "build-tool", "Tell other agents what it finished": "tell-agents",
    "Explain its work in a picture or a short video": "media",
}


def ts(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)


def receipt_problems(r):
    """R1 to R7, on one receipt."""
    p = []
    for key in ("agent", "repair", "episode", "source", "cause", "close", "verification", "fix", "recheckDue"):
        if key not in r:
            p.append(f"missing {key}")
    if p:
        return p
    kind, ver = r["close"].get("kind"), r["verification"].get("kind")
    if kind not in CLOSE_KINDS:
        p.append(f"R1 bad close kind {kind!r}")
    if kind == "fixed-verified" and not r["verification"].get("link") and ver != "publication-readback":
        p.append("R2 fixed-verified links no runner run or rescore")
    if kind == "fixed-verified" and ver == "runner" and not r["fix"].get("commits"):
        p.append("R2 a runner close names no fix commit")
    if kind == "outcome-verified" and not r["verification"].get("link"):
        p.append("R3 outcome-verified links no done step")
    if kind == "administrative" and not r["close"].get("closedBy") and not r["close"].get("removedWithoutClosure"):
        p.append("R4 an administrative close says no reason")
    if r["close"].get("removedWithoutClosure") and not r["close"].get("why"):
        p.append("R4 a removed row says no reason")
    if r.get("escalation") and not (r["escalation"].get("receiver") or {}).get("who") and not r.get("backfilled") and not closed_before_receiver_due(r):
        p.append("R5 an escalated episode names no receiver")
    if (r["source"] or {}).get("type") not in SOURCES:
        p.append(f"R6 bad source type {(r['source'] or {}).get('type')!r}")
    if SECRET.search(json.dumps(r)):
        p.append("R7 it carries something that reads as a secret")
    return p


def recheck_problems(c, receipt, written_at=None):
    p = []
    if receipt is None:
        return ["a recheck with no receipt beside it"]
    if c.get("verdict") not in ("held", "recurred"):
        p.append(f"bad verdict {c.get('verdict')!r}")
    if c.get("window") != [receipt["close"]["at"], receipt["recheckDue"]]:
        p.append("its window is not its receipt's close to its recheckDue")
    if c.get("verdict") == "recurred" and not c.get("sameCause"):
        p.append("recurred with no same-cause failure counted")
    if written_at is not None and written_at < ts(receipt["recheckDue"]):
        p.append("written before its receipt's recheckDue")
    return p


def lessons(text):
    """Its failure lines: play, reason, time and the bucket it says it went to (None when the line names none)."""
    out = []
    for line in text.splitlines():
        m = LESSON.match(line.strip())
        if not m or m["play"].startswith("self-test of tools/"):
            continue
        went = re.search(r" · Went to: (\S+)\s*$", m["rest"])
        out.append({"play": PLAY.get(m["play"], "?"), "reason": m["reason"], "at": ts(m["at"].replace(" ", "T") + ":00Z"),
                    "bucket": went.group(1) if went else None, "line": line.strip()})
    return out


def lesson_problems(lines):
    """Every failure line names one known bucket, once any line does (the host began to write them on 21 Nov 2026)."""
    if not any(l["bucket"] for l in lines):
        return []
    p = [f"a failure line names no bucket: {l['line'][:110]}" for l in lines if l["bucket"] is None]
    p += [f"unknown bucket {l['bucket']!r}: {l['line'][:90]}" for l in lines if l["bucket"] and l["bucket"] not in BUCKETS]
    return p


def escalated_at(repair):
    found = re.findall(r"^Escalated (\d{4}-\d\d-\d\dT[0-9:.]+Z):", repair.get("escalation") or "", re.M)
    return ts(found[-1]) if found else None


def health_problems(health, failures, now):
    """H1 and H2, on one health file and its agent's LESSONS failure lines."""
    p = []
    skipped = [(s.get("play") or str(s.get("repair", "")).split("-s-", 1)[-1], ts(s["at"])) for s in health.get("policySkips") or [] if s.get("at")]
    def counted(f):
        if f.get("bucket") in ("skip", "policy_skip", "stopped_on_rule") or not labels.counts_as_failure(f.get("line") or f.get("reason") or ""):
            return False
        return not any(play == f["play"] and abs((f["at"] - at).total_seconds()) <= 1800 for play, at in skipped)
    failures = [f for f in failures if counted(f)]
    for r in health.get("repairs") or []:
        if r.get("state") == "ESCALATED" and not (r.get("receiver") or {}).get("who"):
            at = escalated_at(r)
            if at is not None and now - at >= datetime.timedelta(hours=RECEIVER_HOURS):
                p.append(f"H1 {r['id']}: escalated {at.strftime('%Y-%m-%d %H:%M')} UTC with no receiver")
        if r.get("state") in OPEN and str(r.get("kind", "")).startswith("step:") and r.get("lastObservedAt"):
            play, last = r["kind"].split(":", 1)[1], ts(r["lastObservedAt"])
            newer = [f for f in failures if f["play"] == play and f["at"] > last + datetime.timedelta(minutes=20)]
            if newer:
                p.append(f"H2 {r['id']}: counters stand at {last.strftime('%Y-%m-%d %H:%M')} UTC while LESSONS has {len(newer)} later failure(s) of that play")
    return p


def lesson_view(health, failures, now):
    """The failure lines as the counter check reads them: a funds pause ("paused: needs funding") and a host limit
    ("blocked: host limit") are not failures, are left out of the count and H2, and are each said on a line of their own."""
    counted, funds, host = labels.split(failures, text=lambda f: f["line"])
    return {"failures": len(counted), "problems": health_problems(health, failures, now), "paused": labels.paused_line(funds, health), "blocked": labels.blocked_line(host)}


def watchdog_intake(findings, repairs, now):
    """What the watchdog found that no repair covers. Report-only."""
    to_open, contradictions = [], []
    by_artifact = {}
    for r in repairs or []:
        by_artifact.setdefault(r.get("artifact"), []).append(r)
    for f in findings or []:
        if f.get("severity") != "repair":
            continue
        subject = f.get("subject") or ""
        artifact = subject.split("tools/", 1)[1].split("/", 1)[0] if "tools/" in subject else subject
        rows = by_artifact.get(artifact, [])
        if any(r.get("state") in OPEN for r in rows):
            continue
        if f.get("check") == "D22" and any(r.get("state") == "RELEASED" for r in rows):
            contradictions.append(f"{f['id']}: the file is not committed, and {[r['id'] for r in rows if r.get('state') == 'RELEASED'][0]} is RELEASED")
        elif f.get("firstSeen") and now - ts(f["firstSeen"]) >= datetime.timedelta(hours=WATCHDOG_GRACE_HOURS):
            to_open.append(f"{f['id']}: {f.get('check')} on {subject[:70]}, first seen {f['firstSeen'][:16]}, no repair")
    return to_open, contradictions


def commits_of(repo, path):
    """How many commits wrote a file, or None when the clone has no history to say."""
    try:
        shallow = subprocess.run(["git", "-C", repo, "rev-parse", "--is-shallow-repository"], capture_output=True, text=True, timeout=30).stdout.strip()
        if shallow != "false":
            return None
        out = subprocess.run(["git", "-C", repo, "log", "--format=%H", "--", path], capture_output=True, text=True, timeout=60)
        return len(out.stdout.split()) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def read_health(n, health_dir=None):
    """bee-scouts/health/<n>.json, live or from a local folder. It has no default: absent or unread is a STOP."""
    source = f"health/{n}.json"
    if health_dir:
        health = si.read_json(os.path.join(health_dir, f"{n}.json"), source)
    else:
        try:
            with urllib.request.urlopen(urllib.request.Request(RAW.format(n=n), headers={"User-Agent": "bee-self-test"}), timeout=30) as response:
                text = response.read().decode("utf-8", "replace")
        except (OSError, ValueError) as error:
            raise si.Stop(si.EMPTY, source, f"absent: could not be fetched ({error})")
        health = si.parse_json(source, text)
    repairs = si.field(source, health, "repairs", list, nonempty=False)
    for key, rows in (("repairs", repairs), ("policySkips", health.get("policySkips") or [])):
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise si.Stop(si.UNPARSEABLE, source, f"`{key}` is not a list of objects")
    return health


def read_watchdog(repo):
    """watchdog/latest.json's findings. No default: an absent file or a missing `findings` key is a STOP, never
    "no findings"; an empty list is the watchdog saying it found nothing."""
    source = "watchdog/latest.json"
    findings = si.field(source, si.read_json(os.path.join(repo, "watchdog", "latest.json"), source), "findings", list, nonempty=False)
    if not all(isinstance(f, dict) for f in findings):
        raise si.Stop(si.UNPARSEABLE, source, "a finding is not an object")
    return findings


def read_record(folder, name, kind):
    """One receipt or recheck: a JSON object whose parts the checks read are objects."""
    source = f"repairs/{name}"
    r = si.read_json(os.path.join(folder, name), source)
    parts = ("close", "verification", "fix") if kind == "receipt" else ()
    for key in parts:
        if key in r and not isinstance(r[key], dict):
            raise si.Stop(si.UNPARSEABLE, source, f"`{key}` is not an object")
    for key in ("source", "escalation") if kind == "receipt" else ():
        if r.get(key) is not None and not isinstance(r[key], dict):
            raise si.Stop(si.UNPARSEABLE, source, f"`{key}` is not an object")
    return r


def stopped(report, stop):
    """A STOP said with its agent, and kept in that agent's report; the rest of the report goes on."""
    print(f"hivepunk-{report.get('agent', '?')}: {stop.line()}", file=sys.stderr)
    report.setdefault("stops", []).append(stop.as_dict())


def read_receipts(repo, now, report):
    """Its repairs/ folder. This check owns the receipts (<repair>--e<k>.json) and their rechecks; an honest-failure row
    (<repair>--e<k>.honest-failure.json) is kept_rules.py's, and is left to it."""
    folder, receipts = os.path.join(repo, "repairs"), {}
    if not os.path.isdir(folder):
        report.setdefault("unread", []).append("repairs/")
        si.default_used(f"{os.path.basename(os.path.normpath(repo))} repairs/", "absent: no repair of this agent has ended, so no receipt is written yet")
        return report
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json") or name.endswith((".recheck.json", ".honest-failure.json")):
            continue
        try:
            r = read_record(folder, name, "receipt")
        except si.Stop as stop:
            stopped(report, stop)
            continue
        receipts[name[:-5]] = r
        report["receipts"] += 1
        report["byCloseKind"][r.get("close", {}).get("kind")] = report["byCloseKind"].get(r.get("close", {}).get("kind"), 0) + 1
        report["problems"] += [f"{name}: {p}" for p in receipt_problems(r)]
        if name != f"{r.get('repair')}--e{r.get('episode')}.json":
            report["problems"].append(f"{name}: its name is not its repair and episode")
        written = commits_of(repo, f"repairs/{name}")
        if written is not None and written > 1:
            report["problems"].append(f"{name}: R8 written {written} times; a receipt is never edited")
        if "recheckDue" in r and ts(r["recheckDue"]) <= now and not os.path.exists(os.path.join(folder, name[:-5] + ".recheck.json")):
            report["rechecks"]["due"] += 1
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".recheck.json"):
            continue
        try:
            c = read_record(folder, name, "recheck")
        except si.Stop as stop:
            stopped(report, stop)
            continue
        report["rechecks"][c.get("verdict")] = report["rechecks"].get(c.get("verdict"), 0) + 1
        report["problems"] += [f"{name}: {p}" for p in recheck_problems(c, receipts.get(name[:-len(".recheck.json")]))]
    return report


def check_agent(repo, now, health_dir=None):
    """One agent's clone: its receipts and rechecks, its LESSONS lines, its health file (live, or from health_dir) and its
    watchdog. A file that STOPs is listed under `stops` and the rest of the report is still worked out."""
    n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
    report = {"agent": n, "receipts": 0, "byCloseKind": {k: 0 for k in CLOSE_KINDS}, "rechecks": {"held": 0, "recurred": 0, "due": 0},
              "lessons": {"lines": 0, "byBucket": {}, "unrouted": []}, "problems": [], "watchdog": {"noRepair": [], "contradictions": []},
              "stops": [], "unread": []}
    read_receipts(repo, now, report)
    failures, text, path = [], None, os.path.join(repo, "LESSONS.md")
    if not os.path.exists(path):
        report["unread"].append("LESSONS.md")
        si.default_used(f"{os.path.basename(os.path.normpath(repo))} LESSONS.md", "absent: the host has written no LESSONS.md yet")
    else:
        try:
            text = si.read_text(path, "LESSONS.md")
        except si.Stop as stop:
            stopped(report, stop)
    if text is not None:
        failures = lessons(text)
        report["lessons"]["lines"] = len(failures)
        for f in failures:
            if f["bucket"]:
                report["lessons"]["byBucket"][f["bucket"]] = report["lessons"]["byBucket"].get(f["bucket"], 0) + 1
        report["lessons"]["unrouted"] = [f["line"][:140] for f in failures if f["bucket"] == "unrouted"][:10]
        report["problems"] += [f"LESSONS.md: {p}" for p in lesson_problems(failures)]
    try:
        health = read_health(n, health_dir)
    except si.Stop as stop:
        stopped(report, stop)
        health = None
    if health is not None:
        report["health"] = {"status": health.get("status"), "at": health.get("at"), "funding": labels.funding_state(health)}
        view = lesson_view(health, failures, now)
        report["lessons"]["counted"] = view["failures"]
        report["paused"], report["blocked"] = view["paused"], view["blocked"]
        report["problems"] += view["problems"]
    try:
        findings = read_watchdog(repo)
    except si.Stop as stop:
        stopped(report, stop)
        findings = None
    if findings is not None and health is not None:
        to_open, contradictions = watchdog_intake(findings, health.get("repairs"), now)
        report["watchdog"] = {"noRepair": to_open, "contradictions": contradictions}
    return report


# ---------------------------------------------------------------------------------------------------------------- fixtures
def closed_before_receiver_due(r):
    """Whether an episode closed inside RECEIVER_HOURS of its escalation, before HB-065 asked for a receiver (H1's window).
    An escalation or a close with no readable time is not."""
    try:
        escalated, closed = ts(r["escalation"]["at"]), ts(r["close"]["at"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    return datetime.timedelta(0) <= closed - escalated < datetime.timedelta(hours=RECEIVER_HOURS)


def self_test():
    T = "2026-11-21T08:45:00.000Z"
    run = "https://github.com/HivemindOS-Agents/bee-self-test/actions/runs/44885139037"
    def receipt(**over):
        r = {"v": 1, "kind": "repair-receipt", "agent": "1071", "repair": "rp-1071-t-reentrancy-cases", "episode": 1, "repairKind": "selfTest", "artifact": "reentrancy-cases",
             "source": {"type": "runner", "ref": "run:1", "health": "https://github.com/HivemindOS-Agents/bee-scouts/blob/main/health/1071.json"},
             "cause": {"text": "FAIL: no exploit or payload instructions in records", "hash": "abc", "laterCauses": [], "hashes": ["abc"]},
             "openedAt": "2026-11-21T07:40:17.000Z", "states": ["OPEN", "REPAIR_ATTEMPTED", "RELEASED"], "counters": {"failedAttempts": 2, "sameCause": 1, "recurrences": 0},
             "escalation": None, "fix": {"commits": ["19bfeaa", "f9c837b"], "by": "agent"}, "verification": {"kind": "runner", "link": run},
             "close": {"kind": "fixed-verified", "closedBy": f"code: self-test runner passed ({run})", "at": T, "removedWithoutClosure": False, "why": None},
             "recheckDue": "2026-11-28T08:45:00.000Z"}
        r.update(over)
        return r
    admin = lambda **close: receipt(fix={"commits": [], "by": "none"}, verification={"kind": "none", "link": None},
                                    close={"kind": "administrative", "closedBy": None, "at": T, "removedWithoutClosure": False, "why": None, **close})
    escalation = {"text": "Parked after 2 failed steps", "at": "2026-11-17T04:18:29.237Z", "receiver": None}
    cases = [
        ("a runner close with its run and its fix commits", receipt(), []),
        ("a runner close with no run link", receipt(verification={"kind": "runner", "link": None}), ["R2 fixed-verified links no runner run or rescore"]),
        ("a runner close that names no fix commit", receipt(fix={"commits": [], "by": "none"}), ["R2 a runner close names no fix commit"]),
        ("a publication read back needs no link", receipt(verification={"kind": "publication-readback", "link": None}, fix={"commits": [], "by": "none"}), []),
        ("a done step with a public link", receipt(fix={"commits": [], "by": "none"}, verification={"kind": "public-step", "link": "https://github.com/HivemindOS-Agents/hivepunk-632/blob/main/work/x.md"},
                                                  close={"kind": "outcome-verified", "closedBy": "step: a media step ended done (https://…)", "at": T, "removedWithoutClosure": False, "why": None}), []),
        ("outcome-verified with no link", receipt(fix={"commits": [], "by": "none"}, verification={"kind": "public-step", "link": None},
                                                 close={"kind": "outcome-verified", "closedBy": "step: x", "at": T, "removedWithoutClosure": False, "why": None}), ["R3 outcome-verified links no done step"]),
        ("a done step on the host's record only is allowed", receipt(fix={"commits": [], "by": "none"}, verification={"kind": "host-step-record", "link": None},
                                                                    close={"kind": "outcome-unverified", "closedBy": "step: a research step ended done (research:m:7)", "at": T, "removedWithoutClosure": False, "why": None}), []),
        ("a host pause says why", admin(closedBy="host: play paused (B-51: no picture before launch)"), []),
        ("an administrative close with no reason", admin(), ["R4 an administrative close says no reason"]),
        ("a removed row with its reason", admin(removedWithoutClosure=True, why="reclassified: every failure it held was a policy skip (HB-062)"), []),
        ("a removed row with no reason", admin(removedWithoutClosure=True), ["R4 a removed row says no reason"]),
        ("an escalated episode with no receiver", receipt(escalation=escalation), ["R5 an escalated episode names no receiver"]),
        # 547's fixprotocol e1 (23 Nov 2026): escalated 02:19:37, closed fixed-verified 06:30:27, before a receiver was
        # due. HB-065 asks for a receiver within 24 hours of the escalation (H1's window), so this is no problem.
        ("closed 4 h after its escalation, before a receiver was due", receipt(escalation={**escalation, "at": "2026-11-23T02:19:37.199Z"},
                                                                               close={**receipt()["close"], "at": "2026-11-23T06:30:27.000Z"}), []),
        ("closed 25 h after its escalation with no receiver", receipt(escalation={**escalation, "at": "2026-11-23T02:19:37.199Z"},
                                                                        close={**receipt()["close"], "at": "2026-11-24T03:30:00.000Z"}), ["R5 an escalated episode names no receiver"]),
        ("an escalation with no time is judged as before", receipt(escalation={**escalation, "at": None}), ["R5 an escalated episode names no receiver"]),
        ("an escalated episode with its receiver", receipt(escalation={**escalation, "receiver": {"who": "HivemindOS host: HB-041", "by": "rule", "at": T, "returned": "x", "returnedAt": T}}), []),
        ("a backfilled receipt records an escalation nobody received", {**admin(removedWithoutClosure=True, why="reclassified: every failure it held was a policy skip (HB-062)"), "escalation": escalation, "backfilled": True, "note": "from the public history"}, []),
        ("an unknown close kind and source", receipt(close={"kind": "fixed", "closedBy": "x", "at": T, "removedWithoutClosure": False, "why": None}, source={"type": "agent-note", "ref": None, "health": "x"}),
         ["R1 bad close kind 'fixed'", "R6 bad source type 'agent-note'"]),
        ("a receipt that carries a key", receipt(cause={"text": "api_key=sk-live-123", "hash": "x", "laterCauses": [], "hashes": ["x"]}), ["R7 it carries something that reads as a secret"]),
        ("a receipt missing its close", {k: v for k, v in receipt().items() if k != "close"}, ["missing close"]),
    ]
    bad = []
    for name, r, want in cases:
        got = receipt_problems(r)
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    base = receipt()
    recheck = {"v": 1, "kind": "repair-recheck", "repair": base["repair"], "episode": 1, "receiptCloseAt": T, "window": [T, base["recheckDue"]], "sameCause": 0, "otherCauses": 1, "verdict": "held", "firstRecurrence": None}
    for name, c, r, at, want in [
        ("a held recheck", recheck, base, ts("2026-11-28T09:00:00Z"), []),
        ("a recurred recheck", {**recheck, "verdict": "recurred", "sameCause": 2}, base, None, []),
        ("recurred with nothing counted", {**recheck, "verdict": "recurred"}, base, None, ["recurred with no same-cause failure counted"]),
        ("written before it was due", recheck, base, ts("2026-11-27T09:00:00Z"), ["written before its receipt's recheckDue"]),
        ("another window", {**recheck, "window": [T, "2026-11-22T08:45:00.000Z"]}, base, None, ["its window is not its receipt's close to its recheckDue"]),
        ("no receipt beside it", recheck, None, None, ["a recheck with no receipt beside it"]),
    ]:
        got = recheck_problems(c, r, at)
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    # 667 as its files stood at 09:31 UTC 21 Nov 2026: four escalations with nobody named, three with counters that stopped.
    now = ts("2026-11-21T09:31:00Z")
    row = lambda play, last, esc, **over: {"id": f"rp-667-s-{play}", "artifact": play, "kind": f"step:{play}", "state": "ESCALATED", "lastObservedAt": last, "closedBy": None,
                                           "escalation": f"Parked after 2 failed steps of its {play} play in a row.\nEscalated {esc}: parked 27 h with no new input.", **over}
    health = {"agent": "667", "status": "repairing", "repairs": [
        row("propose", "2026-11-20T06:17:44.280Z", "2026-11-17T04:18:29.237Z"), row("research", "2026-11-17T00:08:43.501Z", "2026-11-17T04:18:29.237Z"),
        row("publish-dataset", "2026-11-17T00:05:46.850Z", "2026-11-18T01:06:22.820Z"), row("agents", "2026-11-17T00:10:07.475Z", "2026-11-18T01:06:22.820Z")]}
    text = "\n".join([
        "## Failures", "",
        "- Failed: Publish a small open dataset · Reason: The research could not finish. Your agent will try again at its next check-in. · 2026-11-21 09:19 UTC · 6th time running",
        "- Failed: Research a token, protocol or project · Reason: Nothing came of it: the search found no pages. · 2026-11-21 06:14 UTC · 6th time running",
        "- Failed: See what other agents are doing · Reason: Nothing came of it this time. · 2026-11-20 06:19 UTC · 5th time running",
        "- Failed: Propose a fix or an improvement · Reason: No proposal this time: its answer could not be read (cut off or not JSON). It tries again at the next check-in. · 2026-11-20 06:17 UTC · 6th time running",
        "- Failed: self-test of tools/cardkeys · Reason: its run failed · 2026-11-12 09:31 UTC"])
    got = health_problems(health, lessons(text), now)
    want = ["H1 rp-667-s-propose: escalated 2026-11-17 04:18 UTC with no receiver",
            "H1 rp-667-s-research: escalated 2026-11-17 04:18 UTC with no receiver", "H2 rp-667-s-research: counters stand at 2026-11-17 00:08 UTC while LESSONS has 1 later failure(s) of that play",
            "H1 rp-667-s-publish-dataset: escalated 2026-11-18 01:06 UTC with no receiver", "H2 rp-667-s-publish-dataset: counters stand at 2026-11-17 00:05 UTC while LESSONS has 1 later failure(s) of that play",
            "H1 rp-667-s-agents: escalated 2026-11-18 01:06 UTC with no receiver", "H2 rp-667-s-agents: counters stand at 2026-11-17 00:10 UTC while LESSONS has 1 later failure(s) of that play"]
    if got != want:
        bad.append(f"667's four escalations: got {got}")
    # Each with a receiver and counters at its newest failure: nothing wrong. Under a day escalated: not yet a problem.
    received = {"repairs": [dict(r, receiver={"who": "HivemindOS host"}, lastObservedAt="2026-11-21T09:19:00.000Z") for r in health["repairs"]]}
    if health_problems(received, lessons(text), now):
        bad.append(f"received and counted: got {health_problems(received, lessons(text), now)}")
    # 547 at 11:05 UTC 21 Nov: its one later publish-dataset line is a topic refusal the file lists as a policy skip.
    skip547 = {"policySkips": [{"at": "2026-11-21T02:53:17.049Z", "play": "publish-dataset", "filter": "hb043:topic"}],
               "repairs": [{"id": "rp-547-s-publish-dataset", "artifact": "publish-dataset", "kind": "step:publish-dataset", "state": "RECURRENCE_DETECTED", "lastObservedAt": "2026-11-20T23:57:05.729Z", "closedBy": None, "escalation": None}]}
    line547 = "- Failed: Publish a small open dataset · Reason: No dataset this time: it was about HivemindOS's own issues or self-tests, not something people outside need. Nothing was published. · 2026-11-21 02:53 UTC"
    if health_problems(skip547, lessons(line547), now):
        bad.append("a policy skip the file lists is not a stopped counter")
    if len(health_problems({**skip547, "policySkips": []}, lessons(line547), now)) != 1:
        bad.append("the same line with no policy skip listed is a stopped counter")
    if health_problems({**skip547, "policySkips": []}, lessons(line547 + " · Went to: policy_skip"), now):
        bad.append("a line that went to policy_skip is not a stopped counter")
    fresh = {"repairs": [row("propose", "2026-11-20T06:17:44.280Z", "2026-11-21T04:00:00.000Z")]}
    if health_problems(fresh, [], now):
        bad.append("escalated under 24 hours ago is not yet a problem")
    # LESSONS buckets: none written yet is not a problem; once one line has a bucket, every line needs a known one.
    if lesson_problems(lessons(text)):
        bad.append("lines from before the host wrote buckets are not a problem")
    tagged = text.replace("· 2026-11-21 09:19 UTC · 6th time running", "· 2026-11-21 09:19 UTC · 6th time running · Went to: no_funds").replace("· 2026-11-20 06:19 UTC · 5th time running", "· 2026-11-20 06:19 UTC · 5th time running · Went to: nowhere")
    got = lesson_problems(lessons(tagged))
    if len(got) != 3 or not got[2].startswith("unknown bucket 'nowhere'") or not all(g.startswith("a failure line names no bucket") for g in got[:2]):
        bad.append(f"bucket lines: got {got}")
    if [l["bucket"] for l in lessons(tagged)] != ["no_funds", None, "nowhere", None]:
        bad.append(f"bucket parsing: got {[l['bucket'] for l in lessons(tagged)]}")
    # The watchdog: 632's D22 on a tool whose frozen repair is RELEASED is a contradiction; a finding a day old with no
    # repair is listed; one whose subject has an open repair, a younger one and a "report" one are not.
    findings = [
        {"id": "wd-632-D22-a", "check": "D22", "severity": "repair", "subject": "tools/attribution-docs-check-fixtures/fixtures.csv", "firstSeen": "2026-11-20T00:08:10.995Z"},
        {"id": "wd-632-D17-b", "check": "D17", "severity": "repair", "subject": "ARTIFACTS.md", "firstSeen": "2026-11-19T00:01:40.189Z"},
        {"id": "wd-632-D22-c", "check": "D22", "severity": "repair", "subject": "tools/card-fixtures-checker/checker.py", "firstSeen": "2026-11-21T00:01:40.189Z"},
        {"id": "wd-632-D2-d", "check": "D2", "severity": "repair", "subject": "tools/hf-trending-models/x.py", "firstSeen": "2026-11-15T00:00:00.000Z"},
        {"id": "wd-632-D18-e", "check": "D18", "severity": "report", "subject": "ARTIFACTS.md", "firstSeen": "2026-11-15T13:48:48.674Z"},
    ]
    repairs = [{"id": "rp-632-f-attribution-docs-check-fixtures", "artifact": "attribution-docs-check-fixtures", "state": "RELEASED"},
               {"id": "rp-632-t-hf-trending-models", "artifact": "hf-trending-models", "state": "PARKED"}]
    to_open, contradictions = watchdog_intake(findings, repairs, now)
    if [x.split(":")[0] for x in to_open] != ["wd-632-D17-b"] or [x.split(":")[0] for x in contradictions] != ["wd-632-D22-a"]:
        bad.append(f"watchdog intake: got {to_open} and {contradictions}")
    # One owner per file kind (HB-067 D): a repairs/ folder with a receipt, its recheck and an honest-failure row is one
    # receipt and no problem here; the honest-failure row is kept_rules.py's, and it finds no problem in it either.
    one_of_each = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "repair-receipts", "one-of-each")
    got = read_receipts(one_of_each, ts("2026-11-22T09:00:00Z"), {"receipts": 0, "byCloseKind": {}, "rechecks": {"held": 0, "recurred": 0, "due": 0}, "problems": []})
    if (got["receipts"], got["problems"], got["rechecks"]["held"]) != (1, [], 1):
        bad.append(f"one file of each kind: got {got['receipts']} receipt(s), {got['problems']}")
    import kept_rules
    rows = [n for n in os.listdir(os.path.join(one_of_each, "repairs")) if n.endswith(".honest-failure.json")]
    if len(rows) != 1 or kept_rules.honest_failure_problems(json.load(open(os.path.join(one_of_each, "repairs", rows[0])))):
        bad.append("the honest-failure row is kept_rules.py's, and valid there")
    total = len(cases) + 6 + 5 + 1 + 3 + 2
    for line in bad:
        print("FAIL", line)
    print(f"repair receipts self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    args, health_dir = sys.argv[1:], None
    if "--health" in args:
        at = args.index("--health")
        if at + 1 >= len(args):
            print(si.Stop(si.EMPTY, "--health", "names no folder").line(), file=sys.stderr)
            sys.exit(si.EXIT_STOP)
        health_dir = args[at + 1]
        args = args[:at] + args[at + 2:]
    if not args:
        print(__doc__)
        sys.exit(2)
    now = datetime.datetime.now(datetime.timezone.utc)
    reports, unread = [], 0
    for repo in args:
        try:
            reports.append(check_agent(repo, now, health_dir))
        except (OSError, ValueError, KeyError, AttributeError, TypeError) as error:
            # A file whose inner shape is wrong beyond what read_* checks: still a named reason, never a traceback.
            unread += 1
            si.stop_line(si.Stop(si.UNPARSEABLE, repo, f"{type(error).__name__}: {error}"))
    print(json.dumps({"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "agents": reports}, indent=2))
    labels.print_lines(reports)
    problems = sum(len(r["problems"]) for r in reports)
    stops = sum(len(r["stops"]) for r in reports)
    print(f"repair receipts: {sum(r['receipts'] for r in reports)} receipts, {problems} problems, {stops} stops in {len(reports)} agents", file=sys.stderr)
    sys.exit(si.EXIT_STOP if unread or stops else 1 if problems else 0)
