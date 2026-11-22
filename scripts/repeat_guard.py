#!/usr/bin/env python3
"""HB-067 B, second half (22 Nov 2026 update, section 5 B), and HB-068's detector (section 4): no repeat on the same
cause.

A repeat is keyed on the play or tool and its normalised cause, never on the commit: 12 different commits that fail
the same way are 12 tries of one thing. After 2 failures with one key, the 3rd and every later one is reported as one
the guard WOULD HOLD, until something releases the key:

  a changed input   for a runner failure, a commit that changed the tool's folder other than GOAL.md, README.md or
                    the host's SELFTEST_OUTPUT.md; a research receipt, a non-empty commit under tools/<name>/; a
                    LESSONS line names no input, and an unknown input is never read as a changed one
  the named file    a failure that says "missing <file>" is released only when a commit adds that file
  a host fix        one listed with --host-fix SUBJECT=ISO-TIME (no public file records host fixes yet)
  a pass            a runner record that passed between two failures

Three sources, each guarded on its own:
  lessons   every "- Failed:" line LESSONS.md has carried since --since, from its git history ("self-test of tools/"
            lines are the runner's, below)
  runner    this repository's own history of results/hivepunk-<n>/<tool>.json: the tool and the failure's tail
  receipts  research receipts (research/*.json) on the agent's own tool: "tools/x/", "x" and "x standalone ..." are
            one subject; research on a project, a token or another project's tool is not counted

Also:
  misrouted         a LESSONS cause that once went to host_cause routes every later line with it to host_cause; a
                    later line that went elsewhere is listed
  write-never-landed (HB-068) a tool that failed 3 or more times on "missing <file>" while no commit in its agent's
                    repository ever added that file; `hostLimit: true` when no file of that kind was ever committed
                    there. Those failures are the host's: they are shown as "blocked: host limit", not as repeats
  paid after pause  a paid play with a "Failed:" line after the health file's funding.since while its funding.state
                    is needs_funding (labels.py)
Funds rows ("paused: needs funding") and host-limit rows are never failures or repeats; each is its own line per agent.
A rule that held is not a failure either: a line that went to skip, policy_skip or stopped_on_rule, or (before the
host wrote buckets) one that reads "Skipped:", "Stopped on ..." or "That is a stop on a rule", or whose cause once
went to one of those buckets.

    python3 scripts/repeat_guard.py --self-test       # the fixtures only (fixtures/repeat-guard/), no network
    python3 scripts/repeat_guard.py [--since 2026-11-14] [--runner .] [--health-dir DIR] [--host-fix S=T] DIR...
                                                      # clones of hivepunk-<n> with history; health/<n>.json is read
                                                      # live unless --health-dir names a bee-scouts health/ folder

Shadow mode, report-only: it holds nothing. Exit 0 when nothing would be held, 1 when something would, 2 when a clone
could not be read.
"""
import datetime
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import git_history  # noqa: E402
import labels  # noqa: E402
import repair_receipts  # noqa: E402

LIMIT = 2
SINCE = "2026-11-14"
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/health/{n}.json"
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "repeat-guard")
BOILERPLATE = (r"it tries again at the next check-in\.?", r"your agent will try again at its next check-in\.?", r"it will try again at its next check-in\.?",
               r"\b\d+(?:st|nd|rd|th) time running\b", r"went to: \S+")
MISSING = re.compile(r"\bmissing:?\s+[`'\"]?([\w./-]+\.[A-Za-z0-9]{1,8})\b", re.I)
NOT_AN_INPUT = {"goal.md", "readme.md", "selftest_output.md"}
MIN_PREFIX = 16
HELD_BUCKETS = ("skip", "policy_skip", "stopped_on_rule")
HELD_TEXT = re.compile(r"^Skipped:|^Stopped on |That is a stop on a rule")


def normalise(reason):
    """(text, cut short) for a failure's reason: lower case, the host's retry wording, "Nth time running", "Went to",
    links, hashes and numbers taken out. A reason cut short with "…" is matched by its start."""
    s = (reason or "").strip()
    cut = s.endswith("…") or s.endswith("...")
    s = s.rstrip("…").rstrip(".").lower() if cut else s.lower()
    for pattern in BOILERPLATE:
        s = re.sub(pattern, " ", s)
    s = re.sub(r"https?://\S+", " ", s)
    s = re.sub(r"\b[0-9a-f]{7,64}\b", " ", s)
    s = re.sub(r"\d+(?:[.,]\d+)?", " ", s)
    s = re.sub(r"\s+", " ", s).strip(" .·:;,-")
    return s, cut


def same(a, b):
    """Two normalised causes are one when they are equal, or when one was cut short and the two agree for as long as
    the shorter one goes (the longer line may say more after the words the shorter one stops at)."""
    if a[0] == b[0]:
        return True
    n = min(len(a[0]), len(b[0]))
    return (a[1] or b[1]) and n >= MIN_PREFIX and a[0][:n] == b[0][:n]


def keyed(failures):
    """[{subject, cause, cut, items}] with each failure under its key, oldest first."""
    keys = []
    for f in sorted(failures, key=lambda f: f["at"]):
        c = normalise(f["cause"])
        for k in keys:
            if k["subject"] == f["subject"] and same((k["cause"], k["cut"]), c):
                if k["cut"] and not c[1]:
                    k["cause"], k["cut"] = c
                k["items"].append(f)
                break
        else:
            keys.append({"subject": f["subject"], "cause": c[0], "cut": c[1], "items": [f]})
    return keys


def named_file(cause):
    m = MISSING.search(cause or "")
    return os.path.basename(m.group(1)).lower() if m else None


class Releases:
    """What releases a held key, read from the agent's commits, the runner's passes and the host fixes."""

    def __init__(self, commits=(), passes=(), host_fixes=()):
        self.commits, self.passes, self.host_fixes = list(commits), list(passes), list(host_fixes)

    def __call__(self, source, subject, cause, after, before):
        window = [c for c in self.commits if after < c["at"] <= before]
        for s, at in self.host_fixes:
            if s == subject and after < at <= before:
                return "host fix"
        name = named_file(cause)
        if name:
            under = f"tools/{subject}/" if source == "runner" else ""
            if any(st != "D" and p.startswith(under) and os.path.basename(p).lower() == name for c in window for st, p in c["files"]):
                return "the named file appeared"
            return None
        if source == "runner" and any(p["tool"] == subject and after < p["at"] < before for p in self.passes):
            return "a pass"
        if source in ("runner", "receipts"):
            for c in window:
                if any(p.startswith(f"tools/{subject}/") and os.path.basename(p).lower() not in NOT_AN_INPUT for _, p in c["files"]):
                    return "a changed input"
        return None


def guard(failures, source, released=None):
    """Each key's tries and the dispatches the guard would hold."""
    released = released or Releases()
    out = []
    for k in keyed(failures):
        run, held, releases = [], [], []
        for f in k["items"]:
            if run:
                why = released(source, k["subject"], f["cause"], run[-1]["at"], f["at"])
                if why:
                    releases.append({"at": f["at"].strftime("%Y-%m-%dT%H:%M:%SZ"), "by": why})
                    run = []
            run.append(f)
            if len(run) > LIMIT:
                held.append(f)
        out.append({"subject": k["subject"], "cause": k["cause"] + ("…" if k["cut"] else ""), "tries": len(k["items"]), "held": held, "releases": releases,
                    "first": k["items"][0]["at"], "last": k["items"][-1]["at"], "hostCause": any(i.get("bucket") == "host_cause" for i in k["items"])})
    return out


def misrouted(failures):
    """LESSONS lines whose cause once went to host_cause and that later went somewhere else."""
    found = []
    for k in keyed(failures):
        host = None
        for f in k["items"]:
            if f.get("bucket") == "host_cause":
                host = host or f["at"]
            elif host and f.get("bucket"):
                found.append({"subject": k["subject"], "cause": k["cause"], "at": f["at"].strftime("%Y-%m-%dT%H:%M:%SZ"), "wentTo": f["bucket"],
                              "hostCauseSince": host.strftime("%Y-%m-%dT%H:%M:%SZ")})
    return found


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def guard_view(failures, released=None, source=None):
    """One source's view: funds and host-limit rows out first, then the repeats of what is left."""
    if source is None:
        source = failures[0]["source"] if failures else "lessons"
    held_rule = {id(i) for k in keyed(failures) if any(i.get("bucket") in HELD_BUCKETS for i in k["items"]) for i in k["items"]}
    kept = [f for f in failures if id(f) not in held_rule and f.get("bucket") not in HELD_BUCKETS and not HELD_TEXT.search(f.get("cause") or "")]
    counted, funds, host = labels.split(kept, text=lambda f: f.get("row", f))
    keys = guard(counted, source, released)
    would = [{"subject": k["subject"], "cause": k["cause"], "tries": k["tries"], "wouldHold": len(k["held"]), "heldFrom": stamp(k["held"][0]["at"]),
              "first": stamp(k["first"]), "last": stamp(k["last"]), "releases": k["releases"], "routeTo": "host_cause" if k["hostCause"] else "agent"}
             for k in keys if k["held"]]
    return {"failures": len(counted), "keys": len(keys), "wouldHold": would, "misrouted": misrouted(counted) if source == "lessons" else [],
            "paused": labels.paused_line(funds, at=lambda f: f["at"]), "blocked": labels.blocked_line(host, at=lambda f: f["at"]),
            "fundsRows": len(funds), "hostLimitRows": len(host), "rulesThatHeld": len(failures) - len(kept)}


# ------------------------------------------------------------------------------------------------------------- the sources
def lesson_failures(text):
    """LESSONS.md text to failures: {source, subject (the play), cause, at, bucket, line}."""
    out = []
    for f in repair_receipts.lessons(text):
        out.append({"source": "lessons", "subject": f["play"], "cause": f["reason"], "at": f["at"], "bucket": f["bucket"], "line": f["line"], "row": f["line"]})
    return out


def lesson_history(repo, since=SINCE):
    """Every "- Failed:" line LESSONS.md has carried since `since`, one per play and minute, as its newest version."""
    out = git_history.git(repo, "log", "-p", "--first-parent", "--since", since, "--format=", "--", "LESSONS.md")
    added = [line[1:] for line in out.splitlines() if line.startswith("+- Failed:")]
    seen, found = set(), []
    for f in lesson_failures("\n".join(added)):
        key = (f["subject"], f["at"])
        if key not in seen:
            seen.add(key)
            found.append(f)
    return found


def key_line(tail):
    lines = [l.strip() for l in (tail or "").splitlines() if l.strip()]
    for l in lines:
        if re.search(r"\bFAIL|Error\b|Exception\b|\bmissing\b", l):
            return l
    return lines[-1] if lines else "(no output)"


def runner_failures(runs):
    return [{"source": "runner", "subject": r["tool"], "cause": key_line(r.get("tail")), "at": r["at"], "row": r} for r in runs if r.get("result") == "failure"]


def runner_history(runner_repo, n, since=SINCE):
    """This repository's records of hivepunk-<n>'s runs since `since`, one per tool and run time, from its history."""
    log = git_history.git(runner_repo, "log", "--since", since, "--format=%x01%H", "--name-only", "--", f"results/hivepunk-{n}/")
    specs, commit = [], None
    for line in log.splitlines():
        if line.startswith("\x01"):
            commit = line[1:]
        elif line.endswith(".json") and commit:
            specs.append(f"{commit}:{line}")
    seen, runs = set(), []
    for spec, text in git_history.show_many(runner_repo, specs).items():
        try:
            r = json.loads(text or "")
        except ValueError:
            continue
        if not r.get("tool") or not r.get("at") or (r["tool"], r["at"]) in seen:
            continue
        seen.add((r["tool"], r["at"]))
        runs.append({**r, "at": git_history.ts(r["at"])})
    return sorted(runs, key=lambda r: r["at"])


def subject_of(subject):
    """"tools/x/", "x", "x standalone ..." and "Something (tools/x/)" are all x."""
    s = (subject or "").strip()
    m = re.search(r"tools/([A-Za-z0-9._-]+)", s)
    if m:
        return m.group(1).strip("/").lower()
    return s.split()[0].strip("/").lower() if s.split() else ""


def receipt_failures(receipts, own):
    """Research receipts on the agent's own tool. own: the names of its tools (ever in tools/, or named tools/<x>)."""
    out = []
    for r in receipts:
        name = subject_of(r.get("subject"))
        if name and name in own:
            out.append({"source": "receipts", "subject": name, "cause": "research on its own tool, nothing built under tools/", "at": r["at"], "row": r})
    return out


def receipt_history(repo, since=SINCE, commits=None):
    """Every version of research/*.json written since `since` whose subjectKind is tool: {subject, at, path}."""
    specs = []
    for c in commits if commits is not None else git_history.commits(repo, since, ["research/"]):
        if c["at"] < git_history.ts(since + "T00:00:00Z"):
            continue
        specs += [f"{c['h']}:{p}" for st, p in c["files"] if st in ("A", "M") and p.startswith("research/") and p.endswith(".json")]
    seen, found = set(), []
    for spec, text in git_history.show_many(repo, specs).items():
        try:
            r = json.loads(text or "")
        except ValueError:
            continue
        if r.get("kind") != "research-receipt" or r.get("subjectKind") != "tool" or not r.get("at") or r["at"] in seen:
            continue
        seen.add(r["at"])
        found.append({"subject": r.get("subject"), "at": git_history.ts(r["at"]), "path": spec.split(":", 1)[1], "status": r.get("status"), "reason": r.get("reason")})
    return sorted(found, key=lambda r: r["at"])


def own_tools(commits, receipts=()):
    names = {p.split("/")[1].lower() for c in commits for _, p in c["files"] if p.startswith("tools/") and p.count("/") >= 2}
    names |= {m.group(1).strip("/").lower() for r in receipts for m in [re.search(r"tools/([A-Za-z0-9._-]+)", r.get("subject") or "")] if m}
    return names


def write_never_landed(runs, commits, shallow=False):
    """HB-068: a tool that failed 3+ times on "missing <file>" while no commit ever added that file."""
    ever = {os.path.basename(p).lower() for c in commits for st, p in c["files"] if st == "A"}
    kinds = {os.path.splitext(p)[1].lower() for c in commits for st, p in c["files"] if st == "A" and os.path.splitext(p)[1]}
    groups = {}
    for r in runs:
        if r.get("result") != "failure":
            continue
        name = named_file(key_line(r.get("tail")))
        if name:
            groups.setdefault((r["tool"], name), []).append(r)
    found = []
    for (tool, name), rows in sorted(groups.items()):
        if len(rows) < 3 or name in ever:
            continue
        kind = os.path.splitext(name)[1].lower()
        found.append({"tool": tool, "file": name, "fails": len(rows), "first": stamp(min(r["at"] for r in rows)), "last": stamp(max(r["at"] for r in rows)),
                      "hostLimit": None if shallow else kind not in kinds, "kind": kind,
                      "why": ("no history to say" if shallow else f"no {kind} file was ever committed in this repository" if kind not in kinds else f"{kind} files were committed, never this one")})
    return found


def runner_view(runs, commits, released=None, shallow=False):
    """The runner's view, with HB-068's detector first: the failures of a write that never landed on a file kind the
    repository never had are the host's limit, not the agent's repeats."""
    found = write_never_landed(runs, commits, shallow)
    limited = {(f["tool"], f["file"]) for f in found if f["hostLimit"]}
    marked = [dict(r, hostLimit=True) if (r.get("tool"), named_file(key_line(r.get("tail")))) in limited else r for r in runs]
    view = guard_view(runner_failures(marked), released=released, source="runner")
    view["writeNeverLanded"] = found
    return view


def read_health(n, health_dir=None):
    if health_dir:
        return json.load(open(os.path.join(health_dir, f"{n}.json")))
    with urllib.request.urlopen(urllib.request.Request(RAW.format(n=n), headers={"User-Agent": "bee-self-test"}), timeout=30) as response:
        return json.load(response)


def check_agent(repo, runner_repo, since, health_dir=None, host_fixes=()):
    n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
    git_history.prefetch(repo, since, ["LESSONS.md", "research/"])
    commits = git_history.commits(repo)
    shallow = git_history.is_shallow(repo)
    runs = runner_history(runner_repo, n, since)
    released = Releases(commits, [r for r in runs if r.get("result") == "success"], [(s, t) for s, t in host_fixes])
    lessons = lesson_history(repo, since)
    receipts = receipt_history(repo, since, commits)
    try:
        health = read_health(n, health_dir)
    except (OSError, ValueError):
        health = None
    views = {"lessons": guard_view(lessons, released=released, source="lessons"),
             "runner": runner_view(runs, commits, released, shallow),
             "receipts": guard_view(receipt_failures(receipts, own_tools(commits, receipts)), released=released, source="receipts")}
    funds = [r for v in views.values() for r in [v.get("paused")] if r]
    blocked = [r for v in views.values() for r in [v.get("blocked")] if r]
    paid = labels.paid_after_pause(lessons, health)
    return {"agent": n, "since": since, "shallow": shallow, "health": None if health is None else {"status": health.get("status"), "funding": labels.funding_state(health)},
            "sources": views, "paidAfterPause": [f["line"][:160] for f in paid],
            "paused": labels.paused_line([f for f in lessons if labels.kind(f["line"]) == "funds"], health, at=lambda f: f["at"]) if funds or labels.funding_state(health) == labels.FUNDS_STATUS else None,
            "blocked": "; ".join(blocked) if blocked else None}


# ---------------------------------------------------------------------------------------------------------------- fixtures
def load(name):
    return open(os.path.join(FIXTURES, name), encoding="utf-8").read()


def fixture_runs(name):
    return [{**r, "at": git_history.ts(r["at"])} for r in json.loads(load(name))]


def fixture_commits(name):
    return [{**c, "at": git_history.ts(c["at"]), "files": [tuple(f) for f in c["files"]]} for c in json.loads(load(name))]


def self_test():
    bad = []
    T = git_history.ts
    # Normalising a cause.
    for name, a, b, want in [
        ("the retry wording and the count", "No proposal this time: its answer could not be read (cut off or not JSON). It tries again at the next check-in.",
         "No proposal this time: its answer could not be read (cut off or not JSON).", True),
        ("the other retry wording", "The research could not finish. Your agent will try again at its next check-in.", "The research could not finish.", True),
        ("numbers, links and hashes", "FAIL: 3 of 5 rows at https://x.test/a differ from 8d354ee4c2", "FAIL: 4 of 9 rows at https://y.test/b differ from 0a1b2c3d4e", True),
        ("a reason cut short matches by its start", "No dataset this time: it was about HivemindOS's own issues or self-tests, not something people outside need. Nothing was published. That is a stop on a rule, a finished outcome: its next dataset is o…",
         "No dataset this time: it was about HivemindOS's own issues or self-tests, not something people outside need. Nothing was published. That is a stop on a rule, a finished outcome: its next dataset is on another topic.", True),
        ("two different causes", "Nothing came of it: the search found no pages.", "Nothing came of it this time.", False),
    ]:
        if same(normalise(a), normalise(b)) != want:
            bad.append(f"{name}: {normalise(a)} vs {normalise(b)}")
    # 667's LESSONS.md as it stood at 09:40 UTC 22 Nov 2026 (25 lines).
    view = guard_view(lesson_failures(load("LESSONS-667.md")), source="lessons")
    got = sorted((w["subject"], w["tries"], w["wouldHold"], w["routeTo"]) for w in view["wouldHold"])
    want = [("agents", 6, 4, "agent"), ("propose", 5, 3, "host_cause"), ("publish-dataset", 5, 3, "agent"), ("research", 6, 4, "agent")]
    if got != want:
        bad.append(f"667's repeats: got {got}")
    if (view["failures"], view["fundsRows"]) != (22, 3) or view["paused"] != "paused: needs funding (since 2026-11-22 00:16 UTC, 2 plays held)":
        bad.append(f"667's funds rows: {view['failures']} counted, {view['fundsRows']} funds, {view['paused']}")
    if [(m["subject"], m["wentTo"]) for m in view["misrouted"]] != [("propose", "repair")] * 4:
        bad.append(f"667's propose went to host_cause on 16 Nov, then 4 times to repair: got {view['misrouted']}")
    # 86's: research cut off went to host_cause on 19 Nov and to repair on 21 Nov.
    view = guard_view(lesson_failures(load("LESSONS-86.md")), source="lessons")
    if [(m["subject"], m["at"]) for m in view["misrouted"]] != [("research", "2026-11-21T04:06:00Z")]:
        bad.append(f"86's misrouted research: got {view['misrouted']}")
    if [(w["subject"], w["tries"], w["wouldHold"]) for w in view["wouldHold"]] != [("propose", 3, 1)]:
        bad.append(f"86's propose x3: got {view['wouldHold']}")
    # 547's runner: 12 failures on one missing .patch, 12 commits, 10 would be held; GOAL.md and README.md edits and a
    # self_test.py edit do not release a failure that names its missing file.
    runs, commits = fixture_runs("runner-547.json"), fixture_commits("commits-547.json")
    view = runner_view(runs, commits, Releases(commits))
    found = view["writeNeverLanded"]
    if [(f["tool"], f["file"], f["fails"], f["hostLimit"]) for f in found] != [("fixprotocol-modifyliquidities-nonreentrant", "modifyliquidities-nonreentrant.patch", 12, True)]:
        bad.append(f"547's write that never landed: got {found}")
    if view["wouldHold"] or view["failures"] or not (view["blocked"] or "").startswith("blocked: host limit (since 2026-11-21 03:11 UTC, 1 held"):
        bad.append(f"547's 12 are the host's limit, not repeats: {view['failures']} failures, {view['wouldHold']}, {view['blocked']}")
    plain = guard_view(runner_failures(runs), released=Releases(commits), source="runner")
    if [(w["tries"], w["wouldHold"], w["heldFrom"]) for w in plain["wouldHold"]] != [(12, 10, "2026-11-21T10:00:04Z")]:
        bad.append(f"547's 12 as repeats, before the detector: got {plain['wouldHold']}")
    # The named file appearing releases it; a .patch committed once before means it is not the host's file-kind limit.
    landed = commits + [{"h": "p1", "at": T("2026-11-21T11:00:00Z"), "subject": "x", "files": [("A", "tools/fixprotocol-modifyliquidities-nonreentrant/modifyLiquidities-nonReentrant.patch")]}]
    again = guard_view(runner_failures(runs), released=Releases(landed), source="runner")
    if [(w["wouldHold"], [r["by"] for r in w["releases"]]) for w in again["wouldHold"]] != [(8, ["the named file appeared"])]:
        bad.append(f"the named file appearing releases the key: got {again['wouldHold']}")
    other = commits + [{"h": "p0", "at": T("2026-10-30T00:00:00Z"), "subject": "x", "files": [("A", "tools/old/fix.patch")]}]
    if [f["hostLimit"] for f in write_never_landed(runs, other)] != [False] or write_never_landed(runs[:2], commits):
        bad.append("a kind committed before is not a host limit, and 2 failures are not yet a finding")
    # A failure that names no file: an edit to self_test.py releases it, an edit to GOAL.md does not, and a pass does.
    tool = "x"
    fail = lambda t: {"tool": tool, "at": T(t), "tail": "FAIL: clean sample: expected 0 issues, got 1", "result": "failure"}
    runs2 = [fail(f"2026-11-21T0{h}:00:00Z") for h in range(1, 7)]
    edits = [{"h": "g", "at": T("2026-11-21T02:30:00Z"), "subject": "x", "files": [("M", "tools/x/GOAL.md")]},
             {"h": "s", "at": T("2026-11-21T04:30:00Z"), "subject": "x", "files": [("M", "tools/x/self_test.py")]}]
    got = guard_view(runner_failures(runs2), released=Releases(edits), source="runner")["wouldHold"]
    if [(w["wouldHold"], w["heldFrom"], [r["by"] for r in w["releases"]]) for w in got] != [(2, "2026-11-21T03:00:00Z", ["a changed input"])]:
        bad.append(f"a self_test.py edit releases, a GOAL.md edit does not: got {got}")
    got = guard_view(runner_failures(runs2), released=Releases([], [{"tool": tool, "at": T("2026-11-21T03:30:00Z")}]), source="runner")["wouldHold"]
    if [w["wouldHold"] for w in got] != [2]:
        bad.append(f"a pass between failures releases: got {got}")
    got = guard_view(runner_failures(runs2), released=Releases([], [], [(tool, T("2026-11-21T02:30:00Z"))]), source="runner")["wouldHold"]
    if [(w["wouldHold"], w["heldFrom"]) for w in got] != [(2, "2026-11-21T05:00:00Z")]:
        bad.append(f"a host fix releases: got {got}")
    # 632's research receipts on card-fixtures-checker, 19-21 Nov: one subject under four spellings, held from the 3rd.
    receipts = [{**r, "at": T(r["at"])} for r in json.loads(load("receipts-632.json"))]
    tools632 = own_tools(fixture_commits("commits-632.json"), receipts)
    view = guard_view(receipt_failures(receipts, tools632), source="receipts")
    if [(w["subject"], w["tries"], w["wouldHold"], w["heldFrom"]) for w in view["wouldHold"]] != [("card-fixtures-checker", 12, 10, "2026-11-20T07:02:47Z")]:
        bad.append(f"632's card-fixtures-checker research: got {view['wouldHold']}")
    if "fastify-decorators" in tools632 or view["failures"] != 14:
        bad.append(f"another project's tool is not its own: {sorted(tools632)[:5]}, {view['failures']}")
    built = fixture_commits("commits-632.json") + [{"h": "b", "at": T("2026-11-20T12:00:00Z"), "subject": "x", "files": [("A", "tools/card-fixtures-checker/checker.py")]}]
    got = guard_view(receipt_failures(receipts, tools632), released=Releases(built), source="receipts")["wouldHold"]
    if [(w["subject"], w["wouldHold"]) for w in got if w["subject"] == "card-fixtures-checker"] != [("card-fixtures-checker", 2 + 6)]:
        bad.append(f"a commit under tools/card-fixtures-checker/ releases: got {got}")
    # Labels: a funds row and a host-limit row are never repeats (labels.py runs the full contract).
    funds = [{"source": "lessons", "subject": "propose", "cause": "it had no funds to pay for its thinking call (the service answered 402)", "at": T(f"2026-11-22T0{h}:00:00Z"), "line": "Went to: no_funds"} for h in range(1, 5)]
    if guard_view(funds, source="lessons")["wouldHold"]:
        bad.append("funds rows are never repeats")
    skips = [{"source": "lessons", "subject": "propose", "cause": "Skipped: it already opened its bee-scouts issue today.", "at": T(f"2026-11-17T0{h}:00:00Z")} for h in range(1, 5)]
    skips += [{"source": "lessons", "subject": "publish-dataset", "cause": "No dataset this time: it was about HivemindOS's own issues. Nothing was published. That is a stop on a rule, a finished outcome: its next dataset is o…", "at": T(f"2026-11-18T0{h}:00:00Z"), "bucket": "policy_skip"} for h in range(1, 5)]
    skips += [{"source": "lessons", "subject": "publish-dataset", "cause": "No dataset this time: it was about HivemindOS's own issues. Nothing was published.", "at": T(f"2026-11-16T0{h}:00:00Z")} for h in range(1, 4)]
    view = guard_view(skips, source="lessons")
    if view["wouldHold"] or view["rulesThatHeld"] != 11:
        bad.append(f"a rule that held is not a repeat: got {view['wouldHold']}")
    total = 5 + 3 + 2 + 2 + 1 + 1 + 1 + 3 + 2 + 1 + 1 + 1
    for line in bad:
        print("FAIL", line)
    print(f"repeat guard self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    since, runner, health_dir, fixes, repos = SINCE, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."), None, [], []
    it = iter(argv)
    for a in it:
        if a == "--since":
            since = next(it)
        elif a == "--runner":
            runner = next(it)
        elif a == "--health-dir":
            health_dir = next(it)
        elif a == "--host-fix":
            s, _, t = next(it).partition("=")
            fixes.append((s, git_history.ts(t)))
        else:
            repos.append(a)
    if not repos:
        print(__doc__)
        return 2
    reports, unread = [], 0
    for repo in repos:
        try:
            reports.append(check_agent(repo, runner, since, health_dir, fixes))
        except (OSError, ValueError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
    print(json.dumps({"since": since, "limit": LIMIT, "mode": "shadow", "agents": reports}, indent=2, default=str))
    held = sum(len(v["wouldHold"]) for r in reports for v in r["sources"].values())
    dispatches = sum(w["wouldHold"] for r in reports for v in r["sources"].values() for w in v["wouldHold"])
    agent = sum(1 for r in reports for v in r["sources"].values() for w in v["wouldHold"] if w["routeTo"] == "agent")
    mis = sum(len(r["sources"]["lessons"]["misrouted"]) for r in reports)
    landed = sum(len(r["sources"]["runner"]["writeNeverLanded"]) for r in reports)
    paid = sum(len(r["paidAfterPause"]) for r in reports)
    for r in reports:
        for name, v in r["sources"].items():
            for w in v["wouldHold"]:
                print(f"hivepunk-{r['agent']} {name}: {w['subject']} x{w['tries']} on \"{w['cause'][:70]}\", {w['wouldHold']} would be held from {w['heldFrom']} ({w['routeTo']})", file=sys.stderr)
    labels.print_lines(reports)
    print(f"repeat guard: {held} repeated causes ({agent} the agent's), {dispatches} dispatches would be held, {mis} misrouted lines, {landed} writes that never landed, "
          f"{paid} paid plays after a funding pause, in {len(reports)} agents", file=sys.stderr)
    return 2 if unread else 1 if held or mis or landed or paid else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
