#!/usr/bin/env python3
"""One rule for every live read in this repository's workflows: report-only has a date, and a failure is never swallowed.

25 Nov 2026 update, row 41r1 (inside HB-087r1, with HB-074r1 and HB-083r1): host-checks.yml carried 17 lines that ended
in `|| echo "report-only, exit $?"`, so a live check could stay report-only for ever and nothing in the file said until
when. Now each live step runs through this script, which records the step's exit, and the job's last step gives one
verdict from shadow.json, the file that already holds each observing check's lifecycle (HB-067 A):

  exit 0                                        ok
  exit 2 or more (a STOP: an input that could not be read, or a security finding)   fails the run, always
  exit 1, the check not in shadow.json          fails the run: a check with no lifecycle is enforced
  exit 1, its lifecycle observing and today on or before its decideBy (or an extend's)   reported, does not fail
  exit 1, past that date with no decision       fails the run: the planned switch to blocking happens on the date
                                                (HB-074r1, HB-065's 28 Nov, L52's 30 Nov) unless the host records
                                                an extend, with a reason, in shadow.json
  exit 1, decision enforce                      fails the run
  any exit, decision retired                    fails the run: a retired check no longer runs here
  an input recorded as unread                   fails the run (an agent repository that could not be cloned)
  no live step recorded at all                  fails the run

It is a CI rule: it fails a workflow run, which blocks the dev's merge and tells the team. It never stops an agent.

    python3 scripts/live_gate.py run ID -- COMMAND...    # run a live check; its output as it comes, its exit recorded
    python3 scripts/live_gate.py unread ID WHAT          # an input of check ID could not be read
    python3 scripts/live_gate.py verdict [--shadow shadow.json] [--today YYYY-MM-DD]
    python3 scripts/live_gate.py lint WORKFLOW.yml...    # see below
    python3 scripts/live_gate.py --self-test

The record is $LIVE_GATE, else $RUNNER_TEMP/live-gate.jsonl. `run` exits 0 itself, so the live steps after it still say
where the agents stand; only `verdict` decides.

lint (required in CI) fails a workflow file that:
  - swallows a check's failure: `|| echo`, `|| true`, `|| :` or `|| exit 0` on a line that runs a script or a test,
    or `continue-on-error: true` anywhere (an exit captured with `|| code=$?` and then acted on is not swallowed);
  - uses an action by a tag or a branch: every `uses:` names a 40-hex commit SHA, with its version in a comment
    (HB-071 E, widened in the 23 Nov v4 update, section 6).
A line that does either on purpose carries the comment `# lint-allowed: <why>` and is listed in the lint's output,
never silently passed: rescore's re-run, whose REPRODUCED, DIFFERENT or UNABLE is the record it writes, and
skill-lift's download of a run's artifact, which is absent when the run made none and is then said in the next step.
"""
import datetime
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OBSERVING = ("prose", "partly", "observe", "shadow", "report-only")
SHA_PIN = re.compile(r"^\s*-?\s*uses:\s*([^@\s]+)@([0-9a-f]{40})\s*(#.*)?$")
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
SWALLOW = re.compile(r"\|\|\s*(?:echo\b|true\b|:(?:\s|$)|exit\s+0\b)")
RUNS_CHECK = re.compile(r"\bpython3?\s+(?:-I\s+)?(?:\S*scripts/|-m\s+unittest\b|\S*tests/)")
CONTINUE = re.compile(r"^\s*continue-on-error\s*:\s*(?!false\b)\S")
ALLOWED = re.compile(r"#\s*lint-allowed:\s*\S")


def ledger_path():
    return os.environ.get("LIVE_GATE") or os.path.join(os.environ.get("RUNNER_TEMP") or ".", "live-gate.jsonl")


def record(entry, path=None):
    with open(path or ledger_path(), "a", encoding="utf-8") as out:
        out.write(json.dumps(entry, sort_keys=True) + "\n")


def run(check, command, path=None):
    """Run COMMAND, its output straight through, and record its exit under CHECK."""
    if not command:
        print(f"live gate: {check}: no command", file=sys.stderr)
        record({"check": check, "exit": 2, "why": "no command"}, path)
        return 0
    try:
        code = subprocess.run(command).returncode
    except OSError as error:
        print(f"live gate: {check}: could not start: {error}", file=sys.stderr)
        code = 2
    record({"check": check, "exit": code}, path)
    print(f"live gate: {check}: exit {code} (recorded; the last step decides from shadow.json)")
    return 0


def day(text):
    return datetime.date.fromisoformat(str(text)[:10])


def lifecycles(shadow):
    return {c["id"]: c for c in shadow.get("checks") or [] if isinstance(c, dict) and c.get("id")}


def decide(check, code, entry, today):
    """(fails, why) for one recorded exit."""
    if code == 0:
        if entry and any(d.get("decision") == "retired" for d in entry.get("decisions") or []):
            return True, "retired in shadow.json, and still runs here: remove its step"
        return False, "ok"
    if code >= 2 or code < 0:
        return True, f"exit {code}: a STOP or a finding, which is never report-only"
    if entry is None:
        return True, "exit 1, and it has no lifecycle in shadow.json: a check with no decide-by date is enforced"
    decisions = entry.get("decisions") or []
    final = [d.get("decision") for d in decisions if d.get("decision") in ("enforce", "retired")]
    if final:
        return True, f"exit 1, and shadow.json records {final[-1]}"
    lc = entry.get("lifecycle") or {}
    extends = [d for d in decisions if d.get("decision") == "extend" and d.get("decideBy")]
    try:
        by = day(extends[-1]["decideBy"] if extends else lc["decideBy"])
    except (KeyError, ValueError, TypeError):
        return True, "exit 1, and its lifecycle has no readable decideBy"
    if lc.get("stage") not in OBSERVING:
        return True, f"exit 1, stage {lc.get('stage')!r} is not an observing stage"
    if today > by:
        return True, f"exit 1, past its decide-by date {by} with no decision: it blocks from that date"
    return False, f"exit 1, report-only until {by} ({entry.get('id')}, stage {lc.get('stage')})"


def verdict(entries, shadow, today):
    """(failures, reports) over the recorded entries."""
    known, fails, reports = lifecycles(shadow), [], []
    if not entries:
        return ["no live step recorded anything: nothing was read"], []
    for e in entries:
        check = str(e.get("check") or "")
        if "unread" in e:
            fails.append(f"{check}: could not read {e['unread']}")
            continue
        try:
            code = int(e.get("exit"))
        except (TypeError, ValueError):
            fails.append(f"{check}: an exit that is not a number ({e.get('exit')!r})")
            continue
        failed, why = decide(check, code, known.get(check), today)
        if failed:
            fails.append(f"{check}: {why}")
        elif code:
            reports.append(f"{check}: {why}")
    return fails, reports


def read_ledger(path):
    if not os.path.exists(path):
        return []
    out = []
    for n, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        if line.strip():
            try:
                e = json.loads(line)
            except ValueError:
                e = {"check": f"line {n}", "exit": "unparseable"}
            out.append(e if isinstance(e, dict) else {"check": f"line {n}", "exit": "unparseable"})
    return out


def lint_text(name, text):
    """(problems, recorded) for one workflow file."""
    problems, recorded = [], []
    for n, raw in enumerate(text.splitlines(), 1):
        allowed = ALLOWED.search(raw)
        line = raw[:allowed.start()] if allowed else raw
        if CONTINUE.search(line) or (SWALLOW.search(line) and RUNS_CHECK.search(line)):
            if allowed:
                recorded.append(f"{name}:{n}: {raw.strip()[:200]}")
            elif CONTINUE.search(line):
                problems.append(f"{name}:{n}: continue-on-error swallows a step's failure")
            else:
                problems.append(f"{name}:{n}: a check's failure is swallowed: {raw.strip()[:160]}")
        used = USES.match(raw)
        if used and not used.group(1).startswith("./") and not SHA_PIN.match(raw):
            problems.append(f"{name}:{n}: action {used.group(1)} is not pinned to a full commit SHA (with its version in a comment)")
        elif used and SHA_PIN.match(raw) and not (SHA_PIN.match(raw).group(3) or "").strip("# "):
            problems.append(f"{name}:{n}: action {used.group(1)} is pinned with no version comment")
    return problems, recorded


SELF_TEST_CASES = 24


def self_test():
    bad = []
    today = day("2026-11-26")
    shadow = {"checks": [
        {"id": "watching", "lifecycle": {"stage": "report-only", "since": "2026-11-23", "decideBy": "2026-11-30"}, "decisions": []},
        {"id": "past", "lifecycle": {"stage": "shadow", "since": "2026-11-12", "decideBy": "2026-11-25"}, "decisions": []},
        {"id": "extended", "lifecycle": {"stage": "shadow", "since": "2026-11-12", "decideBy": "2026-11-25"},
         "decisions": [{"decision": "extend", "at": "2026-11-25", "reason": "one more week of numbers", "decideBy": "2026-12-02"}]},
        {"id": "enforced", "lifecycle": {"stage": "report-only", "since": "2026-11-20", "decideBy": "2026-11-30"}, "decisions": [{"decision": "enforce", "at": "2026-11-25"}]},
        {"id": "retired", "lifecycle": {"stage": "shadow", "since": "2026-11-20", "decideBy": "2026-11-30"}, "decisions": [{"decision": "retired", "at": "2026-11-25"}]},
    ]}
    known = lifecycles(shadow)
    for name, check, code, want in [
        ("a pass is a pass", "watching", 0, False),
        ("report-only before its date", "watching", 1, False),
        ("a STOP is never report-only", "watching", 2, True),
        ("past its date with no decision it blocks (HB-074r1)", "past", 1, True),
        ("an extend with a new date keeps it report-only", "extended", 1, False),
        ("enforce blocks", "enforced", 1, True),
        ("a retired check that still runs fails", "retired", 0, True),
        ("a check with no lifecycle is enforced (41r1)", "unlisted", 1, True),
        ("a crash is not a pass", "watching", -9, True),
    ]:
        got, why = decide(check, code, known.get(check), today)
        if got != want:
            bad.append(f"{name}: got {got} ({why})")
    fails, reports = verdict([], shadow, today)
    if not fails:
        bad.append("nothing recorded must fail: nothing was read")
    fails, reports = verdict([{"check": "x", "unread": "hivepunk-547"}], shadow, today)
    if not fails:
        bad.append("an agent repository that could not be cloned must fail")
    fails, reports = verdict([{"check": "watching", "exit": 1}, {"check": "watching", "exit": 0}], shadow, today)
    if fails or len(reports) != 1:
        bad.append(f"one report-only finding is reported, not failed: {fails} {reports}")
    # The lint, on the shapes it must catch (every one of them was in host-checks.yml before 26 Nov 2026) and on the
    # shapes it must let through.
    sha = "11d5960a326750d5838078e36cf38b85af677262"
    for name, text, want in [
        ("|| echo report-only on a check", '          python3 scripts/opportunities_48h.py || echo "report-only, exit $?"\n', 1),
        ("|| true on a check", "          python3 scripts/verify_claims.py x --json y || true\n", 1),
        ("continue-on-error", "        continue-on-error: true\n", 1),
        ("an action by its tag", "      - uses: actions/checkout@v4\n", 1),
        ("a pin with no version comment", f"      - uses: actions/checkout@{sha}\n", 1),
        ("a pinned action with its version", f"      - uses: actions/checkout@{sha} # v4.4.0\n", 0),
        ("an exit captured and acted on", '          python3 scripts/source_match.py || code=$?\n', 0),
        ("a clone that may fail, not a check", '          git clone --quiet x y || echo "could not read x"\n', 0),
        ("nothing to commit is not a check", """          git commit -m "n: $(python3 -c 'print(1)')" || exit 0\n""", 0),
        ("a test run through unittest", "          python3 -m unittest discover -s tests || true\n", 1),
    ]:
        problems, _ = lint_text("fixture.yml", text)
        if len(problems) != want:
            bad.append(f"lint, {name}: {problems}")
    problems, recorded = lint_text("f.yml", "          python3 scripts/verify_claims.py x --json y || true  # lint-allowed: the result is the record\n"
                                   "        continue-on-error: true  # lint-allowed: absent when the run made none\n")
    if problems or len(recorded) != 2:
        bad.append(f"lint: a line marked lint-allowed is listed, not failed: {problems} {recorded}")
    problems, _ = lint_text("f.yml", "          python3 scripts/verify_claims.py x || true  # lint-allowed:\n")
    if len(problems) != 1:
        bad.append(f"lint: lint-allowed with no reason is not allowed: {problems}")
    total = SELF_TEST_CASES
    for line in bad:
        print("FAIL:", line)
    print(f"live gate self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["run"] and len(argv) >= 2:
        rest = argv[2:]
        if rest[:1] == ["--"]:
            rest = rest[1:]
        return run(argv[1], rest)
    if argv[:1] == ["unread"] and len(argv) == 3:
        record({"check": argv[1], "unread": argv[2]})
        print(f"live gate: {argv[1]}: could not read {argv[2]} (recorded; it fails the run at its last step)", file=sys.stderr)
        return 0
    if argv[:1] == ["verdict"]:
        shadow_path, today = os.path.join(HERE, "..", "shadow.json"), datetime.datetime.now(datetime.timezone.utc).date()
        rest = argv[1:]
        while rest:
            if rest[0] == "--shadow" and len(rest) > 1:
                shadow_path, rest = rest[1], rest[2:]
            elif rest[0] == "--today" and len(rest) > 1:
                today, rest = day(rest[1]), rest[2:]
            else:
                print(__doc__)
                return 2
        try:
            shadow = json.load(open(shadow_path, encoding="utf-8"))
        except (OSError, ValueError) as error:
            print(f"STOP unparseable_security_setting: {shadow_path}: {error}", file=sys.stderr)
            return 2
        fails, reports = verdict(read_ledger(ledger_path()), shadow, today)
        for line in reports:
            print(f"::warning title=report-only::{line}")
        for line in fails:
            print(f"::error title=live gate::{line}")
        print(f"live gate: {len(fails)} failing, {len(reports)} report-only (each with its date in shadow.json)")
        return 1 if fails else 0
    if argv[:1] == ["lint"] and len(argv) > 1:
        problems, recorded = [], []
        for path in argv[1:]:
            p, r = lint_text(os.path.relpath(path), open(path, encoding="utf-8").read())
            problems += p
            recorded += r
        for line in recorded:
            print(f"outcome recorded on purpose: {line}")
        for line in problems:
            print(f"FAIL: {line}")
        print(f"workflow lint: {len(problems)} problems in {len(argv) - 1} files")
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
