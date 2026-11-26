#!/usr/bin/env python3
"""HB-074: a scheduled workflow that has not run within its period plus a grace is flagged.

GitHub starts this repository's scheduled runs hours late (host-checks, cron 06:40, ran at 14:54 UTC on 22 Nov 2026), so
the grace is 12 hours: a run inside it is late by GitHub's habit, not missing.

Manual-only (24 Nov 2026 update, row 39, guard 129): a workflow with no `schedule:` trigger is never timed, and is
never counted as observed. One that the agents service dispatches (`repository_dispatch`: self-test, rescore) is
`dispatched`. Any other with no run in 14 days must say so in its name, `name: <name> (manual-only)`, which is what the
Actions list shows a reader: it is then `manual_only`. One with no run in 14 days and no label is `unlabelled_manual`,
and a label on a workflow that has a schedule is `label_contradicts_schedule`; both are problems.

    python3 scripts/workflow_age.py --self-test                # the fixtures only, no network
    python3 scripts/workflow_age.py OWNER/REPO [WORKFLOW_DIR]  # needs GH_TOKEN for the Actions API

A run of any event counts as a run: a dispatch that did the work is the work done. States: ok, not_due_yet, late (it ran
before, not within its period plus the grace), late_never_ran (due, past the grace, and no run ever), unsupported (a cron
this reader cannot time), and for a workflow with no schedule dispatched, manual_only, unlabelled_manual or
label_contradicts_schedule. Exit 0: none late and no label problem. 1: one is. 2: something could not be read.
"""
import datetime as dt
import glob
import json
import os
import re
import subprocess
import sys

GRACE = dt.timedelta(hours=12)
CRON = re.compile(r"""^\s*-\s*cron:\s*["']([^"']+)["']""", re.M)
NAME = re.compile(r"^name:\s*(.+?)\s*$", re.M)
DISPATCHED = re.compile(r"^\s*repository_dispatch\s*:", re.M)
LABEL = "(manual-only)"
MANUAL_DAYS = 14
UTC = dt.timezone.utc


def parse_time(text):
    return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def iso(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None


def cron_shape(expr):
    """(minute, hour, weekday or None) for a daily or weekly cron, else None. Cron weekdays: 0 or 7 is Sunday."""
    parts = expr.split()
    if len(parts) != 5 or parts[2] != "*" or parts[3] != "*" or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    if parts[4] == "*":
        return int(parts[0]), int(parts[1]), None
    return (int(parts[0]), int(parts[1]), int(parts[4]) % 7) if parts[4].isdigit() else None


def last_due(shape, now):
    """The newest time this cron was due at or before `now`."""
    minute, hour, weekday = shape
    when = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if weekday is None:
        return when if when <= now else when - dt.timedelta(days=1)
    when -= dt.timedelta(days=((when.weekday() + 1) % 7 - weekday) % 7)
    return when if when <= now else when - dt.timedelta(days=7)


def first_due(shape, added):
    """The first time this cron was due after the workflow was added."""
    period = dt.timedelta(days=1 if shape[2] is None else 7)
    return last_due(shape, added) + period


def state_of(expr, added, last_run, now):
    """One schedule's state. `added`: when the workflow file first landed. `last_run`: its newest run of any event."""
    shape = cron_shape(expr)
    if not shape:
        return {"state": "unsupported", "cron": expr}
    due = last_due(shape, now)
    out = {"cron": expr, "lastDue": iso(due), "lastRun": iso(last_run)}
    if first_due(shape, added) > now - GRACE:
        return {**out, "state": "not_due_yet" if not last_run or last_run < due else "ok"}
    # The newest slot whose grace has ended must have a run at or after it.
    settled = due if due <= now - GRACE else due - dt.timedelta(days=1 if shape[2] is None else 7)
    if last_run and last_run >= settled:
        return {**out, "state": "ok"}
    return {**out, "state": "late" if last_run else "late_never_ran"}


def manual_state(name, has_schedule, dispatched, last_run, now):
    """Row 39, guard 129: the state of a workflow's label, or None for a scheduled one with no label."""
    labelled = name.endswith(LABEL)
    if has_schedule:
        return {"state": "label_contradicts_schedule"} if labelled else None
    if dispatched and not labelled:
        return {"state": "dispatched", "lastRun": iso(last_run)}
    if labelled:
        return {"state": "manual_only", "lastRun": iso(last_run)}
    if last_run and last_run >= now - dt.timedelta(days=MANUAL_DAYS):
        return {"state": "ran_lately", "lastRun": iso(last_run)}
    return {"state": "unlabelled_manual", "lastRun": iso(last_run)}


PROBLEMS = ("late", "late_never_ran", "unlabelled_manual", "label_contradicts_schedule")


def gh(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, check=True, timeout=60, text=True)
    return json.loads(out.stdout)


def newest_run(repo, name):
    runs = gh(f"repos/{repo}/actions/workflows/{name}/runs?per_page=1").get("workflow_runs") or []
    return parse_time(runs[0]["created_at"]) if runs else None


def added_at(path):
    folder, base = os.path.split(path)
    out = subprocess.run(["git", "-C", folder, "log", "--diff-filter=A", "--format=%cI", "--", base], capture_output=True, check=True, timeout=30, text=True)
    lines = out.stdout.split()
    return dt.datetime.fromisoformat(lines[-1]).astimezone(UTC) if lines else None


def self_test():
    bad = []

    def want(label, got, state):
        if got["state"] != state:
            bad.append(f"{label}: got {got}")

    t = lambda s: parse_time(s)
    weekly, daily = "35 4 * * 1", "40 6 * * *"  # bazaar-weekly's and host-checks' own crons
    added = t("2026-11-16T14:56:23Z")
    # bazaar-weekly: added Mon 16 Nov after its slot, first due Mon 23 Nov 04:35.
    want("before its first slot", state_of(weekly, added, None, t("2026-11-22T12:00:00Z")), "not_due_yet")
    want("10:07 on its first day is inside GitHub's delay", state_of(weekly, added, None, t("2026-11-23T10:07:00Z")), "not_due_yet")
    want("past the grace with no run ever", state_of(weekly, added, None, t("2026-11-23T16:36:00Z")), "late_never_ran")
    want("ran late on its first day", state_of(weekly, added, t("2026-11-23T13:00:00Z"), t("2026-11-23T16:36:00Z")), "ok")
    want("a push run before its first slot is not that slot's run", state_of(weekly, added, added, t("2026-11-23T16:36:00Z")), "late")
    # host-checks: 8 hours late is fine; a whole day missed is not.
    old = t("2026-11-01T00:00:00Z")
    want("8 h late", state_of(daily, old, t("2026-11-22T14:54:10Z"), t("2026-11-23T10:00:00Z")), "ok")
    want("a day missed", state_of(daily, old, t("2026-11-21T14:54:10Z"), t("2026-11-23T10:00:00Z")), "late")
    want("a dispatch counts as the run", state_of(daily, old, t("2026-11-23T07:00:00Z"), t("2026-11-23T20:00:00Z")), "ok")
    want("a cron it cannot time says so", state_of("*/15 * * * *", old, None, t("2026-11-23T10:00:00Z")), "unsupported")
    if iso(last_due(cron_shape("0 8 * * 0"), t("2026-11-23T10:00:00Z"))) != "2026-11-22T08:00:00Z":
        bad.append("weekday 0 is Sunday")
    if iso(last_due(cron_shape("0 8 * * 7"), t("2026-11-23T10:00:00Z"))) != "2026-11-22T08:00:00Z":
        bad.append("weekday 7 is Sunday")
    # Row 39, guard 129, on this repository's own cases of 24 Nov 2026.
    now = t("2026-11-26T12:00:00Z")
    for label, got, state in [
        ("skill-lift, never run and unlabelled", manual_state("skill-lift", False, False, None, now), "unlabelled_manual"),
        ("no run in 14 days and no label", manual_state("memory-reads", False, False, t("2026-11-09T18:21:16Z"), now), "unlabelled_manual"),
        ("labelled, it is manual_only and never observed", manual_state("skill-lift (manual-only)", False, False, None, now), "manual_only"),
        ("a run inside 14 days is not yet manual", manual_state("verify-sources", False, False, t("2026-11-15T12:21:24Z"), now), "ran_lately"),
        ("the agents service dispatches it", manual_state("rescore", False, True, t("2026-11-26T11:18:13Z"), now), "dispatched"),
        ("a label on a scheduled workflow", manual_state("host-checks (manual-only)", True, False, None, now), "label_contradicts_schedule"),
    ]:
        want(label, got, state)
    if manual_state("host-checks", True, False, None, now) is not None:
        bad.append("a scheduled workflow with no label is timed, not labelled")
    total = 18
    for line in bad:
        print("FAIL:", line)
    print(f"workflow age self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if not argv:
        print(__doc__)
        return 2
    repo, folder = argv[0], argv[1] if len(argv) > 1 else ".github/workflows"
    now, rows, unread = dt.datetime.now(UTC), [], 0
    for path in sorted(glob.glob(os.path.join(folder, "*.yml"))):
        text = open(path, encoding="utf-8").read()
        crons = CRON.findall(text)
        name = os.path.basename(path)
        title = (NAME.search(text).group(1).strip("\"'") if NAME.search(text) else name)
        if not crons:
            try:
                last = newest_run(repo, name)
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                unread += 1
                print(f"could not read {name}: {error}", file=sys.stderr)
                continue
            rows.append({"workflow": name, "name": title, **manual_state(title, False, bool(DISPATCHED.search(text)), last, now)})
            continue
        labelled = manual_state(title, True, False, None, now)
        if labelled:
            rows.append({"workflow": name, "name": title, **labelled})
        try:
            added, last = added_at(path), newest_run(repo, name)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            unread += 1
            print(f"could not read {name}: {error}", file=sys.stderr)
            continue
        if added is None:
            unread += 1
            print(f"could not date {name}", file=sys.stderr)
            continue
        rows += [{"workflow": name, **state_of(expr, added, last, now)} for expr in crons]
    print(json.dumps({"at": iso(now), "graceHours": GRACE.total_seconds() / 3600, "workflows": rows}, indent=2))
    late = [r for r in rows if r["state"] in PROBLEMS]
    for r in late:
        print(f"{r['workflow']}: {r['state']} (cron {r.get('cron')}, due {r.get('lastDue')}, last run {r.get('lastRun')})", file=sys.stderr)
    timed = [r for r in rows if "cron" in r]
    manual = [r["workflow"] for r in rows if r["state"] == "manual_only"]
    print(f"workflow age: {sum(1 for r in late if 'cron' in r)} late of {len(timed)} schedules; "
          f"{len(manual)} manual-only, never counted as observed ({', '.join(manual) or 'none'}); "
          f"{sum(1 for r in late if 'cron' not in r)} label problems", file=sys.stderr)
    return 2 if unread else 1 if late else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
