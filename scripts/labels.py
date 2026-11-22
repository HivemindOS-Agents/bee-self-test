#!/usr/bin/env python3
"""The two labels every host check reads the same way (22 Nov 2026 update, sections 3 and 4): a step that did not run
because its agent had no funds, and a step the host's own limits stopped. Neither is the agent's failure.

  paused: needs funding   status "needs_funding", reason "no_funds". In LESSONS.md: a line that went to `no_funds`,
                          or says "had no funds to pay for" or "(the service answered 402)", and the lines under a
                          "## Paused: needs funding" header.
  blocked: host limit     status or reason "host_limit", or `hostLimit: true`. In LESSONS.md: a line that says the
                          host did not commit a file ("is not committed by the host", "over the per-commit file limit").

Every reader that counts failures or repeats (repair_receipts.py's counter check, rule_stops.py, kept_rules.py,
repeat_guard.py and its write-landed detector) takes these rows out before it counts, and prints each label on its
own line per agent. This file is the one place the two are recognised; the readers import it.

    python3 scripts/labels.py --self-test     # the predicate, and the contract: one funds-paused case and one
                                              # host-limit case through every reader, 0 failures, 0 repeat flags,
                                              # 1 "paused: needs funding" and 1 "blocked: host limit"

A health file's `funding` block (`state`, `since`, `heldPlays`, ...) is new and may not be there yet: no block means
not paused. A paid play (propose, research, publish-dataset) that has a "Failed:" line after `funding.since` while
`funding.state` is "needs_funding" was dispatched with no funds, and is listed by `paid_after_pause`.
"""
import datetime
import re
import sys

FUNDS_STATUS, FUNDS_REASON, FUNDS_LABEL = "needs_funding", "no_funds", "paused: needs funding"
HOST_LIMIT, HOST_LIMIT_LABEL = "host_limit", "blocked: host limit"
FUNDS_HEADER = "Paused: needs funding"
PAID_PLAYS = ("propose", "research", "publish-dataset")
FUNDS_TEXT = re.compile(r"Went to: no_funds\b|had no funds to pay for|\(the service answered 402\)|paused: needs funding|\bneeds_funding\b", re.I)
HOST_TEXT = re.compile(r"Went to: host_limit\b|blocked: host limit|\bhost_limit\b|is not committed by the host|over the per-commit file limit", re.I)
FIELDS = ("status", "reason", "label", "bucket", "rule", "routeTo", "outcome", "state")
TEXTS = ("line", "tail", "reason", "why", "text", "cause", "title")


def _of_text(text):
    if FUNDS_TEXT.search(text):
        return "funds"
    if HOST_TEXT.search(text):
        return "host_limit"
    return None


def kind(row):
    """"funds", "host_limit" or None, for a LESSONS line (a string) or a record (a dict: a run row, a step record, a
    health repair, a stop, an honest-failure row)."""
    if row is None:
        return None
    if isinstance(row, str):
        return _of_text(row)
    if row.get("section") == FUNDS_HEADER:
        return "funds"
    for field in FIELDS:
        value = str(row.get(field) or "").strip().lower()
        if value in (FUNDS_STATUS, FUNDS_REASON, FUNDS_LABEL) or value.startswith(FUNDS_REASON + ":"):
            return "funds"
        if value in (HOST_LIMIT, HOST_LIMIT_LABEL) or value.startswith(HOST_LIMIT + ":"):
            return "host_limit"
    if row.get("hostLimit") is True:
        return "host_limit"
    for field in TEXTS:
        value = row.get(field)
        if isinstance(value, dict):
            value = value.get("text")
        if isinstance(value, str) and _of_text(value):
            return _of_text(value)
    rounds = row.get("rounds")
    if isinstance(rounds, list) and rounds:
        kinds = {_of_text(str(r.get("cause") or "")) for r in rounds}
        if len(kinds) == 1 and None not in kinds:
            return kinds.pop()
    return None


def counts_as_failure(row):
    """A row the failure counts and repeat flags may see: not funds, not a host limit, not marked countsAsFailure: false."""
    if kind(row):
        return False
    return not (isinstance(row, dict) and row.get("countsAsFailure") is False)


def split(rows, text=None):
    """(counted, funds, host_limit). text(row) picks what to read from a row, when it is not the row itself."""
    counted, funds, host = [], [], []
    for row in rows:
        k = kind(text(row) if text else row)
        if k is None and isinstance(row, dict) and row.get("countsAsFailure") is False:
            continue
        (funds if k == "funds" else host if k == "host_limit" else counted).append(row)
    return counted, funds, host


def lessons_header(text):
    """The plays listed under a "## Paused: needs funding" header in LESSONS.md, as [{"line", "section"}]."""
    out, section = [], None
    for line in (text or "").splitlines():
        head = re.match(r"^##\s+(.*)$", line)
        if head:
            section = head.group(1).strip()
            continue
        if section and section.lower() == FUNDS_HEADER.lower() and line.startswith("- "):
            out.append({"line": line.strip(), "section": FUNDS_HEADER})
    return out


def _stamp(value):
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return str(value)[:16].replace("T", " ") + " UTC" if value else None


def _play(row):
    if isinstance(row, dict):
        return row.get("play") or row.get("subject") or row.get("tool") or row.get("rule") or row.get("line")
    return row


def paused_line(rows, health=None, at=lambda r: r.get("at") if isinstance(r, dict) else None):
    """'paused: needs funding (since ..., N plays held)', or None when nothing is paused. A health file's funding block,
    when there is one, is what the line says; otherwise the funds rows are."""
    funding = (health or {}).get("funding") or {}
    if funding.get("state") == FUNDS_STATUS:
        held = funding.get("heldPlays")
        n = len(held) if isinstance(held, (list, dict)) else int(held or 0)
        return f"{FUNDS_LABEL} (since {_stamp(funding.get('since')) or 'unknown'}, {n} plays held)"
    if not rows:
        return None
    times = sorted(t for t in (at(r) for r in rows) if t is not None)
    plays = {_play(r) for r in rows}
    return f"{FUNDS_LABEL} (since {_stamp(times[0]) if times else 'unknown'}, {len(plays)} plays held)"


def blocked_line(rows, at=lambda r: r.get("at") if isinstance(r, dict) else None):
    """'blocked: host limit (since ..., N held: a, b)', or None."""
    if not rows:
        return None
    times = sorted(t for t in (at(r) for r in rows) if t is not None)
    held = sorted({str(_play(r)) for r in rows})
    return f"{HOST_LIMIT_LABEL} (since {_stamp(times[0]) if times else 'unknown'}, {len(held)} held: {', '.join(h[:60] for h in held[:5])})"


def funding_state(health):
    """The health file's funding state, or None when it has no funding block (not paused)."""
    return ((health or {}).get("funding") or {}).get("state")


def paid_after_pause(failures, health):
    """Paid plays with a "Failed:" line after the health file's funding.since while funding.state is needs_funding.
    failures: [{"play", "at" (datetime), "line"}]."""
    funding = (health or {}).get("funding") or {}
    if funding.get("state") != FUNDS_STATUS or not funding.get("since"):
        return []
    since = datetime.datetime.fromisoformat(str(funding["since"]).replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
    return [f for f in failures if f.get("play") in PAID_PLAYS and f.get("at") and f["at"] > since]


def print_lines(reports, out=sys.stderr):
    """Each agent's paused and blocked line, on a line of its own."""
    for r in reports:
        for key in ("paused", "blocked"):
            if r.get(key):
                print(f"hivepunk-{r.get('agent')}: {r[key]}", file=out)


# ---------------------------------------------------------------------------------------------------------------- fixtures
FUNDS_LINE = ("- Failed: Propose a fix or an improvement · Reason: No proposal this time: it had no funds to pay for its thinking call "
              "(the service answered 402). It tries again at the next check-in. · 2026-11-22 {t} UTC · Went to: no_funds")
HOST_LINE = ("- Failed: Build a small tool in its own repository · Reason: tools/x/fix.patch was not committed: file kind .patch is not "
             "committed by the host. Retrying the same file will not land it. · 2026-11-22 {t} UTC · Went to: host_cause")


def contract():
    """One funds-paused case and one host-limit case, each written three times with the same cause so that a reader
    which counted them would flag a repeat, through every reader. Returns the failures."""
    import kept_rules
    import repair_receipts
    import repeat_guard
    import rule_stops
    bad = []
    ts = repair_receipts.ts
    times = ("00:16", "03:20", "06:26")
    text = "\n".join(["# Lessons", "", "## Failures", ""] + [FUNDS_LINE.format(t=t) for t in times] + [HOST_LINE.format(t=t) for t in times])

    def expect(reader, failures, repeats, view):
        paused = [view.get("paused")] if view.get("paused") else []
        blocked = [view.get("blocked")] if view.get("blocked") else []
        got = (failures, repeats, len(paused), len(blocked), all(p.startswith(FUNDS_LABEL) for p in paused), all(b.startswith(HOST_LIMIT_LABEL) for b in blocked))
        if got != (0, 0, 1, 1, True, True):
            bad.append(f"{reader}: {failures} failures, {repeats} repeat flags, paused {paused}, blocked {blocked}")

    # repair_receipts.py: an open step repair of propose and build-tool whose counters stand before the six lines.
    health = {"repairs": [{"id": f"rp-1-s-{p}", "kind": f"step:{p}", "state": "OPEN", "lastObservedAt": "2026-11-21T00:00:00.000Z"} for p in ("propose", "build-tool")]}
    view = repair_receipts.lesson_view(health, repair_receipts.lessons(text), ts("2026-11-22T09:00:00Z"))
    expect("repair_receipts", view["failures"], len(view["problems"]), view)
    # rule_stops.py: three stops on no_funds and three on host_limit, each on one folder, within 24 hours.
    at = lambda t: ts(f"2026-11-22T{t}:00Z")
    stops = [{"at": at(t), "path": f"work/f-{t}.md", "rule": "no_funds", "why": "no funds for its paid call", "folder": None} for t in times]
    stops += [{"at": at(t), "path": f"work/h-{t}.md", "rule": "host_limit", "why": "file kind .patch is not committed by the host", "folder": "tools/x"} for t in times]
    view = rule_stops.stop_view(stops, [], [])
    expect("rule_stops", len(view["counted"]), len(view["findings"]), view)
    # kept_rules.py: an honest-failure row whose rounds are funds refusals, and one whose rounds are host limits.
    rounds = lambda cause: [{"round": n, "at": f"2026-11-22T0{n}:00:00.000Z", "run": f"https://x/runs/{n}", "cause": cause} for n in (1, 2, 3)]
    rows = [{"kind": "honest-failure", "tool": "a", "rounds": rounds("it had no funds to pay for its thinking call (the service answered 402)")},
            {"kind": "honest-failure", "tool": "x", "rounds": rounds("tools/x/fix.patch was not committed: file kind .patch is not committed by the host")}]
    view = kept_rules.honest_view(rows)
    expect("kept_rules", len(view["honestFailures"]), 0, view)
    # repeat_guard.py, each of its three sources and its write-landed detector.
    lines = repeat_guard.lesson_failures(text)
    view = repeat_guard.guard_view(lines)
    expect("repeat_guard LESSONS", view["failures"], len(view["wouldHold"]), view)
    runs = [{"tool": "a", "at": at(t), "tail": "it had no funds to pay for its thinking call (the service answered 402)", "result": "failure"} for t in times]
    runs += [{"tool": "x", "at": at(t), "tail": "FAIL: missing fix.patch", "result": "failure", "status": HOST_LIMIT} for t in times]
    view = repeat_guard.guard_view(repeat_guard.runner_failures(runs))
    expect("repeat_guard runner", view["failures"], len(view["wouldHold"]), view)
    receipts = [{"subject": "a", "at": at(t), "status": FUNDS_STATUS} for t in times] + [{"subject": "x", "at": at(t), "reason": HOST_LIMIT} for t in times]
    view = repeat_guard.guard_view(repeat_guard.receipt_failures(receipts, {"a", "x"}))
    expect("repeat_guard receipts", view["failures"], len(view["wouldHold"]), view)
    # The write-landed detector: three failures on a missing .patch in a repository that never committed one are the
    # host's limit, with no status written on them; three funds refusals beside them are a pause.
    commits = [{"h": "c1", "at": at("00:00"), "subject": "x: self_test.py", "files": [("A", "tools/x/self_test.py")]}]
    missing = [{"tool": "x", "at": at(t), "tail": "FAIL: missing fix.patch", "result": "failure"} for t in times]
    view = repeat_guard.runner_view(runs[:3] + missing, commits)
    if [f["hostLimit"] for f in view["writeNeverLanded"]] != [True]:
        bad.append(f"write-landed detector: got {view['writeNeverLanded']}")
    expect("repeat_guard write-landed", view["failures"], len(view["wouldHold"]), view)
    return bad, 6


def self_test():
    bad = []
    at = datetime.datetime(2026, 11, 22, 6, 26, tzinfo=datetime.timezone.utc)
    cases = [
        ("a line that went to no_funds", FUNDS_LINE.format(t="06:26"), "funds"),
        ("the wording alone, before buckets", "- Failed: Research a token, protocol or project · Reason: Nothing came of it: it had no funds to pay for the search. · 2026-11-22 06:27 UTC", "funds"),
        ("a 402 said in brackets", "Nothing came of it (the service answered 402).", "funds"),
        ("a host-limit line", HOST_LINE.format(t="06:26"), "host_limit"),
        ("a line that went to host_cause for another reason", "- Failed: Propose a fix or an improvement · Reason: its answer could not be read (cut off or not JSON). · 2026-11-16 00:19 UTC · Went to: host_cause", None),
        ("an ordinary failure", "- Failed: Research a token, protocol or project · Reason: Nothing came of it: the search found no pages. · 2026-11-21 06:14 UTC · Went to: repair", None),
        ("a run row with the machine fields", {"status": "needs_funding", "reason": "no_funds", "label": FUNDS_LABEL, "countsAsFailure": False}, "funds"),
        ("a held play in a health file", {"state": "precondition_unmet", "reason": "no_funds: balance 0 < quote 12000"}, "funds"),
        ("a host-limit step record", {"status": "host_limit", "reason": "file kind .patch is not committed"}, "host_limit"),
        ("a detector finding", {"tool": "x", "hostLimit": True}, "host_limit"),
        ("a runner record that failed", {"tool": "x", "result": "failure", "tail": "FAIL: missing x.patch"}, None),
        ("a line under the Paused header", {"line": "- Propose a fix or an improvement: held", "section": FUNDS_HEADER}, "funds"),
    ]
    for name, row, want in cases:
        if kind(row) != want:
            bad.append(f"{name}: got {kind(row)}, want {want}")
    if counts_as_failure({"result": "failure", "countsAsFailure": False}) or not counts_as_failure({"result": "failure"}):
        bad.append("countsAsFailure: false is honoured, and a plain failure counts")
    header = lessons_header("# Lessons\n\n## Paused: needs funding\n\n- Propose a fix or an improvement: held since 2026-11-22 00:16 UTC\n- Research a token, protocol or project: held\n\n## Failures\n\n- Failed: x\n")
    if [kind(h) for h in header] != ["funds", "funds"]:
        bad.append(f"the Paused header: got {header}")
    rows = [{"play": "propose", "at": at}, {"play": "research", "at": at + datetime.timedelta(minutes=1)}, {"play": "propose", "at": at - datetime.timedelta(hours=6)}]
    if paused_line(rows) != "paused: needs funding (since 2026-11-22 00:26 UTC, 2 plays held)":
        bad.append(f"the paused line from rows: got {paused_line(rows)}")
    health = {"funding": {"state": "needs_funding", "since": "2026-11-22T00:16:00Z", "heldPlays": ["propose", "research", "publish-dataset", "agents"]}}
    if paused_line([], health) != "paused: needs funding (since 2026-11-22 00:16 UTC, 4 plays held)" or paused_line([], {}) is not None:
        bad.append(f"the paused line from a health file: got {paused_line([], health)}")
    if funding_state({"status": "repairing"}) is not None:
        bad.append("no funding block is not paused")
    failures = [{"play": "propose", "at": at}, {"play": "agents", "at": at}, {"play": "research", "at": at - datetime.timedelta(hours=7)}]
    if [f["play"] for f in paid_after_pause(failures, health)] != ["propose"] or paid_after_pause(failures, {"funding": {"state": "ok", "since": "2026-11-22T00:16:00Z"}}):
        bad.append(f"paid plays after a pause: got {paid_after_pause(failures, health)}")
    got = blocked_line([{"tool": "x", "at": at}])
    if got != "blocked: host limit (since 2026-11-22 06:26 UTC, 1 held: x)":
        bad.append(f"the blocked line: got {got}")
    contract_bad, contract_n = contract()
    bad += contract_bad
    total = len(cases) + 7 + contract_n
    for line in bad:
        print("FAIL", line)
    print(f"labels self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    print(__doc__)
    sys.exit(2)
