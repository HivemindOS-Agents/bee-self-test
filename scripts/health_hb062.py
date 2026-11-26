#!/usr/bin/env python3
"""HB-062's check on the published health files (20 Nov 2026 update, Part 1): a refusal by the HB-043 topic filter is
a policy skip, not a failure, and does not hold an agent's health unless no step of that play ended done within 48 h.

The host classifies; this only reads what it published in bee-scouts/health/<n>.json and says when a file breaks the
rule. Keyless and read-only. Exit 0 only when every file is consistent.

    python3 scripts/health_hb062.py                 # the five active agents, live
    python3 scripts/health_hb062.py 547 1071        # some of them
    python3 scripts/health_hb062.py path/to/547.json
    python3 scripts/health_hb062.py --self-test     # the fixtures only, no network

What a file must hold:
  1. A refusal alone never holds health: no id in `reasons` names a repair whose cause is the filter's whole sentence,
     unless its state is STUCK_AFTER_SKIPS.
  2. A row with state SKIPPED_POLICY is not in `reasons`, has skips listed, and is younger than 48 h from its first skip.
  3. A row with state STUCK_AFTER_SKIPS is in `reasons`, and the file's status is not "ok".
  4. Every entry of `policySkips` has a time, a reason and the filter "hb043:topic", and names a row of `repairs`.
  5. "ok" stands beside no reason; "repairing" or "degraded" names at least one.
"""
import datetime
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labels  # noqa: E402

AGENTS = ["547", "632", "667", "1071", "86"]
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/health/{n}.json"
TOPIC = "it was about hivemindos's own issues or self-tests, not something people outside need"
FILTER = "hb043:topic"
STUCK_HOURS = 48


def is_topic(cause):
    """The filter's whole sentence, anchored; never a substring."""
    return (cause or "").strip().rstrip(".").lower() == TOPIC


def ts(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def check(doc, now):
    """(problems, summary) for one health file."""
    problems = []
    rows = {r.get("id"): r for r in doc.get("repairs") or []}
    reasons = list(doc.get("reasons") or [])
    skips = list(doc.get("policySkips") or [])
    status = doc.get("status")
    # A label in reasons (labels.py: "no_funds" for a funds pause, "host_limit") is not a repair id and names no row
    # (22 Nov 2026 update, section 3 item 5). A funds pause has its own shape: status needs_funding, a funding block.
    funds = [r for r in reasons if labels.kind({"reason": r}) == "funds"]
    if funds and (status != labels.FUNDS_STATUS or labels.funding_state(doc) != labels.FUNDS_STATUS):
        problems.append(f"{funds[0]}: a funds pause needs status {labels.FUNDS_STATUS} and a funding block in that state")
    if status == labels.FUNDS_STATUS and not funds:
        problems.append(f"status {status} names no {labels.FUNDS_REASON} reason")
    for rid in reasons:
        row = rows.get(rid)
        if row is None and labels.kind({"reason": rid}):
            continue
        if row is None:
            problems.append(f"{rid}: named in reasons with no row in repairs")
        elif is_topic(row.get("cause")) and row.get("state") != "STUCK_AFTER_SKIPS":
            problems.append(f"{rid}: a topic refusal holds health as {row.get('state')}")
    for rid, row in rows.items():
        state = row.get("state")
        mine = [s for s in skips if s.get("repair") == rid]
        if state == "SKIPPED_POLICY":
            if rid in reasons:
                problems.append(f"{rid}: SKIPPED_POLICY is named in reasons")
            if not mine:
                problems.append(f"{rid}: SKIPPED_POLICY with no skip listed")
            elif (now - min(ts(s["at"]) for s in mine)).total_seconds() >= STUCK_HOURS * 3600:
                problems.append(f"{rid}: skipped for {STUCK_HOURS} h with no done step, and not STUCK_AFTER_SKIPS")
        if state == "STUCK_AFTER_SKIPS":
            if rid not in reasons:
                problems.append(f"{rid}: STUCK_AFTER_SKIPS is not named in reasons")
            if status == "ok":
                problems.append(f"{rid}: STUCK_AFTER_SKIPS beside status ok")
    for s in skips:
        if not s.get("at") or not s.get("reason") or s.get("filter") != FILTER:
            problems.append(f"a policy skip without its time, reason or filter: {json.dumps(s)[:120]}")
        elif s.get("repair") not in rows:
            problems.append(f"a policy skip names no row: {s.get('repair')}")
    if status == "ok" and reasons:
        problems.append("status ok beside reasons")
    if status in ("repairing", "degraded") and not reasons:
        problems.append(f"status {status} with no reason")
    stuck = [rid for rid, row in rows.items() if row.get("state") == "STUCK_AFTER_SKIPS"]
    return problems, {"agent": str(doc.get("agent")), "status": status, "realBlocks": [r for r in reasons if r not in stuck and not labels.kind({"reason": r})],
                      "stuckAfterSkips": stuck, "policySkips": len(skips), "notices": doc.get("notices") or [], "paused": labels.paused_line([], doc)}


def load(src):
    if os.path.exists(src):
        with open(src) as f:
            return json.load(f)
    with urllib.request.urlopen(urllib.request.Request(RAW.format(n=src), headers={"user-agent": "bee-self-test-health-hb062"}), timeout=20) as r:
        return json.load(r)


def main(argv):
    if "--self-test" in argv:
        return self_test()
    now = datetime.datetime.now(datetime.timezone.utc)
    bad = 0
    for src in argv or AGENTS:
        try:
            problems, summary = check(load(src), now)
        except Exception as error:  # an unreadable file is a fail, said as such
            problems, summary = [f"could not read: {error}"], {"agent": src}
        bad += 1 if problems else 0
        print(json.dumps({**summary, "problems": problems}))
    print("HB-062 health check:", "PASS" if not bad else f"FAIL: {bad} file(s) break the rule")
    return 0 if not bad else 1


def self_test():
    now = datetime.datetime(2026, 11, 20, 13, 25, tzinfo=datetime.timezone.utc)
    sentence = "it was about HivemindOS's own issues or self-tests, not something people outside need"
    rid = "rp-1-s-publish-dataset"

    def skip(at):
        return {"repair": rid, "play": "publish-dataset", "at": at, "reason": sentence, "filter": FILTER}

    def row(state, cause=sentence, **more):
        return {"id": rid, "artifact": "publish-dataset", "kind": "step:publish-dataset", "state": state, "cause": cause, **more}

    def doc(status, reasons, rows, skips=(), **more):
        return {"agent": "1", "status": status, "reasons": list(reasons), "repairs": list(rows), "policySkips": list(skips), **more}

    recent = [skip("2026-11-19T18:03:59.108Z"), skip("2026-11-19T23:41:20.000Z")]
    old = [skip("2026-11-18T10:00:00.000Z"), skip("2026-11-18T15:00:00.000Z")]
    rows_failure = "it described a dataset instead of holding its rows"
    funding = {"state": "needs_funding", "label": "paused: needs funding", "since": "2026-11-21T06:14:08.559Z", "heldPlays": ["publish-dataset", "propose", "research"]}
    cases = [
        # A topic refusal alone: health ok, the skips listed.
        ("topic alone reads ok", doc("ok", [], [row("SKIPPED_POLICY")], recent), 0),
        # What was published on 20 Nov: the refusal parked as a repeated failure and holding health.
        ("a refusal counted as a failure", doc("repairing", [rid], [row("PARKED")]), 1),
        ("a refusal escalated", doc("repairing", [rid], [row("ESCALATED")]), 1),
        # A real publish failure still reads repairing.
        ("a real failure holds", doc("repairing", [rid], [row("PARKED", rows_failure)]), 0),
        # A content cause that only mentions outside is a failure, and may hold.
        ("mentions outside", doc("repairing", [rid], [row("REPAIR_ATTEMPTED", "the rows were about things people outside need, and the card was missing")]), 0),
        ("not the whole sentence", doc("repairing", [rid], [row("PARKED", "Skipped: " + sentence + " and the upload failed")]), 0),
        # 48 h without a done step: it holds again, and must say so.
        ("stuck holds", doc("repairing", [rid], [row("STUCK_AFTER_SKIPS")], old), 0),
        ("stuck but ok", doc("ok", [], [row("STUCK_AFTER_SKIPS")], old), 2),
        ("48 h old and still only skipped", doc("ok", [], [row("SKIPPED_POLICY")], old), 1),
        # A mixed row counts its real failure; its skips are listed beside it.
        ("mixed holds on its real failure", doc("repairing", [rid], [row("REPAIR_ATTEMPTED", rows_failure, counters={"failedAttempts": 1, "policySkips": 2})], recent), 0),
        # A skip row never holds, and a skip always carries its time, reason and filter.
        ("a skip row in reasons", doc("repairing", [rid], [row("SKIPPED_POLICY")], recent), 2),
        ("a skip with no filter", doc("ok", [], [row("SKIPPED_POLICY")], [{**recent[0], "filter": None}]), 1),
        ("repairing with no reason", doc("repairing", [], []), 1),
        # 22 Nov update, section 3 item 5: a funds pause is status "needs_funding" with reasons[0] "no_funds" and a
        # funding block. "no_funds" is a label, not a repair id (667 and 86 on 26 Nov read exactly this way).
        ("a funds pause", doc("needs_funding", ["no_funds"], [row("RELEASED", rows_failure)], funding=funding), 0),
        ("a funds pause beside a real block", doc("needs_funding", ["no_funds", rid], [row("PARKED", rows_failure)], funding=funding), 0),
        ("no_funds with a status that is not needs_funding", doc("repairing", ["no_funds"], [], funding=funding), 1),
        ("no_funds with no funding block", doc("needs_funding", ["no_funds"], []), 1),
        ("needs_funding that does not name no_funds", doc("needs_funding", [], [], funding=funding), 1),
        ("a host limit named in reasons", doc("repairing", ["host_limit"], []), 0),
    ]
    for name, d, want in cases:
        problems, _summary = check(d, now)
        assert len(problems) == want, (name, problems)
    assert check(cases[0][1], now)[1] == {"agent": "1", "status": "ok", "realBlocks": [], "stuckAfterSkips": [], "policySkips": 2, "notices": [], "paused": None}
    assert check(cases[6][1], now)[1]["stuckAfterSkips"] == [rid]
    print(f"self-test: {len(cases) + 2}/{len(cases) + 2} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
