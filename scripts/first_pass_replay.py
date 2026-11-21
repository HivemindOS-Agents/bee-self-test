#!/usr/bin/env python3
"""HB-058's replay (first passing patch): work a proof bundle's `firstPass` record out again from the build steps it
lists, and say when a build ended failed although an earlier step had passed.

A bundle is one build step's record. It is written once and never rewritten, so it speaks for its build up to its own
step (`asOfStep`), never after it. Outcomes:
  shipped-final      the step's self-test passed: this patch stands shipped
  shipped-revert     an earlier passing step was restored, tested again and passed
  never-passed       no step has passed
  failed-after-pass  this step failed after an earlier one passed. Not an end: the agent's next step may pass, and
                     after 12 idle hours the host restores the passing step (`revertTo`, `revertNotBefore`)
  final-failed       a restore was tried and failed its own self-test: nothing is shipped

Keyless and read-only. Exit 0 only when every bundle read is consistent and no build is left failed past its time.

    python3 scripts/first_pass_replay.py DIR [DIR ...]   # folders holding proofs/prf-*.json (cloned agent repos)
    python3 scripts/first_pass_replay.py --self-test     # the fixtures only

What is checked:
  1. A bundle that lists `steps`: firstPassStep, shippedStep, shippedCommit, outcome and revertTo worked out from the
     steps match what it says.
  2. Its fields agree with its outcome (a shipped outcome names a step and a commit; an unshipped one names neither).
  3. A tool's newest bundle is not left at failed-after-pass more than 12 h past its `revertNotBefore` (a restore that
     never came), and none says final-failed without a `revertOf` step when it lists steps.
An older bundle of the same tool that says failed-after-pass or final-failed while a newer one shipped is counted, not
failed: the build went on.
"""
import datetime
import glob
import json
import os
import sys

LATE_HOURS = 12


def first_pass(steps):
    """The record a list of steps gives: the same rule as the host's (core agent-first-pass.ts)."""
    steps = sorted(steps, key=lambda s: s["step"])
    first = next((s for s in steps if s["state"] == "passed"), None)
    out = {"firstPassStep": first["step"] if first else None, "shippedStep": None, "shippedCommit": None, "revertTo": None}
    if not steps or not first:
        return {**out, "outcome": "never-passed"}
    last = steps[-1]
    if last["state"] == "passed":
        reverted = last.get("revertOf") is not None
        return {**out, "shippedStep": last["revertOf"] if reverted else last["step"], "shippedCommit": last.get("commit"),
                "outcome": "shipped-revert" if reverted else "shipped-final"}
    if last.get("revertOf") is not None:
        return {**out, "outcome": "final-failed"}
    passed = [s for s in steps if s["state"] == "passed" and s["step"] < last["step"]]
    return {**out, "outcome": "failed-after-pass", "revertTo": passed[-1]["step"] if passed else None}


def check_bundle(doc):
    """Problems of one bundle's firstPass record ([] when it has none or is consistent)."""
    fp = doc.get("firstPass")
    if not fp:
        return []
    problems = []
    outcome = fp.get("outcome")
    shipped = outcome in ("shipped-final", "shipped-revert")
    if shipped and (fp.get("shippedStep") is None or not fp.get("shippedCommit")):
        problems.append(f"{outcome} names no shipped step or commit")
    if not shipped and (fp.get("shippedStep") is not None or fp.get("shippedCommit")):
        problems.append(f"{outcome} names a shipped step")
    if outcome == "never-passed" and fp.get("firstPassStep") is not None:
        problems.append("never-passed with a first pass step")
    if outcome != "never-passed" and fp.get("firstPassStep") is None:
        problems.append(f"{outcome} with no first pass step")
    steps = fp.get("steps")
    if steps:
        want = first_pass(steps)
        for key in ("firstPassStep", "shippedStep", "shippedCommit", "outcome"):
            if want[key] != fp.get(key):
                problems.append(f"replay: {key} is {fp.get(key)!r}, the steps give {want[key]!r}")
        if want["outcome"] == "failed-after-pass" and want["revertTo"] != fp.get("revertTo"):
            problems.append(f"replay: revertTo is {fp.get('revertTo')!r}, the steps give {want['revertTo']!r}")
        if fp.get("asOfStep") != max(s["step"] for s in steps):
            problems.append("asOfStep is not its last listed step")
    return problems


def ts(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def scan(docs, now):
    """(problems, summary) for every bundle given: each one's own record, then each tool's newest."""
    problems, counts, moved_on = [], {}, 0
    by_tool = {}
    for doc in docs:
        fp = doc.get("firstPass")
        if not fp:
            continue
        counts[fp.get("outcome")] = counts.get(fp.get("outcome"), 0) + 1
        for p in check_bundle(doc):
            problems.append(f"{doc.get('id')}: {p}")
        by_tool.setdefault((doc.get("agent"), doc.get("artifact")), []).append(doc)
    for (agent, tool), group in sorted(by_tool.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        group.sort(key=lambda d: d.get("at") or "")
        newest = group[-1]
        moved_on += sum(1 for d in group[:-1] if d["firstPass"].get("outcome") in ("failed-after-pass", "final-failed"))
        fp = newest["firstPass"]
        if fp.get("outcome") == "failed-after-pass":
            due = fp.get("revertNotBefore")
            if due and (now - ts(due)).total_seconds() > LATE_HOURS * 3600:
                problems.append(f"{newest.get('id')}: failed after a pass and not restored {LATE_HOURS} h past {due}")
        if fp.get("outcome") == "final-failed" and not fp.get("steps"):
            # Written before 21 Nov 2026, when a failed step after a pass was also called final-failed.
            if (now - ts(newest.get("at") or "1970-01-01T00:00:00Z")).total_seconds() > 2 * LATE_HOURS * 3600:
                problems.append(f"{newest.get('id')}: the tool's newest bundle says final-failed and nothing shipped after it")
    return problems, {"bundlesWithFirstPass": sum(counts.values()), "outcomes": counts, "tools": len(by_tool), "olderFailedStepsTheBuildMovedPast": moved_on}


def load(dirs):
    docs = []
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "proofs", "prf-*.json"))):
            try:
                with open(path) as f:
                    docs.append(json.load(f))
            except Exception as error:  # an unreadable bundle is said, never skipped silently
                docs.append({"id": os.path.basename(path), "firstPass": {"outcome": f"unreadable: {error}"}})
    return docs


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if not argv:
        print(__doc__)
        return 2
    problems, summary = scan(load(argv), datetime.datetime.now(datetime.timezone.utc))
    print(json.dumps(summary))
    for p in problems:
        print("PROBLEM", p)
    print("HB-058 first-pass replay:", "PASS" if not problems else f"FAIL: {len(problems)} problem(s)")
    return 0 if not problems else 1


def self_test():
    c = lambda n: str(n) * 40
    step = lambda n, state, **more: {"step": n, "state": state, "commit": c(n)[:40], "tree": None, "checkSha256": None, **more}
    n = 0
    # The spec's six fixtures (18 Nov 2026, HB-058 section 9), on the rule itself.
    assert first_pass([step(1, "failed"), step(2, "passed"), step(3, "failed")]) == {"firstPassStep": 2, "shippedStep": None, "shippedCommit": None, "revertTo": 2, "outcome": "failed-after-pass"}; n += 1
    assert first_pass([step(1, "failed"), step(2, "passed"), step(3, "failed"), step(4, "passed", revertOf=2)])["outcome"] == "shipped-revert"; n += 1
    assert first_pass([step(1, "failed"), step(2, "passed"), step(3, "failed"), step(4, "passed", revertOf=2)])["shippedStep"] == 2; n += 1
    assert first_pass([step(1, "failed"), step(2, "failed"), step(3, "passed")]) == {"firstPassStep": 3, "shippedStep": 3, "shippedCommit": c(3)[:40], "revertTo": None, "outcome": "shipped-final"}; n += 1
    assert first_pass([step(1, "failed"), step(2, "failed")])["outcome"] == "never-passed"; n += 1
    assert first_pass([step(1, "passed"), step(2, "failed"), step(3, "failed", revertOf=1)])["outcome"] == "final-failed"; n += 1
    assert first_pass([step(1, "passed"), step(2, "passed"), step(3, "failed")])["revertTo"] == 2; n += 1  # the latest passing step

    def bundle(steps, at="2026-11-19T12:42:53Z", bid="prf-1-tool-aaaaaaa", **over):
        want = first_pass(steps)
        fp = {"firstPassStep": want["firstPassStep"], "shippedStep": want["shippedStep"], "shippedCommit": want["shippedCommit"], "outcome": want["outcome"],
              "asOfStep": max(s["step"] for s in steps), "steps": steps}
        if want["outcome"] == "failed-after-pass":
            fp["revertTo"] = want["revertTo"]
            fp["revertNotBefore"] = "2026-11-20T00:58:00.000Z"
        fp.update(over)
        return {"id": bid, "agent": "1", "artifact": "tools/tool", "at": at, "firstPass": fp}

    failed = [step(1, "failed"), step(2, "passed"), step(3, "failed")]
    assert check_bundle(bundle(failed)) == []; n += 1
    # A bundle that says something its own steps do not give is caught.
    assert len(check_bundle(bundle(failed, outcome="shipped-final", shippedStep=3, shippedCommit=c(3)[:40]))) == 3; n += 1
    assert check_bundle(bundle(failed, firstPassStep=1)) == ["replay: firstPassStep is 1, the steps give 2"]; n += 1
    assert check_bundle(bundle(failed, revertTo=1)) == ["replay: revertTo is 1, the steps give 2"]; n += 1
    assert check_bundle({"id": "x", "firstPass": {"firstPassStep": 2, "shippedStep": None, "shippedCommit": None, "outcome": "shipped-final"}}) == ["shipped-final names no shipped step or commit"]; n += 1
    assert check_bundle({"id": "x"}) == []; n += 1
    now = datetime.datetime(2026, 11, 21, 3, 0, tzinfo=datetime.timezone.utc)
    # 1071 on 19 Nov: a failed step after a pass, and its next step shipped 33 minutes later. Counted, not a problem.
    old = {"id": "prf-1071-glb-fixture-byte-layouts-bcd63e1", "agent": "1071", "artifact": "tools/glb-fixture-byte-layouts", "at": "2026-11-19T12:42:53Z",
           "firstPass": {"firstPassStep": 2, "shippedStep": None, "shippedCommit": None, "outcome": "final-failed"}}
    newer = {"id": "prf-1071-glb-fixture-byte-layouts-0300656", "agent": "1071", "artifact": "tools/glb-fixture-byte-layouts", "at": "2026-11-19T13:15:48Z",
             "firstPass": {"firstPassStep": 2, "shippedStep": 9, "shippedCommit": c(9)[:40], "outcome": "shipped-final"}}
    problems, summary = scan([old, newer], now)
    assert problems == [] and summary["olderFailedStepsTheBuildMovedPast"] == 1; n += 1
    # The same old bundle as the tool's newest, a day later: nothing shipped after it.
    assert len(scan([old], now)[0]) == 1; n += 1
    # A failed step after a pass, newest for its tool: fine inside its time, a problem 12 h past it with no restore.
    assert scan([bundle(failed)], datetime.datetime(2026, 11, 20, 6, 0, tzinfo=datetime.timezone.utc))[0] == []; n += 1
    assert len(scan([bundle(failed)], now)[0]) == 1; n += 1
    # Restored and passed: the newest bundle says shipped-revert, and the older failed one is counted.
    restored = failed + [step(4, "passed", revertOf=2)]
    problems, summary = scan([bundle(failed), bundle(restored, at="2026-11-20T01:10:00Z", bid="prf-1-tool-bbbbbbb")], now)
    assert problems == [] and summary["outcomes"] == {"failed-after-pass": 1, "shipped-revert": 1}; n += 1
    print(f"self-test: {n}/{n} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
