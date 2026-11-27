#!/usr/bin/env python3
"""Counts from an outside repository's own test run, for the HiveOS Evidence Lab's outside seed (dev update
2026-11-27 row 134, guard 298). Reads the test output a sandbox wrote to a file and prints the counts only: passed,
failed and total, from the summary line of the runner the repository uses (jest, vitest, node --test, pytest, unittest,
go test). Never prints a line of the output itself: the run's log is public and a non-pass is held for 7 days.

  outside_counts.py OUTPUT_FILE EXIT_CODE   prints JSON {"passed", "failed", "total", "runner"} or {"runner": null}
  outside_counts.py --self-test             the fixtures below

Reads text only; runs nothing."""
import json, re, sys

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def counts(text: str, exit_code: int):
    t = ANSI.sub("", text)
    # jest: "Tests:       2 failed, 41 passed, 43 total"
    # A workspace run prints one summary per package: every one is added up.
    m = re.findall(r"^Tests:\s+(.*?(\d+) total)\s*$", t, re.M)
    if m:
        f = sum(int(x.group(1)) for line, _ in m for x in [re.search(r"(\d+) failed", line)] if x)
        p = sum(int(x.group(1)) for line, _ in m for x in [re.search(r"(\d+) passed", line)] if x)
        return {"passed": p, "failed": f, "total": sum(int(total) for _, total in m), "runner": "jest"}
    # vitest: "      Tests  2 failed | 41 passed (43)"
    m = re.findall(r"^\s*Tests\s+(.*?)\((\d+)\)\s*$", t, re.M)
    if m:
        f = sum(int(x.group(1)) for line, _ in m for x in [re.search(r"(\d+) failed", line)] if x)
        p = sum(int(x.group(1)) for line, _ in m for x in [re.search(r"(\d+) passed", line)] if x)
        return {"passed": p, "failed": f, "total": sum(int(total) for _, total in m), "runner": "vitest"}
    # node --test: "ℹ tests 43" / "ℹ pass 41" / "ℹ fail 2" (or "# tests 43" in TAP)
    tests = re.findall(r"^[ℹ#] tests (\d+)$", t, re.M); passed = re.findall(r"^[ℹ#] pass (\d+)$", t, re.M); failed = re.findall(r"^[ℹ#] fail (\d+)$", t, re.M)
    if tests and passed:
        return {"passed": sum(map(int, passed)), "failed": sum(map(int, failed)), "total": sum(map(int, tests)), "runner": "node --test"}
    # pytest: "==== 2 failed, 41 passed, 3 skipped in 4.20s ===="
    m = re.findall(r"^=+ (.*?) in [\d.]+s(?: \([^)]*\))? =+$", t, re.M)
    if m:
        line = m[-1]
        get = lambda w: sum(int(x) for x in re.findall(rf"(\d+) {w}", line))
        p, f, e = get("passed"), get("failed"), get("errors?")
        if p or f or e:
            return {"passed": p, "failed": f + e, "total": p + f + e, "runner": "pytest"}
    # unittest: "Ran 43 tests in 0.5s" then "OK" or "FAILED (failures=2)"
    m = re.findall(r"^Ran (\d+) tests? in", t, re.M)
    if m:
        total = int(m[-1]); bad = re.search(r"FAILED \((.*?)\)", t)
        failed = sum(int(x) for x in re.findall(r"(?:failures|errors)=(\d+)", bad.group(1))) if bad else 0
        return {"passed": total - failed, "failed": failed, "total": total, "runner": "unittest"}
    # go test: one "ok" or "FAIL" line per package
    oks = re.findall(r"^ok\s+\S+", t, re.M); fails = re.findall(r"^FAIL\s+\S+\s", t, re.M)
    if oks or fails:
        return {"passed": len(oks), "failed": len(fails), "total": len(oks) + len(fails), "runner": "go test (packages)"}
    return {"runner": None}


def self_test() -> int:
    cases = [
        ("Tests:       2 failed, 41 passed, 43 total\n", 1, {"passed": 41, "failed": 2, "total": 43, "runner": "jest"}),
        ("Tests:       12 passed, 12 total\n", 0, {"passed": 12, "failed": 0, "total": 12, "runner": "jest"}),
        ("\x1b[2m      Tests \x1b[22m 41 passed\x1b[39m (41)\n", 0, {"passed": 41, "failed": 0, "total": 41, "runner": "vitest"}),
        ("      Tests  2 failed | 41 passed (43)\n", 1, {"passed": 41, "failed": 2, "total": 43, "runner": "vitest"}),
        ("ℹ tests 9\nℹ pass 9\nℹ fail 0\n", 0, {"passed": 9, "failed": 0, "total": 9, "runner": "node --test"}),
        ("===== 2 failed, 41 passed, 3 skipped in 4.20s =====\n", 1, {"passed": 41, "failed": 2, "total": 43, "runner": "pytest"}),
        ("Ran 5 tests in 0.010s\n\nFAILED (failures=1, errors=1)\n", 1, {"passed": 3, "failed": 2, "total": 5, "runner": "unittest"}),
        ("ok  \texample.com/a\t0.1s\nFAIL\texample.com/b\t0.2s\n", 1, {"passed": 1, "failed": 1, "total": 2, "runner": "go test (packages)"}),
        ("Tests:       3 passed, 3 total\n...\nTests:       40 passed, 40 total\n", 0, {"passed": 43, "failed": 0, "total": 43, "runner": "jest"}),
        ("      Tests  5 passed (5)\n      Tests  1 failed | 9 passed (10)\n", 1, {"passed": 14, "failed": 1, "total": 15, "runner": "vitest"}),
        ("npm ERR! missing script: test\n", 1, {"runner": None}),
    ]
    bad = 0
    for text, code, want in cases:
        got = counts(text, code)
        if got != want:
            bad += 1
            print(f"FAIL {want.get('runner')}: got {got}")
    print(f"outside_counts self-test: {len(cases) - bad} of {len(cases)}")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read() if len(sys.argv) > 1 else ""
    print(json.dumps(counts(text, int(sys.argv[2]) if len(sys.argv) > 2 else 1)))
