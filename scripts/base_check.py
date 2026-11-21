#!/usr/bin/env python3
"""HB-061: the check that judges a change comes from the base, and every runner record says how it was verified.

A tool's self-test is run from the same tree that changed the tool, so a change can edit the check that judges it. When
a change edits a check file, the runner also runs the BASE check (the check as it stood at the tool's last passing run)
on the new code, and, if that fails, the edited check on the base code. The record then says which check decided.

This file runs none of the tool's code. It only reads trees and builds the two mixed trees; the self-test itself is run
by the workflow's own steps, each mixed tree in its own job with no token, and the verdict is the job's result as GitHub
reports it, never anything the tool printed (self-test.yml).

    python3 scripts/base_check.py plan NEW_DIR [BASE_DIR]        # what changed between the two tool folders (JSON)
    python3 scripts/base_check.py build base-check-on-new NEW_DIR BASE_DIR OUT_DIR
    python3 scripts/base_check.py build new-check-on-base NEW_DIR BASE_DIR OUT_DIR
    python3 scripts/base_check.py stamp FACTS.json                # the verified_by stamp for the record (JSON)
    python3 scripts/base_check.py --self-test

Check files: self_test.py, self_test.mjs, self_test.sh, anything under fixtures/, and any file named expected*.
Host-written (ignored): SELFTEST_OUTPUT.md, ARTIFACTS.md, README.md, GOAL.md, *_OUTPUT.txt. Everything else is code.

The stamp, on the runner's record as `verified_by`:
  kind         none (the run did not pass) or runner
  check_from   base (the check that decided is the one from the last passing run, or was not edited),
               same-change (the pass rests on a check this change wrote) or none
  base_check   passed, failed, not-run, unchanged, or unavailable-new-tool
  signal       null, new-check (a first check), loosened (the edited check also passes the old code) or
               behavior-changed (the edited check fails the old code)
  would_block  true when a pass rests on an edited check that the base check does not back. Observe mode: logged only.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile

SELF_TESTS = ("self_test.py", "self_test.mjs", "self_test.sh")
HOST_WRITTEN = ("SELFTEST_OUTPUT.md", "ARTIFACTS.md", "README.md", "GOAL.md")
MODES = ("base-check-on-new", "new-check-on-base")


def is_check(rel):
    """Whether a path inside a tool folder is a check file."""
    parts = rel.split("/")
    return rel in SELF_TESTS or parts[0] == "fixtures" or parts[-1].startswith("expected")


def is_host_written(rel):
    name = rel.split("/")[-1]
    return rel in HOST_WRITTEN or name.endswith("_OUTPUT.txt")


def files_of(root):
    """Every regular file under root as {relative path: sha256}, hidden folders and symlinks left out."""
    out = {}
    if not root or not os.path.isdir(root):
        return out
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and not os.path.islink(os.path.join(base, d)))
        for name in sorted(names):
            path = os.path.join(base, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                out[os.path.relpath(path, root).replace(os.sep, "/")] = hashlib.sha256(f.read()).hexdigest()
    return out


def digest(files):
    """One sha256 for a set of files: their paths and hashes, sorted."""
    return hashlib.sha256("\n".join(f"{p} {h}" for p, h in sorted(files.items())).encode()).hexdigest()


def kind_of(files):
    return next((name for name in SELF_TESTS if name in files), "none")


def plan(new_dir, base_dir=None):
    """What changed between the tool folder now and at its last passing run. No tool code is run."""
    new = files_of(new_dir)
    new_checks = {p: h for p, h in new.items() if is_check(p)}
    new_code = {p: h for p, h in new.items() if not is_check(p) and not is_host_written(p)}
    out = {"kind": kind_of(new), "checks_sha256": digest(new_checks), "check_files": len(new_checks), "base_available": False,
           "check_edited": False, "code_changed": False, "checks_changed": [], "base_kind": "none"}
    base = files_of(base_dir) if base_dir else {}
    if not base:
        return out
    base_checks = {p: h for p, h in base.items() if is_check(p)}
    base_code = {p: h for p, h in base.items() if not is_check(p) and not is_host_written(p)}
    changed = sorted(p for p in set(new_checks) | set(base_checks) if new_checks.get(p) != base_checks.get(p))
    out.update(base_available=True, base_kind=kind_of(base), check_edited=bool(changed), checks_changed=changed[:20],
               code_changed=new_code != base_code, base_checks_sha256=digest(base_checks))
    return out


def build(mode, new_dir, base_dir, out_dir):
    """A mixed tree: the code of one side and the check files of the other. Host-written files come with the code."""
    if mode not in MODES:
        raise SystemExit(f"unknown mode {mode!r}")
    code_dir, check_dir = (new_dir, base_dir) if mode == "base-check-on-new" else (base_dir, new_dir)
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    copied = {"code": 0, "checks": 0}
    for rel in files_of(code_dir):
        if is_check(rel):
            continue
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(os.path.join(code_dir, rel), dest)
        copied["code"] += 1
    for rel in files_of(check_dir):
        if not is_check(rel):
            continue
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(os.path.join(check_dir, rel), dest)
        copied["checks"] += 1
    return {"mode": mode, "kind": kind_of(files_of(out_dir)), **copied}


def stamp(facts):
    """The verified_by stamp from what the workflow observed. `facts`:
      result              the main run: success, failure, none (no self-test file) or anything else
      run, tested_sha     the run's URL and the commit it tested
      base_sha            the last passing run's commit the host named, or ""
      plan                the plan() of the two trees, or None when it could not be made
      base_job, newbase_job  each extra job's result as GitHub reports it: success, failure, skipped, cancelled, ""
      check_sha256        the sha256 of the self-test file that ran
    """
    result = facts.get("result")
    p = facts.get("plan") or {}
    base_sha = facts.get("base_sha") or ""
    out = {"kind": "runner" if result == "success" else "none", "run": facts.get("run") or None, "tested_sha": facts.get("tested_sha") or None,
           "check_from": "none", "base_sha": base_sha or None, "check_sha256": facts.get("check_sha256") or None, "check_edited": None,
           "base_check": "not-run", "new_check_on_base": "not-run", "signal": None, "would_block": False, "reasons": [], "mode": "observe"}
    if result != "success":
        out["reasons"].append("the run did not pass" if result == "failure" else f"the run ended {result}")
        if p.get("base_available"):
            out["check_edited"] = bool(p.get("check_edited"))
        return out
    if not base_sha or not p.get("base_available"):
        out.update(check_from="same-change", base_check="unavailable-new-tool", signal="new-check")
        out["reasons"].append("no earlier passing run to take a check from" if not base_sha else "the base tree could not be read")
        return out
    out["check_edited"] = bool(p.get("check_edited"))
    if not p.get("check_edited"):
        out.update(check_from="base", base_check="unchanged")
        return out
    base_job, newbase_job = facts.get("base_job") or "", facts.get("newbase_job") or ""
    if base_job == "success":
        out.update(check_from="base", base_check="passed")
        out["reasons"].append("a check file changed, and the base check passes on the new code")
        return out
    if base_job != "failure":
        out.update(check_from="same-change", base_check="not-run")
        out["reasons"].append(f"a check file changed and the base check did not run ({base_job or 'no result'})")
        return out
    out.update(check_from="same-change", base_check="failed", would_block=True)
    if newbase_job == "success":
        out.update(new_check_on_base="passed", signal="loosened")
        out["reasons"].append("the base check fails on the new code, and the edited check also passes the base code")
    elif newbase_job == "failure":
        out.update(new_check_on_base="failed", signal="behavior-changed")
        out["reasons"].append("the base check fails on the new code, and the edited check fails the base code")
    else:
        out["reasons"].append(f"the base check fails on the new code; the edited check was not run on the base code ({newbase_job or 'no result'})")
    return out


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if len(argv) >= 2 and argv[0] == "plan":
        print(json.dumps(plan(argv[1], argv[2] if len(argv) > 2 else None)))
        return 0
    if len(argv) == 5 and argv[0] == "build":
        print(json.dumps(build(argv[1], argv[2], argv[3], argv[4])))
        return 0
    if len(argv) == 2 and argv[0] == "stamp":
        with open(argv[1]) as f:
            print(json.dumps(stamp(json.load(f))))
        return 0
    print(__doc__)
    return 2


def self_test():
    n = 0
    root = tempfile.mkdtemp(prefix="hb061-")

    def tree(name, files):
        d = os.path.join(root, name)
        for rel, text in files.items():
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        return d

    try:
        base = tree("base", {"tool.py": "def f():\n    return 1\n", "self_test.py": "assert f() == 1\n", "fixtures/a.json": "{}", "README.md": "# tool\n", "SELFTEST_OUTPUT.md": "old"})
        # Which files are checks, code or the host's.
        assert [is_check(p) for p in ("self_test.py", "self_test.sh", "fixtures/a/b.json", "expected_output.txt", "data/expected.csv", "tool.py", "tests.py", "README.md")] == [True, True, True, True, True, False, False, False]; n += 1
        assert [is_host_written(p) for p in ("README.md", "SELFTEST_OUTPUT.md", "ARTIFACTS.md", "run_OUTPUT.txt", "tool.py", "docs/README.md")] == [True, True, True, True, False, False]; n += 1
        # A code-only fix: no check file changed.
        code_fix = tree("code_fix", {"tool.py": "def f():\n    return 1  # fixed\n", "self_test.py": "assert f() == 1\n", "fixtures/a.json": "{}", "README.md": "# tool\n"})
        p = plan(code_fix, base)
        assert (p["base_available"], p["check_edited"], p["code_changed"], p["kind"]) == (True, False, True, "self_test.py"); n += 1
        # A host-only edit (README, SELFTEST_OUTPUT.md): nothing changed that counts.
        host_only = tree("host_only", {"tool.py": "def f():\n    return 1\n", "self_test.py": "assert f() == 1\n", "fixtures/a.json": "{}", "README.md": "# tool\n\nopportunity: opp-1-2\n", "SELFTEST_OUTPUT.md": "new"})
        p = plan(host_only, base)
        assert (p["check_edited"], p["code_changed"]) == (False, False); n += 1
        # A weakened check with changed code.
        weak = tree("weak", {"tool.py": "def f():\n    return 2\n", "self_test.py": "assert f() in (1, 2)\n", "fixtures/a.json": "{}"})
        p = plan(weak, base)
        assert (p["check_edited"], p["code_changed"], p["checks_changed"]) == (True, True, ["self_test.py"]); n += 1
        # A fixture changed alone is a check edit; so is a new expected file, and a removed one.
        assert plan(tree("fx", {"tool.py": "def f():\n    return 1\n", "self_test.py": "assert f() == 1\n", "fixtures/a.json": "{\"x\": 1}"}), base)["checks_changed"] == ["fixtures/a.json"]; n += 1
        assert plan(tree("gone", {"tool.py": "def f():\n    return 1\n", "self_test.py": "assert f() == 1\n", "expected.txt": "1"}), base)["checks_changed"] == ["expected.txt", "fixtures/a.json"]; n += 1
        # No base: a new tool.
        p = plan(weak)
        assert (p["base_available"], p["check_edited"]) == (False, False); n += 1
        assert plan(weak, os.path.join(root, "missing"))["base_available"] is False; n += 1
        # The mixed trees: the code of one side with the checks of the other.
        out = os.path.join(root, "mixed")
        b = build("base-check-on-new", weak, base, out)
        got = files_of(out)
        assert b == {"mode": "base-check-on-new", "kind": "self_test.py", "code": 1, "checks": 2}; n += 1
        assert got["tool.py"] == files_of(weak)["tool.py"] and got["self_test.py"] == files_of(base)["self_test.py"] and "fixtures/a.json" in got; n += 1
        b = build("new-check-on-base", weak, base, out)
        got = files_of(out)
        assert got["tool.py"] == files_of(base)["tool.py"] and got["self_test.py"] == files_of(weak)["self_test.py"]; n += 1
        assert "README.md" in got and "SELFTEST_OUTPUT.md" in got, "host-written files come with the code side"; n += 1
        # A symlink out of the folder is never followed or copied.
        os.symlink("/etc/hosts", os.path.join(weak, "fixtures_link"))
        assert "fixtures_link" not in files_of(weak); n += 1
        # The digest is of paths and contents, in any order.
        assert digest({"a": "1", "b": "2"}) == digest({"b": "2", "a": "1"}) != digest({"a": "2", "b": "1"}); n += 1
    finally:
        shutil.rmtree(root, ignore_errors=True)

    edited = {"base_available": True, "check_edited": True}
    same = {"base_available": True, "check_edited": False}

    def s(**facts):
        return stamp({"run": "https://x/runs/1", "tested_sha": "a" * 40, "check_sha256": "c" * 64, **facts})

    def brief(st):
        return (st["kind"], st["check_from"], st["base_check"], st["new_check_on_base"], st["signal"], st["would_block"])

    # The spec's fixtures (20 Nov 2026 update, Part 6, section 9).
    assert brief(s(result="success", base_sha="b" * 40, plan=same)) == ("runner", "base", "unchanged", "not-run", None, False); n += 1                      # a code-only fix, and a host-only edit
    assert brief(s(result="success", base_sha="b" * 40, plan=edited, base_job="success")) == ("runner", "base", "passed", "not-run", None, False); n += 1  # a strengthened check
    assert brief(s(result="success", base_sha="b" * 40, plan=edited, base_job="failure", newbase_job="success")) == ("runner", "same-change", "failed", "passed", "loosened", True); n += 1
    assert brief(s(result="success", base_sha="b" * 40, plan=edited, base_job="failure", newbase_job="failure")) == ("runner", "same-change", "failed", "failed", "behavior-changed", True); n += 1
    assert brief(s(result="success", base_sha="", plan={"base_available": False})) == ("runner", "same-change", "unavailable-new-tool", "not-run", "new-check", False); n += 1
    assert brief(s(result="failure", base_sha="b" * 40, plan=edited, base_job="success")) == ("none", "none", "not-run", "not-run", None, False); n += 1   # a failed run is none
    assert brief(s(result="none", base_sha="", plan=None)) == ("none", "none", "not-run", "not-run", None, False); n += 1
    # A base check that did not run decides nothing and blocks nothing; it says so.
    st = s(result="success", base_sha="b" * 40, plan=edited, base_job="cancelled")
    assert brief(st) == ("runner", "same-change", "not-run", "not-run", None, False) and "did not run (cancelled)" in st["reasons"][0]; n += 1
    st = s(result="success", base_sha="b" * 40, plan=edited, base_job="failure", newbase_job="skipped")
    assert brief(st) == ("runner", "same-change", "failed", "not-run", None, True); n += 1
    # A base the host named whose tree could not be read is said, not guessed.
    assert s(result="success", base_sha="b" * 40, plan={"base_available": False})["reasons"] == ["the base tree could not be read"]; n += 1
    st = s(result="success", base_sha="b" * 40, plan=same)
    assert (st["run"], st["tested_sha"], st["base_sha"], st["check_sha256"], st["mode"], st["check_edited"]) == ("https://x/runs/1", "a" * 40, "b" * 40, "c" * 64, "observe", False); n += 1
    print(f"self-test: {n}/{n} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
