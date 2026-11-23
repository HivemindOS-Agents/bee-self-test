#!/usr/bin/env python3
"""Living spec L52, daily: every Python file under tools/ compiles, frozen tools included.

The runner compiles a tool's folder only when that tool is dispatched (self-test.yml, "Compile its Python"), so a tool
nobody runs again is never re-checked: hivepunk-632's tools/attribution-docs-check-fixtures/attribution_check.py has had
a SyntaxError at line 52 since 8 Nov 2026 (956181a).

It reads each file from the repository's HEAD with git and calls compile() on the text. It never imports or runs a tool's
code, writes no .pyc, and needs no checkout, so it works on the blobless clones host-checks.yml already makes.

    python3 scripts/compile_sweep.py --self-test     # the fixtures only, no network
    python3 scripts/compile_sweep.py DIR...          # each DIR a clone of an agent repository

Exit 0: all compile. 1: a file does not. 2: a repository could not be read.
"""
import json
import os
import subprocess
import sys
import tempfile
import warnings


def git(repo, *args, data=False):
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True, timeout=120)
    return out.stdout if data else out.stdout.decode("utf-8", "replace")


def python_files(repo):
    """Every tracked .py under tools/ at HEAD."""
    names = git(repo, "ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "tools/").split("\0")
    return sorted(n for n in names if n.endswith(".py"))


def problem(text, name):
    """The compile error of one file's bytes as {line, error}, or None. compile() parses; nothing in the file runs."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            compile(text, name, "exec", dont_inherit=True)
        return None
    except (SyntaxError, ValueError) as error:
        return {"line": getattr(error, "lineno", None), "error": f"{type(error).__name__}: {getattr(error, 'msg', None) or error}"[:160]}


def check_repo(repo):
    broken, files = [], python_files(repo)
    for name in files:
        found = problem(git(repo, "cat-file", "blob", f"HEAD:{name}", data=True), name)
        if found:
            broken.append({"path": name, **found})
    return {"repo": os.path.basename(os.path.abspath(repo)), "files": len(files), "broken": broken}


def self_test():
    bad = []
    root = tempfile.mkdtemp(prefix="l52-")
    repo = os.path.join(root, "hivepunk-1")

    def put(rel, text):
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    os.makedirs(repo)
    git(repo, "init", "--quiet")
    # The 632 shape: an assignment cut off at the end of a line, in a tool no run dispatches any more.
    put("tools/frozen-tool/attribution_check.py", "import sys\n\ncard_path =\nprint(card_path)\n")
    put("tools/good-tool/self_test.py", "print('ok')\n")
    # A file that would do something if it were run: compiling it must not.
    marker = os.path.join(root, "ran")
    put("tools/good-tool/side_effect.py", f"open({marker!r}, 'w').write('ran')\n")
    put("notes/not_a_tool.py", "this is not python\n")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", "fixture")
    # Only HEAD counts: a broken file in the working tree that was never committed is not read.
    put("tools/good-tool/uncommitted.py", "def (\n")
    got = check_repo(repo)
    if got["files"] != 3:
        bad.append(f"only tools/ at HEAD is read: got {got['files']} files")
    if [(b["path"], b["line"]) for b in got["broken"]] != [("tools/frozen-tool/attribution_check.py", 3)]:
        bad.append(f"the frozen tool's SyntaxError, and only it: got {got['broken']}")
    if os.path.exists(marker):
        bad.append("a tool's code ran")
    if problem(b"x = 1\n", "a.py") is not None:
        bad.append("good code read as broken")
    if problem(b"x = \x00 1\n", "a.py") is None:
        bad.append("a null byte is a problem, not a crash")
    for line in bad:
        print("FAIL:", line)
    print(f"compile sweep self-test: {5 - len(bad)} of 5 passed")
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if not argv:
        print(__doc__)
        return 2
    reports, unread = [], 0
    for repo in argv:
        try:
            reports.append(check_repo(repo))
        except (OSError, subprocess.SubprocessError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
    print(json.dumps(reports, indent=2))
    broken = [(r["repo"], b) for r in reports for b in r["broken"]]
    for repo, b in broken:
        print(f"{repo}: {b['path']}:{b['line']}: {b['error']}", file=sys.stderr)
    print(f"compile sweep: {len(broken)} broken of {sum(r['files'] for r in reports)} files in {len(reports)} repositories", file=sys.stderr)
    return 2 if unread else 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
