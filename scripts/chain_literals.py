#!/usr/bin/env python3
"""Guard 53 (24 Nov 2026 dev update, section 32.1): no bare chain literal outside the one chain config.

A code file here (Python, a workflow, a shell or JS file under scripts/, tests/ or .github/) may not hold a configured
chain id (8453-style, inside an eip155: string or as 0x hex) or any configured RPC or explorer host. They live in
scripts/chains.py, and the code imports them. The list of what is looked for is built from that same config, so a chain
added there is linted at once. Reports, results, records of runs, fixtures and docs are data, not code, and are not
read (the spec exempts reports, docs and Builder Index rows; recorded chain answers and reviewed task sets are records).

    python3 scripts/chain_literals.py --self-test   # fixtures/chain-literals: the lines guard 53 names fail, their
                                                    # fixed versions pass
    python3 scripts/chain_literals.py [ROOT]        # every code file in the repository

Exit 0: none found. 1: a literal outside the config (each printed as file:line: what). 2: nothing to read.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import chains  # noqa: E402

ROOT = os.path.normpath(os.path.join(HERE, ".."))
CONFIG = "scripts/chains.py"
CODE_DIRS = ("scripts/", "tests/", ".github/")
CODE_EXT = (".py", ".yml", ".yaml", ".sh", ".mjs", ".js", ".ts")
FIXTURES = os.path.join(ROOT, "fixtures", "chain-literals")


def literals_in(text, patterns=None):
    """(line number, what) for every chain literal in a text."""
    patterns = patterns or chains.literal_patterns()
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for what, rx in patterns:
            if rx.search(line):
                found.append((n, what))
    return found


def code_files(root):
    """The repository's code files, as paths relative to root: tracked ones when root is a git checkout."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, timeout=60, check=True).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        out = [os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) for f in fs]
    return sorted(p for p in out if p.startswith(CODE_DIRS) and p.endswith(CODE_EXT) and p != CONFIG and "__pycache__" not in p)


def lint(root):
    """(files read, [(file, line, what)])."""
    files, problems = code_files(root), []
    for path in files:
        try:
            text = open(os.path.join(root, path), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        problems += [(path, n, what) for n, what in literals_in(text)]
    return len(files), problems


def self_test():
    """Each bad fixture is a line guard 53 names, as it stood at the scanned commit; each good one is its fix."""
    bad = []
    cases = sorted(os.listdir(FIXTURES)) if os.path.isdir(FIXTURES) else []
    if not any(n.startswith("bad-") for n in cases) or not any(n.startswith("good-") for n in cases):
        print("chain literals self-test: STOP, no bad and good fixtures in fixtures/chain-literals")
        return 2
    for name in cases:
        if not name.endswith(".txt"):
            continue
        found = literals_in(open(os.path.join(FIXTURES, name), encoding="utf-8").read())
        if name.startswith("bad-") and not found:
            bad.append(f"{name}: no literal found")
        if name.startswith("good-") and found:
            bad.append(f"{name}: {found}")
    # The config itself is the one place they may be, and is never read as code.
    if CONFIG in code_files(ROOT):
        bad.append("the config is linted as code")
    total = len([n for n in cases if n.endswith(".txt")]) + 1
    for line in bad:
        print("FAIL", line)
    print(f"chain literals self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    root = argv[0] if argv else ROOT
    files, problems = lint(root)
    if not files:
        print("chain literals: STOP, no code file to read")
        return 2
    for path, n, what in problems:
        print(f"{path}:{n}: {what} outside {CONFIG}; import it from there")
    print(f"chain literals: {len(problems)} in {files} code files")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
