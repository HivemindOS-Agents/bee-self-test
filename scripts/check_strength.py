#!/usr/bin/env python3
"""HB-067 E, HB-061 plus (22 Nov 2026 update, section 5 E): can a tool's passing self-test fail at all?

It makes n small deliberate breaks of the tool's own code, one at a time, each in a fresh temp copy of the tool's
folder, and runs the tool's unchanged self_test.py against each. A break the self-test fails on (a non-zero exit, or
no exit within the timeout) is caught. The result is `check_strength: k/n`; a check that catches under half is a
"weak check", and one that catches none can never fail on a change to the code it checks.

The breaks are chosen with a fixed seed from every place in the tool's non-test .py files (not self_test.py,
test_*.py or *_test.py) where one of these applies, so a re-run makes the same breaks:
  flip a comparison (< and >=, <= and >, == and !=, in and not in, is and is not)
  negate the condition of an if, a while or a conditional expression
  swap True and False
  add one to an int literal (off by one)
  empty a return (return None in place of its value)

The tool's code is run, but only inside a temp directory, as its own working directory, with an environment that
holds no token or key (PATH only, and HOME set to the temp directory). In CI it runs in a job with no permissions.

    python3 scripts/check_strength.py --self-test               # fixtures/check-strength/, a strong and a weak check
    python3 scripts/check_strength.py [--n 20] [--seed 0] TOOL_DIR...

Report-only: it prints one JSON line a tool. Exit 0 unless a folder could not be read or its unbroken self-test does
not pass (2).
"""
import ast
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

N, SEED, TIMEOUT = 20, 0, 60
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "check-strength")
FLIP = {ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
        ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
SKIP = ("self_test.py", "conftest.py")


def is_test(name):
    return name in SKIP or name.startswith("test_") or name.endswith("_test.py")


def code_files(folder):
    out = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d != "__pycache__")
        out += [os.path.relpath(os.path.join(root, f), folder) for f in sorted(files) if f.endswith(".py") and not is_test(f)]
    return out


def sites(tree):
    """Every place a break applies, in source order: (line, col, kind, index within the node)."""
    found, in_fstring = [], set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            in_fstring |= {id(n) for n in ast.walk(node)}
    for node in ast.walk(tree):
        if id(node) in in_fstring:
            continue
        where = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if isinstance(node, ast.Compare):
            found += [(*where, "flip a comparison", i) for i, op in enumerate(node.ops) if type(op) in FLIP]
        elif isinstance(node, (ast.If, ast.While, ast.IfExp)):
            found.append((*where, "negate a condition", 0))
        elif isinstance(node, ast.Constant) and isinstance(node.value, bool):
            found.append((*where, "swap True and False", 0))
        elif isinstance(node, ast.Constant) and type(node.value) is int:
            found.append((*where, "off by one", 0))
        elif isinstance(node, ast.Return) and node.value is not None and not (isinstance(node.value, ast.Constant) and node.value.value is None):
            found.append((*where, "empty a return", 0))
    return sorted(found)


def apply(tree, site):
    """The tree with one break made at `site` (which `sites` of this same tree returned)."""
    line, col, kind, index = site
    for node in ast.walk(tree):
        if (getattr(node, "lineno", None), getattr(node, "col_offset", None)) != (line, col):
            continue
        if kind == "flip a comparison" and isinstance(node, ast.Compare):
            node.ops[index] = FLIP[type(node.ops[index])]()
        elif kind == "negate a condition" and isinstance(node, (ast.If, ast.While, ast.IfExp)):
            node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        elif kind == "swap True and False" and isinstance(node, ast.Constant) and isinstance(node.value, bool):
            node.value = not node.value
        elif kind == "off by one" and isinstance(node, ast.Constant) and type(node.value) is int:
            node.value += 1
        elif kind == "empty a return" and isinstance(node, ast.Return):
            node.value = None
        else:
            continue
        return ast.fix_missing_locations(tree)
    raise ValueError(f"no {kind} at line {line}")


def run(folder, test="self_test.py", timeout=TIMEOUT):
    """(exit code, or "timeout") of the tool's self-test in `folder`, with no token in its environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": folder, "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C.UTF-8"}
    try:
        return subprocess.run([sys.executable, test], cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return "timeout"


def digest(folder):
    h = hashlib.sha256()
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for f in sorted(files):
            path = os.path.join(root, f)
            h.update(os.path.relpath(path, folder).encode() + b"\0" + open(path, "rb").read())
    return h.hexdigest()


def strength(folder, n=N, seed=SEED, timeout=TIMEOUT):
    """{tool, check_strength, caught, n, label, missed, baseline} for one tool folder."""
    folder = os.path.abspath(folder)
    tool = os.path.basename(os.path.normpath(folder))
    if not os.path.exists(os.path.join(folder, "self_test.py")):
        return {"tool": tool, "check_strength": None, "baseline": "no self_test.py"}
    files = code_files(folder)
    trees = {f: ast.parse(open(os.path.join(folder, f), encoding="utf-8").read(), filename=f) for f in files}
    every = [(f, s) for f in files for s in sites(trees[f])]
    chosen = sorted(random.Random(seed).sample(every, n), key=lambda x: (x[0], x[1])) if len(every) > n else every
    work = tempfile.mkdtemp(prefix="check-strength-")
    try:
        def copy():
            target = os.path.join(work, "t")
            shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(folder, target, ignore=shutil.ignore_patterns("__pycache__", ".git"))
            return target
        base = run(copy(), timeout=timeout)
        if base != 0:
            return {"tool": tool, "check_strength": None, "baseline": f"its self-test does not pass unbroken (exit {base})"}
        # Every file written back unbroken through the same printer must still pass, or no break can be judged.
        target = copy()
        for f in files:
            open(os.path.join(target, f), "w", encoding="utf-8").write(ast.unparse(trees[f]) + "\n")
        if files and run(target, timeout=timeout) != 0:
            return {"tool": tool, "check_strength": None, "baseline": "its code, re-printed unbroken, does not pass"}
        caught, missed = 0, []
        for f, site in chosen:
            target = copy()
            tree = apply(ast.parse(open(os.path.join(folder, f), encoding="utf-8").read()), site)
            open(os.path.join(target, f), "w", encoding="utf-8").write(ast.unparse(tree) + "\n")
            code = run(target, timeout=timeout)
            if code != 0:
                caught += 1
            else:
                missed.append({"file": f, "line": site[0], "break": site[2]})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    total = len(chosen)
    label = "weak check" if total and caught * 2 < total else None
    if not total:
        label = "no code outside its self-test to break"
    return {"tool": tool, "check_strength": f"{caught}/{total}", "caught": caught, "n": total, "sites": len(every), "label": label, "missed": missed, "baseline": "pass", "seed": seed}


def self_test():
    bad = []
    strong, weak = os.path.join(FIXTURES, "strong"), os.path.join(FIXTURES, "weak")
    before = (digest(strong), digest(weak))
    s = strength(strong, n=8)
    if (s.get("caught"), s.get("n"), s.get("label")) != (8, 8, None):
        bad.append(f"a strong check catches every break: got {s}")
    w = strength(weak, n=8)
    if (w.get("caught"), w.get("n"), w.get("label")) != (0, 8, "weak check"):
        bad.append(f"a check that can never fail catches none: got {w}")
    if strength(strong, n=5) != strength(strong, n=5):
        bad.append("the same seed makes the same breaks")
    if (digest(strong), digest(weak)) != before:
        bad.append("the tool folders are not changed: every break is made in a temp copy")
    kinds = {k for _, _, k, _ in sites(ast.parse(open(os.path.join(strong, "rows.py")).read()))}
    if kinds != {"flip a comparison", "negate a condition", "swap True and False", "off by one", "empty a return"}:
        bad.append(f"each kind of break has a place in the fixture: got {sorted(kinds)}")
    src = "def f(x):\n    if x < 1:\n        return True\n    return x == 2\n"
    broken = [ast.unparse(apply(ast.parse(src), site)) for site in sites(ast.parse(src))]
    if len(set(broken)) != len(broken) or ast.unparse(ast.parse(src)) in broken:
        bad.append("every break changes the code, and no two are the same")
    failing = tempfile.mkdtemp(prefix="check-strength-fixture-")
    try:
        open(os.path.join(failing, "self_test.py"), "w").write("raise SystemExit(1)\n")
        if strength(failing)["check_strength"] is not None:
            bad.append("a self-test that fails unbroken is not scored")
    finally:
        shutil.rmtree(failing, ignore_errors=True)
    total = 7
    for line in bad:
        print("FAIL", line)
    print(f"check strength self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    n, seed, folders, it = N, SEED, [], iter(argv)
    for a in it:
        if a == "--n":
            n = int(next(it))
        elif a == "--seed":
            seed = int(next(it))
        else:
            folders.append(a)
    if not folders:
        print(__doc__)
        return 2
    code = 0
    for folder in folders:
        try:
            r = strength(folder, n, seed)
        except (OSError, SyntaxError, ValueError) as error:
            r, code = {"tool": os.path.basename(os.path.normpath(folder)), "check_strength": None, "baseline": f"could not read: {error}"}, 2
        if r.get("check_strength") is None:
            code = 2
        print(json.dumps(r))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
