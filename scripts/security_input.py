#!/usr/bin/env python3
"""How every public security reader here reads its inputs (HB-136). One rule, one place:

  - a security setting that is supplied but empty (nothing, or only commas and whitespace) stops the run:
    STOP empty_security_setting
  - one that does not parse, or parses to the wrong shape, stops the run: STOP unparseable_security_setting
  - only an ABSENT setting may take its documented default, and that use is said: default_used, with the input listed
    as unread. An absent setting with no documented default stops the run as empty_security_setting.

A STOP is never a traceback: it names the reason and the file, and the reader keeps the rest of its report. A reader
exits 2 when it stopped on anything, the exit this repository's checks already give "could not be read".

The readers: in bee-self-test, rule_map_check.py, claim_watch.py, check_skill_files.py, repair_receipts.py and
feed_freshness.py; in bee-scouts, check_outside.py (outside/pauses.jsonl and its history). Each of the two
repositories holds this file, byte for byte the same: another repository, so another copy. Change both together:
each repository's CI runs --same-as against the other's main and fails when the two differ (25 Nov 2026 update,
row 41r4).

Every key a reader takes with field() is a security key, and each needs an empty-state fixture: the reader's test
file maps it in EMPTY_STATE = {"<key>": "<TestClass>.<test_method>"} to a test that runs the reader with that key
missing or empty. --keys fails on a key read and not mapped, a key that is not a plain string, an entry naming a test
that does not exist, and an entry for a key no reader reads any more (row 41r2).

    python3 scripts/security_input.py --self-test
    python3 scripts/security_input.py --same-as OTHER_COPY            # exit 1 when the two copies differ
    python3 scripts/security_input.py --keys SCRIPTS_DIR TEST_FILE    # exit 1 when a security key has no fixture
"""
import ast
import hashlib
import json
import os
import re
import sys

EMPTY = "empty_security_setting"
UNPARSEABLE = "unparseable_security_setting"
DEFAULT_USED = "default_used"
EXIT_STOP = 2
NO_DEFAULT = object()
BLANK = re.compile(r"[\s,]*")


class Stop(Exception):
    """A security input that stops the run: its reason, the file (or the setting) and what was wrong."""

    def __init__(self, reason, source, detail):
        super().__init__(f"{reason}: {source}: {detail}")
        self.reason, self.source, self.detail = reason, str(source), detail

    def line(self):
        return f"STOP {self.reason}: {self.source}: {self.detail}"

    def as_dict(self):
        return {"reason": self.reason, "file": self.source, "detail": self.detail}


def blank(text):
    return BLANK.fullmatch(text) is not None


def default_used(source, why, log=None):
    """Says that an absent input took its documented default. Returns the entry a report lists as unread."""
    line = f"{DEFAULT_USED}: {source}: {why}"
    print(line, file=log or sys.stderr)
    return {"default_used": str(source), "why": why}


def check_text(source, text):
    """Text that was supplied: it must hold something besides commas and whitespace."""
    if blank(text):
        raise Stop(EMPTY, source, "supplied but empty" if not text else "only commas or whitespace")
    return text


def read_text(path, source=None, default=NO_DEFAULT, why=None, unread=None):
    """A file's text. Absent: its documented default (said, and listed in `unread`), or a STOP when it has none."""
    source = source or path
    if not os.path.exists(path):
        if default is NO_DEFAULT:
            raise Stop(EMPTY, source, "absent, and it has no documented default")
        entry = default_used(source, why or "absent: its documented default")
        if unread is not None:
            unread.append(entry)
        return default
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise Stop(UNPARSEABLE, source, f"could not be read: {error.strerror or error}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Stop(UNPARSEABLE, source, f"not UTF-8 text: {error.reason} at byte {error.start}")
    return check_text(source, text)


def _shape(want):
    return {dict: "an object", list: "a list", str: "a string"}.get(want, getattr(want, "__name__", str(want)))


def parse_json(source, text, want=dict):
    """JSON text, which must be one value of type `want`."""
    check_text(source, text)
    try:
        value = json.loads(text)
    except ValueError as error:
        raise Stop(UNPARSEABLE, source, f"not JSON: {error}")
    if want is not None and not isinstance(value, want):
        raise Stop(UNPARSEABLE, source, f"not {_shape(want)} but {type(value).__name__}")
    return value


def read_json(path, source=None, want=dict, default=NO_DEFAULT, why=None, unread=None):
    text = read_text(path, source, default, why, unread)
    if default is not NO_DEFAULT and text is default:
        return default
    return parse_json(source or path, text, want)


def parse_jsonl(source, text, want=dict):
    """JSON lines: at least one, each a `want`. Blank lines between them are allowed; one bad line stops the file."""
    check_text(source, text)
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as error:
            raise Stop(UNPARSEABLE, source, f"line {n} is not JSON: {error}")
        if want is not None and not isinstance(value, want):
            raise Stop(UNPARSEABLE, source, f"line {n} is not {_shape(want)} but {type(value).__name__}")
        out.append(value)
    if not out:
        raise Stop(EMPTY, source, "no line holds a value")
    return out


def field(source, doc, key, want=list, nonempty=True):
    """doc[key]: present (absent is empty: no documented default), of type `want`, and not empty unless allowed."""
    if not isinstance(doc, dict) or key not in doc or doc[key] is None:
        raise Stop(EMPTY, source, f"no `{key}`")
    value = doc[key]
    if want is not None and not isinstance(value, want):
        raise Stop(UNPARSEABLE, source, f"`{key}` is not {_shape(want)} but {type(value).__name__}")
    if nonempty and (not value if not isinstance(value, str) else blank(value)):
        raise Stop(EMPTY, source, f"`{key}` is empty")
    return value


def stop_line(stop, out=None):
    print(stop.line(), file=out or sys.stderr)
    return stop


# ------------------------------------------------------------------------------------- the copies, and the keys' fixtures
def same_as(this, other):
    """(problems, lines): this file against the other repository's copy, byte for byte."""
    data = {}
    for path in (this, other):
        try:
            with open(path, "rb") as handle:
                data[path] = handle.read()
        except OSError as error:
            raise Stop(EMPTY, path, f"could not be read: {error.strerror or error}")
        if not data[path].strip():
            raise Stop(EMPTY, path, "supplied but empty")
    a, b = (hashlib.sha256(data[p]).hexdigest() for p in (this, other))
    if a == b:
        return [], [f"same: {this} and {other} are the same bytes (sha256 {a[:12]})"]
    return [f"differ: {this} sha256 {a[:12]} and {other} sha256 {b[:12]}: change both copies together"], []


def field_keys(scripts_dir):
    """{key: [file:line]} for every field() call on this module in scripts_dir/*.py, and the calls whose key is not a
    plain string ([file:line])."""
    keys, opaque = {}, []
    for name in sorted(os.listdir(scripts_dir)):
        if not name.endswith(".py") or name == "security_input.py":
            continue
        path = os.path.join(scripts_dir, name)
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), path)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "field"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id in ("si", "security_input")):
                continue
            key = node.args[2] if len(node.args) > 2 else next((k.value for k in node.keywords if k.arg == "key"), None)
            where = f"{name}:{node.lineno}"
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.setdefault(key.value, []).append(where)
            else:
                opaque.append(where)
    return keys, opaque


def empty_state_map(test_file):
    """(EMPTY_STATE as a dict or None, {"Class.method"} the test file defines)."""
    with open(test_file, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), test_file)
    mapping, tests = None, set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "EMPTY_STATE" for t in node.targets):
            try:
                mapping = ast.literal_eval(node.value)
            except ValueError:
                raise Stop(UNPARSEABLE, test_file, "EMPTY_STATE is not a literal dict")
            if not isinstance(mapping, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
                raise Stop(UNPARSEABLE, test_file, "EMPTY_STATE is not a dict of key to \"Class.test_method\"")
        if isinstance(node, ast.ClassDef):
            tests |= {f"{node.name}.{f.name}" for f in node.body if isinstance(f, ast.FunctionDef) and f.name.startswith("test")}
    return mapping, tests


def keys_check(scripts_dir, test_file):
    """(problems, lines): every security key read with field() has an empty-state fixture, and nothing else is mapped."""
    if not os.path.isdir(scripts_dir):
        raise Stop(EMPTY, scripts_dir, "absent: no scripts folder to read")
    keys, opaque = field_keys(scripts_dir)
    mapping, tests = empty_state_map(test_file)
    problems = [f"opaque: the key at {w} is not a plain string, so its fixture cannot be checked" for w in opaque]
    if keys and mapping is None:
        problems.append(f"no EMPTY_STATE in {test_file}, and {len(keys)} security key(s) are read: {', '.join(sorted(keys))}")
        mapping = {}
    mapping = mapping or {}
    for key, where in sorted(keys.items()):
        if key not in mapping:
            problems.append(f"missing: `{key}` (read at {', '.join(where)}) has no empty-state fixture in EMPTY_STATE")
        elif mapping[key] not in tests:
            problems.append(f"missing: `{key}` maps to {mapping[key]}, which {test_file} does not define")
    for key in sorted(set(mapping) - set(keys)):
        problems.append(f"stale: EMPTY_STATE maps `{key}`, which no reader in {scripts_dir} reads with field()")
    lines = [f"keys: {key} -> {mapping[key]}" for key in sorted(keys) if key in mapping and mapping[key] in tests]
    lines.append(f"keys: {len(keys)} security key(s) read with field(), {len(keys) - sum(1 for p in problems if p.startswith('missing'))} with an empty-state fixture")
    return problems, lines


# ---------------------------------------------------------------------------------------------------------------- fixtures
def self_test():
    import tempfile
    bad, total = [], 0

    def expect(name, fn, reason):
        nonlocal total
        total += 1
        try:
            got = fn()
            if reason is not None:
                bad.append(f"{name}: no STOP, got {got!r}")
        except Stop as stop:
            if stop.reason != reason:
                bad.append(f"{name}: {stop.reason}, want {reason}")

    folder = tempfile.mkdtemp(prefix="security-input-")
    def put(name, text):
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path
    expect("empty", lambda: read_text(put("a", "")), EMPTY)
    expect("commas and whitespace", lambda: read_text(put("b", " ,\n,\t")), EMPTY)
    expect("absent, no default", lambda: read_text(os.path.join(folder, "none")), EMPTY)
    expect("unparseable", lambda: read_json(put("c", "{x")), UNPARSEABLE)
    expect("the wrong shape", lambda: read_json(put("d", "[1]")), UNPARSEABLE)
    expect("a json line that is not an object", lambda: parse_jsonl("e", '{"a":1}\n[2]\n'), UNPARSEABLE)
    expect("json lines with none", lambda: parse_jsonl("f", "\n \n"), EMPTY)
    expect("a missing key", lambda: field("g", {"v": 1}, "skills"), EMPTY)
    expect("an empty list", lambda: field("h", {"skills": []}, "skills"), EMPTY)
    expect("a key of the wrong type", lambda: field("i", {"skills": {}}, "skills"), UNPARSEABLE)
    expect("a good object", lambda: read_json(put("j", '{"skills":[1]}')), None)
    expect("an empty list allowed", lambda: field("k", {"findings": []}, "findings", nonempty=False), None)
    unread = []
    total += 1
    import io
    import shutil
    log = io.StringIO()
    entry = default_used("LESSONS.md", "not written yet", log=log)
    if read_text(os.path.join(folder, "none"), "LESSONS.md", default="", why="not written yet", unread=unread) != "" or len(unread) != 1 \
            or entry != {"default_used": "LESSONS.md", "why": "not written yet"} or not log.getvalue().startswith("default_used: LESSONS.md"):
        bad.append("an absent input with a documented default takes it, says default_used and is listed as unread")
    # --same-as and --keys on small folders (rows 41r4 and 41r2).
    total += 6
    if same_as(put("s1", "x = 1\n"), put("s2", "x = 1\n"))[0] or not same_as(put("s3", "x = 1\n"), put("s4", "x = 2\n"))[0]:
        bad.append("--same-as: same bytes pass and different bytes fail")
    scripts = os.path.join(folder, "scripts")
    os.makedirs(scripts)
    with open(os.path.join(scripts, "reader.py"), "w", encoding="utf-8") as handle:
        handle.write("import security_input as si\nrows = si.field('x', {}, 'rows', list)\n")
    test_ok = put("test_ok.py", "EMPTY_STATE = {'rows': 'Reader.test_no_rows'}\nclass Reader:\n    def test_no_rows(self):\n        pass\n")
    if keys_check(scripts, test_ok)[0]:
        bad.append("--keys: a mapped key with its test passes")
    if not keys_check(scripts, put("test_none.py", "class Reader:\n    pass\n"))[0]:
        bad.append("--keys: a key with no EMPTY_STATE fails")
    if not keys_check(scripts, put("test_gone.py", "EMPTY_STATE = {'rows': 'Reader.test_gone'}\n"))[0]:
        bad.append("--keys: an entry naming a test that does not exist fails")
    if not keys_check(scripts, put("test_stale.py", "EMPTY_STATE = {'rows': 'Reader.test_no_rows', 'old': 'Reader.test_no_rows'}\nclass Reader:\n    def test_no_rows(self):\n        pass\n"))[0]:
        bad.append("--keys: an entry for a key no reader reads fails")
    with open(os.path.join(scripts, "other.py"), "w", encoding="utf-8") as handle:
        handle.write("import security_input as si\nk = 'rows'\nrows = si.field('x', {}, k, list)\n")
    if not any(p.startswith("opaque") for p in keys_check(scripts, test_ok)[0]):
        bad.append("--keys: a key that is not a plain string fails")
    shutil.rmtree(folder, ignore_errors=True)
    for line in bad:
        print("FAIL", line)
    print(f"security input self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    for flag, count, fn in (("--same-as", 1, lambda other: same_as(os.path.abspath(__file__), other)), ("--keys", 2, keys_check)):
        if sys.argv[1:2] == [flag] and len(sys.argv) == 2 + count:
            try:
                problems, lines = fn(*sys.argv[2:])
            except Stop as stop:
                stop_line(stop)
                sys.exit(EXIT_STOP)
            for line in lines + problems:
                print(line)
            print(f"security input {flag[2:]}:", "PASS" if not problems else f"FAIL ({len(problems)} problems)")
            sys.exit(1 if problems else 0)
    print(__doc__)
    sys.exit(2)
