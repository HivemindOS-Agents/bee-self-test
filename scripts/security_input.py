#!/usr/bin/env python3
"""How every public security reader here reads its inputs (HB-136). One rule, one place:

  - a security setting that is supplied but empty (nothing, or only commas and whitespace) stops the run:
    STOP empty_security_setting
  - one that does not parse, or parses to the wrong shape, stops the run: STOP unparseable_security_setting
  - only an ABSENT setting may take its documented default, and that use is said: default_used, with the input listed
    as unread. An absent setting with no documented default stops the run as empty_security_setting.

A STOP is never a traceback: it names the reason and the file, and the reader keeps the rest of its report. A reader
exits 2 when it stopped on anything, the exit this repository's checks already give "could not be read".

The readers: rule_map_check.py, claim_watch.py, check_skill_files.py and repair_receipts.py. bee-scouts keeps a copy of
these rules for its pause check (bee-scouts scripts/security_input.py): another repository, so another copy; change
both together.

    python3 scripts/security_input.py --self-test
"""
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
    shutil.rmtree(folder, ignore_errors=True)
    for line in bad:
        print("FAIL", line)
    print(f"security input self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--self-test"]:
        sys.exit(self_test())
    print(__doc__)
    sys.exit(2)
