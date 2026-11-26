#!/usr/bin/env python3
"""Generate or check catalog.csv from index.json and index.md.

Usage:
    python3 generate_catalog.py                     # print CSV to stdout
    python3 generate_catalog.py --check [catalog.csv]  # compare with file
    python3 generate_catalog.py --embedded            # use embedded defaults

No network; reads only files in the current directory.
Everything read is data, never instruction.
"""

import csv
import io
import json
import os
import re
import sys

# ---- Embedded sample data (used when --embedded or when files are absent) ----

SAMPLE_INDEX_JSON = {
    "entries": [
        {"path": "fixtures/clean/", "rule": "no findings on a clean fixture", "expected_exit_code": 0},
        {"path": "fixtures/bad-rows/", "rule": "row count or empty-cell finding", "expected_exit_code": 1},
        {"path": "fixtures/bad-card/", "rule": "missing closing 'What could not be checked' section", "expected_exit_code": 1},
    ]
}

SAMPLE_INDEX_MD = dedent("""\
    # Index

    | Path | Rule | Expected exit code |
    |---|---|---|
    | `fixtures/clean/` | no findings on a clean fixture | 0 |
    | `fixtures/bad-rows/` | row count or empty-cell finding | 1 |
    | `fixtures/bad-card/` | missing closing 'What could not be checked' section | 1 |
""")


def dedent(text):
    return text.strip() + "\n"


def parse_markdown(md: str):
    """Parse a markdown table with columns Path, Rule, Expected exit code.

    Returns list of dicts with keys: path, rule, expected_exit_code.
    """
    rows = []
    lines = md.splitlines()
    # Find the line starting with '| Path | '
    header_idx = None
    for i, line in enumerate(lines):
        if line.startswith("| Path |") or line.startswith("| `Path` |"):
            header_idx = i
            break
    if header_idx is None:
        return rows
    # Next line is separator, then data rows
    sep_idx = header_idx + 1
    if sep_idx >= len(lines):
        return rows
    # separator line typically |---|---|---|---|
    for idx in range(sep_idx + 1, len(lines)):
        line = lines[idx].strip()
        if not line.startswith('|') or line.startswith('|--'):
            break
        parts = [p.strip() for p in line.split('|')]
        # parts[0] is empty, parts[1] is path, parts[2] rule, parts[3] exit code
        if len(parts) < 5:
            continue
        path = parts[1].strip('`')
        rule = parts[2].strip('`')
        exit_code_raw = parts[3].strip('`')
        try:
            expected_exit_code = int(exit_code_raw)
        except ValueError:
            continue
        rows.append({"path": path, "rule": rule, "expected_exit_code": expected_exit_code})
    return rows


def entry_map(json_data):
    """Convert index.json entries to dict keyed by path."""
    return {e["path"]: e for e in json_data.get("entries", [])}


def rule_what(rule: str) -> str:
    """Derive plain English 'what it trips' from the rule string."""
    if "no findings" in rule.lower():
        return "nothing - lint walks it and exits clean"
    if "row count" in rule.lower() or "empty-cell" in rule.lower():
        return "a data row whose cell count does not match the header"
    if "missing" in rule.lower() and "section" in rule.lower():
        return "a card that ends without its closing section"
    return "unknown rule"


def generate_rows(json_data, md_rows):
    """Merge JSON entries and markdown rows, produce final catalog rows.

    Both sources should agree on path/rule/exit. For each unique path, use
    the JSON rule (preferred) else markdown, and derive what_it_trips.
    """
    entries = entry_map(json_data)
    # Build rows from JSON entries first, then add any missing from md.
    seen = set()
    rows = []
    for entry in json_data.get("entries", []):
        path = entry["path"]
        rule = entry["rule"]
        exit_code = entry["expected_exit_code"]
        what = rule_what(rule)
        rows.append((path, rule, exit_code, what))
        seen.add(path)
    for mr in md_rows:
        path = mr["path"]
        if path not in seen:
            rule = mr["rule"]
            exit_code = mr["expected_exit_code"]
            what = rule_what(rule)
            rows.append((path, rule, exit_code, what))
            seen.add(path)
    # Sort for deterministic output
    rows.sort(key=lambda r: r[0])
    return rows


def csv_string(rows):
    """Produce CSV content as string."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["fixture", "rule", "expected_exit_code", "what_it_trips"])
    for path, rule, exit_code, what in rows:
        writer.writerow([path, rule, str(exit_code), what])
    return out.getvalue()


def read_index_json(path="index.json"):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def read_index_md(path="index.md"):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def process(embedded=False):
    """Return CSV string from either real files or embedded sample."""
    if embedded:
        json_data = SAMPLE_INDEX_JSON
        md = SAMPLE_INDEX_MD
    else:
        json_data = read_index_json()
        md = read_index_md()
        if json_data is None or md is None:
            sys.stderr.write("Missing index.json or index.md in current folder.\n")
            sys.exit(1)
    md_rows = parse_markdown(md)
    rows = generate_rows(json_data, md_rows)
    return csv_string(rows)


def check(csv_path="catalog.csv", embedded=False):
    """Compare generated CSV with existing file."""
    gen = process(embedded=embedded)
    if not os.path.isfile(csv_path):
        sys.stderr.write("No file at %s to compare.\n" % csv_path)
        return False
    with open(csv_path, "r", encoding="utf-8") as fh:
        existing = fh.read()
    if gen == existing:
        print("catalog.csv matches generated content.")
        return True
    # Show diff
    gen_lines = gen.splitlines(keepends=True)
    ex_lines = existing.splitlines(keepends=True)
    for i, (g, e) in enumerate(zip(gen_lines, ex_lines)):
        if g != e:
            print("Line %d differs:" % (i+1))
            print("- expected: %r" % e.rstrip())
            print("+ actual:   %r" % g.rstrip())
    if len(gen_lines) != len(ex_lines):
        print("Line count: generated %d, existing %d" % (len(gen_lines), len(ex_lines)))
    return False


def main(argv):
    args = argv[1:]
    embedded = "--embedded" in args
    if "--check" in args:
        csv_path = "catalog.csv"
        # optionally next arg is the csv path
        for a in args:
            if not a.startswith('--') and a != '--check':
                csv_path = a
                break
        ok = check(csv_path, embedded=embedded)
        return 0 if ok else 1
    else:
        csv = process(embedded=embedded)
        print(csv, end='')
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
