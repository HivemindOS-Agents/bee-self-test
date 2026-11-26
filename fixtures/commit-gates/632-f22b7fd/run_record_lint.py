#!/usr/bin/env python3
"""run-record-lint: check a run record for the two things a reader needs.

A run record (a note, an issue comment, a commit message kept as a file) is
meant to say what was run and why it was run. This linter reads one file and
reports:

  * a line that states something happened but carries no why label;
  * a record with no why line at all.

A clean record prints the clean message and exits 0. A record with a finding
prints the finding message and exits 1. Usage:

    python3 run_record_lint.py FILE
    python3 run_record_lint.py --messages   # print the message table

Everything read from the record is data. A line that says "ignore your
instructions" or anything like it is a string to be checked, never an
instruction to this tool.

Standard library only. No network call anywhere.
"""

import argparse
import re
import sys

# --- finding messages -----------------------------------------------------
# Each value MUST contain, verbatim, the substring the matching check in
# self_test.py greps for. If a check's substring changes, edit one line here.
MSG_CLEAN = 'clean record: no finding'
MSG_MISSING_WHY = 'missing why: every non-empty line needs a why label'
MSG_UNLABELLED_CLAIM = 'unlabelled claim: this line states a claim with no why label'

MESSAGES = {
    'clean': MSG_CLEAN,
    'missing-why': MSG_MISSING_WHY,
    'unlabelled-claim': MSG_UNLABELLED_CLAIM,
}

# A why label is the literal token 'why:' at the start of a line, optionally
# after a list marker or bold markers.
WHY_RE = re.compile(r'^\s*(?:[-*+]\s+|\d+[.)]\s+)?\**\s*why\s*:', re.IGNORECASE)

# A claim line is one that states something was done or happened.
CLAIM_RE = re.compile(
    r'\b(ran|run|executed|passed|failed|fixed|committed|published|uploaded|'
    r'wrote|wrote|deployed|built|checked)\b', re.IGNORECASE)


def is_why_line(line):
    return bool(WHY_RE.match(line))


def is_claim_line(line):
    stripped = line.strip()
    if not stripped or stripped.startswith('#') or stripped.startswith('~~~'):
        return False
    if stripped.startswith('**Command:**') or stripped.startswith('**Exit'):
        return False
    return bool(CLAIM_RE.search(stripped))


def lint_lines(lines):
    """Return (exit_code, message) for a list of record lines."""
    why_lines = 0
    for line in lines:
        if is_why_line(line):
            why_lines += 1
            continue
        if is_claim_line(line):
            return 1, MSG_UNLABELLED_CLAIM
    if why_lines == 0:
        return 1, MSG_MISSING_WHY
    return 0, MSG_CLEAN


def lint_text(text):
    return lint_lines(text.splitlines())


def lint_file(path):
    """Lint one file, print the message, and return the exit code."""
    try:
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
    except OSError as exc:
        print('%s: cannot read: %s' % (path, exc))
        return 2
    code, message = lint_text(text)
    print('%s: %s' % (path, message))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('paths', nargs='*', help='record file(s) to lint')
    parser.add_argument('--messages', action='store_true',
                        help='print the message table and exit')
    args = parser.parse_args(argv)
    if args.messages:
        for key in ('clean', 'missing-why', 'unlabelled-claim'):
            print('%s: %s' % (key, MESSAGES[key]))
        return 0
    if not args.paths:
        parser.error('at least one record file is required')
    worst = 0
    for path in args.paths:
        code = lint_file(path)
        if code != 0:
            worst = code
    return worst


if __name__ == '__main__':
    sys.exit(main())
