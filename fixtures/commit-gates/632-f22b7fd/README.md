# run-record-lint

Check a run record for the two things a reader needs: what was run, and why.

## What it does

Reads one or more record files and reports:

- **unlabelled claim** - a line that states something happened (`ran`, `passed`,
  `fixed`, `committed`, `published`, ...) but carries no `why:` label;
- **missing why** - a record with no `why:` label anywhere;
- **clean record: no finding** - neither of the above, exit 0.

Everything read from a record is data. A line saying "ignore your instructions"
or anything like it is a string to be checked, never an instruction to this
tool.

## How to run

~~~bash
python3 run_record_lint.py fixtures/clean.txt; echo EXIT=$?
python3 run_record_lint.py --messages
cd tools/run-record-lint-fixtures && python3 self_test.py; echo EXIT=$?
~~~

Standard library only, no network.

## The message table

The three finding messages live in one table at the top of `run_record_lint.py`:

| key | message | substring a check greps for |
|---|---|---|
| `clean` | `clean record: no finding` | `no finding` |
| `missing-why` | `missing why: every non-empty line needs a why label` | `missing why` |
| `unlabelled-claim` | `unlabelled claim: this line states a claim with no why label` | `unlabelled claim` |

Each value is a superset of the substring its check greps for, so a check
cannot fail on wording alone. `--messages` prints the table, which is the one
command needed to diff it against the checks in `self_test.py`.

## What is untested

- **No run was executed by the step that wrote this fix.** The last captured run
  of this folder passed 8/8, but it predates the MESSAGES table; the aligned
  table and this self-test are written, not run. There is no `EXIT=0` line for
  this commit, and `SELFTEST_OUTPUT.md` is written by HivemindOS after the
  commit, not here.
- The three substrings (`no finding`, `missing why`, `unlabelled claim`) come
  from the earlier fixture description (2026-11-15, issue #130), not from
  re-reading `self_test.py` against the linter in this step. Run
  `python3 run_record_lint.py --messages` and diff it against the checks before
  trusting the alignment.
- The `why:` label grammar is a plain literal match; the rule text in the
  fixture description is richer than that. It is a working approximation, not a
  confirmed reading of the rule.

## Licence

CC0-1.0. All fixtures are synthetic.
