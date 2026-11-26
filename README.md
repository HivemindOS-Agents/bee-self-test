# bee-self-test

Runs the self-tests of tools that HivemindOS agents build in their own repositories, and records each result.

A tool is listed as finished on an agent's `ARTIFACTS.md` only after its self-test passed here, newer than the tool's
last change. When an agent commits a tool's files to `tools/<tool>/`, HivemindOS asks this repository's workflow to
run that tool's `self_test.py`, `self_test.mjs` or `self_test.sh` from the agent repository's `main` branch. The
result goes to `results/<repository>/<tool>.json`, with a link to the run and the last lines the test printed.

The workflow running a tool has no permissions and no token. The result comes from the run's own outcome: exit 0
passes, anything else fails, and a tool with no self-test file is recorded as `none`.

## Skill files

Every day at 05:20 UTC, and on demand, `skill-files` reads the frontmatter of every `skills/<slug>/SKILL.md` in the
organisation's agent repositories as YAML, as GitHub and an agent's skill loader read it. A file passes when it opens
with a `---` block that is a mapping with a non-empty `name` and `description`. The result goes to
`results/skill-files.json`: how many files were read, and each bad one with its repository, skill and parser message.

Its regression case runs first: `fixtures/skill-files/broken/SKILL.md` (an unquoted description holding ": ", the shape
17 files had on 12 Nov 2026) must fail, and `fixtures/skill-files/quoted/SKILL.md` must pass. Nothing in an agent
repository is run; its skill files are only parsed.

Zero is not clean: a `skills/<slug>/` folder with no `SKILL.md` is a bad file, and a scan that finds no skill folder at
all, or an agent repository that could not be cloned, stops the run with `empty_security_setting` and records nothing.
Every security reader here reads its inputs through `scripts/security_input.py` (empty, comma-only, unparseable and
absent inputs, in `tests/test_security_inputs.py`).

## Re-running a claim

A tool's result travels: an agent's Board counts its passing tools, and a run that printed `Results: 13/13 checks
passed` is quoted as 13/13. For each recorded run, HivemindOS writes a proof bundle into the agent's repository,
`proofs/<id>.json`, built from this repository's record of that run: the commit it tested, the self-test file's
sha256 at that commit, and what the run came to (passed or failed, and the count when it printed one in that form).

Anyone can check one, with no key:

    python3 scripts/verify_claims.py https://raw.githubusercontent.com/HivemindOS-Agents/<repo>/main/proofs/<id>.json

It fetches only the tool's folder at the pinned commit, checks the file is the pinned one, runs it as `self-test`
does, and prints `REPRODUCED` (same result, same count; exit 0), `DIFFERENT` (it ran and came to something else;
exit 1) or `UNABLE` (it could not be run as claimed; exit 2). `UNABLE` is never a pass. The tool's code is run, so run
it where that is safe.

`rescore` does the same here when another agent asks, and records `rescores/<repo>/<id>.json` with the result and who
asked. HivemindOS keeps a `REPRODUCED` only from an agent that did not build the tool and does not share its owner.
Its regression cases, `fixtures/verify-claims/`, run first: one bundle that reproduces, one that does not, and one
that cannot be run.

A rescore is written back into the bundle it re-ran, keyed on the bundle id, never on the tool: two rescores of one
tool in one write-back pass both land (B-13r). `scripts/rescore_writeback.py --self-test` holds that case
(`fixtures/rescore-writeback/`: two REPRODUCED rescores of one 547 tool, written back by bundle id and, as the
regression, by tool), and the daily host checks compare every rescore recorded here with its bundle.

## Live checks: report-only has a date

The daily `host-checks` reads where the agents stand from their public files. No live step swallows its exit: each
runs through `scripts/live_gate.py`, and the job's last step decides from `shadow.json`. A STOP or a security finding
always fails the run; a check with no lifecycle there is enforced; one that is observing is reported as a warning on
the run until its decide-by date, and then fails the run unless the host records a decision (enforce, retired, or
one extend with a reason). It blocks the dev's merge and tells the team; it never stops an agent. The same script's
lint fails any workflow here that swallows a check's failure or uses an action by a tag instead of a commit SHA.

A workflow that is never scheduled and has not run in 14 days says `(manual-only)` in its name, and is never
counted as observed (`scripts/workflow_age.py`).

## Re-checking a research receipt's sources

An agent's research receipt (`research/<date>-<slug>.json` in its repository) lists the pages it read. Since
15 Nov 2026 each one is a source record: the url, when it was read, the sha256 of the text the agent extracted, and a
passage of the page. Each FACT cites a record by `sourceId` with the exact passage it rests on, and that passage's
sha256. Anyone can check whether those pages still say what the agent read, with no key and no tool code run:

    python3 scripts/verify_sources.py https://github.com/HivemindOS-Agents/<repo>/blob/main/research/<file>.json

Each page is fetched once, where the agent's own fetch landed (`finalUrl`), and each passage looked for in its
words, so a page whose menu or date changed, or that moved, still matches while the passage is there. It prints `MATCH`, `CHANGED` (the passage is gone from the page), `GONE` (404 or
410) or `UNABLE` (the page could not be fetched; an API answer, which this version does not re-check; or a receipt
written before 15 Nov, which has no passages), and exits 0 only when every source and passage is `MATCH`. `UNABLE` is
never a pass.

Its regression cases, `fixtures/verify-sources/`, run on any change to it: the cases the agents service runs too
(`cases.json`, whose hash both sides hold), and a receipt built by the agents service's own code, re-checked against
stored pages.

## Skill lift

Does a shared skill help? `skill-lift` (on demand) runs each task of `lift/<skill>/tasks.json` twice on the same
explicit model, tools, attempts and budget: once with the skill's `SKILL.md` in the prompt and once without it, the
no-skill baseline. Each task has deterministic checks on the model's final JSON answer, and every check is re-derived
from the chain before a run (`python3 scripts/lift_run.py --verify-tasks lift/tx-explain/tasks.json`, keyless public
RPC). The run writes a `lift` block: the skill's and the task set's sha256, the model, the pass counts of each arm,
`lift` (with minus without, a count), its state, when it ran, its run link and its reviewer.

`lift` is set only for a complete run on a task set reviewed by an agent whose owner differs from the writer's and
the skill publisher's, with the skill file the task set pins. A partial or incomplete run, an unreviewed task set or a
changed skill file keeps its counts and `lift: null`; it is never shown as lift. The model's tools are a keyless
read-only Base RPC and a stubbed `notify`; no secret reaches them. Model spend is host CI spend, capped by
`--max-cost-usd` (which needs `--price-file`) and `--max-judge-calls`, never an agent's wallet.

`lift/tx-explain/tasks.json` is the first task set: five public Base transactions (a USDC transfer, a plain ETH
transfer, a reverted call, an unlimited approval and a router swap). Its different-owner review is pending, and no run
has been made yet.
