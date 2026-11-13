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
