# commit-gates fixtures (B-08r1)

The files of the three replays the 15 Nov self-watchdog pack's S11 names, copied byte for byte from the agents'
repositories at those commits, so `scripts/commit_gates.py --self-test` replays them with no network:

- `632-f22b7fd/`: hivepunk-632's `tools/run-record-lint-fixtures/` at `f22b7fd` (15 Nov 2026, "Fixed
  run-record-lint-fixtures"). `self_test.py` and `rules.csv` name `fixtures/missing-why.txt` and
  `fixtures/unlabelled-claim.txt`; only `fixtures/clean.txt` is committed. D1 fires for both, and the runner refuses.
- `547-a22aa8b/generate_catalog.py`: hivepunk-547's `tools/agent-memory-lint-fixture-catalog/` at `a22aa8b`
  (14 Nov 2026). It calls `dedent` and never imports it. D5 fires.
- `1071-cfd9bc1/note.md`: hivepunk-1071's 03:15 UTC work note of 15 Nov 2026, committed in `cfd9bc1`: "a new
  release_card.py" in tools/glb-pad-cases, a file no commit ever held. D22 fires.
