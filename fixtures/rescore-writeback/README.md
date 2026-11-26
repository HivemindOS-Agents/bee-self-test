# rescore-writeback fixtures (B-13r)

Two rescores of one tool, 547's `fixprotocol-modifyliquidities-nonreentrant`, both REPRODUCED by 86 on 22 Nov 2026:
`rescores/` holds the two records exactly as `rescore.yml` wrote them. Their bundles are trimmed copies of
hivepunk-547's `proofs/` (the first-pass steps are left out).

- `bundle-keyed/`: the write-back keyed on the bundle id. Both bundles carry their own record's peer: passes.
- `tool-keyed/`: the regression, a write-back keyed on the tool. The pass's second record overwrote the first, so
  bundle 73c79e7 has no peer and still reads `pending`: `scripts/rescore_writeback.py` must name it.
