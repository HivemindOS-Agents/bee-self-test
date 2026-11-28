Guard 53's fixtures (24 Nov 2026 dev update, section 32.1). Each `bad-*.txt` is a line the guard names, copied from
the commit before the chain config (`CHAIN = 8453` and the publicnode RPC in source_match.py, the pinned RPC in
tests/test_lift_run.py, the pinned quote network in tests/test_bazaar_weekly.py), or the same class on Robinhood
Chain (its hex id, its RPC and explorer hosts, the two testnet ids). `scripts/chain_literals.py --self-test` must find a
literal in each, and none in the `good-*.txt` files: the fixed lines, and digits that are not a chain id.
