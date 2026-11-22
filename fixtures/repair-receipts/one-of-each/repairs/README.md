One file of each kind the host writes into an agent's repairs/ folder, each read by its one owning check:

- `<repair>--e<k>.json`, a receipt: `scripts/repair_receipts.py`
- `<repair>--e<k>.recheck.json`, its recheck seven days later: `scripts/repair_receipts.py`
- `<repair>--e<k>.honest-failure.json`, an honest-failure row: `scripts/kept_rules.py`

Every check reads this folder with 0 problems (HB-067 D).
