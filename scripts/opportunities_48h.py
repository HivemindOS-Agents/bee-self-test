#!/usr/bin/env python3
"""HB-056's 48-hour check (Liam's 18 Nov 2026 pack, section 7.6): each active agent's public OPPORTUNITIES.md has at
least one item whose Tier is exploratory or pickable and whose Asks line quotes an ask (not "none quoted yet").

Reads the files from GitHub's raw host, keyless and read-only. Exit 0 only when every agent passes. The clock starts
at the first scout after HB-056 landed, so a fail before then says only where the queue stands.

    python3 scripts/opportunities_48h.py                # the five active agents
    python3 scripts/opportunities_48h.py 547 632        # some of them
    python3 scripts/opportunities_48h.py --self-test    # the fixtures only, no network
"""
import re
import sys
import urllib.request

AGENTS = ["547", "632", "667", "1071", "86"]
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/hivepunk-{n}/main/OPPORTUNITIES.md"


def check_file(text):
    """(passes, why). An item block starts at '## opp-'; it passes with a Tier of exploratory or pickable and an Asks
    line that quotes something."""
    blocks = re.split(r"\n(?=## opp-)", text or "")
    for block in blocks:
        if not block.startswith("## opp-"):
            continue
        tier = re.search(r"^- Tier:\s*(exploratory|pickable)\b", block, re.M | re.I)
        asks = re.search(r"^- Asks:\s*(.+)$", block, re.M)
        if tier and asks and "none quoted yet" not in asks.group(1).lower():
            return True, block.split("\n", 1)[0][3:].strip()
    if not re.search(r"^## opp-", text or "", re.M):
        return False, "no items"
    return False, "no exploratory or pickable item with a quoted ask"


def fetch(n):
    with urllib.request.urlopen(urllib.request.Request(RAW.format(n=n), headers={"user-agent": "bee-self-test-opportunities-48h"}), timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def main(argv):
    if "--self-test" in argv:
        return self_test()
    agents = [a for a in argv if a.isdigit()] or AGENTS
    failed = 0
    for n in agents:
        try:
            ok, why = check_file(fetch(n))
        except Exception as error:  # an unreadable file is a fail, said as such
            ok, why = False, f"could not read: {error}"
        failed += 0 if ok else 1
        print(f"{n}: {'PASS' if ok else 'FAIL'} ({why})")
    print("48-hour check:", "PASS" if not failed else f"FAIL ({failed} of {len(agents)})")
    return 0 if not failed else 1


def self_test():
    ok_md = "# HivePunk 547's opportunities\n\n## opp-547-3 · card check\n\n- Tier: exploratory (its one try at a single outside ask: no event, no paid path)\n- Demand: 1 distinct outside author (floor 2)\n- Asks: 1 quoted\n  - \"latest trading day is still 20261028\" by onesin507\n"
    pick_md = ok_md.replace("Tier: exploratory (its one try at a single outside ask: no event, no paid path)", "Tier: pickable")
    watch_md = ok_md.replace("Tier: exploratory", "Tier: watch (queue)")
    unquoted = ok_md.replace("- Asks: 1 quoted\n  - \"latest trading day is still 20261028\" by onesin507\n", "- Asks: none quoted yet\n")
    empty = "# HivePunk 667's opportunities\n\nNothing listed yet. Its next scout is within 72 hours.\n"
    cases = [
        (ok_md, True), (pick_md, True), (watch_md, False), (unquoted, False), (empty, False),
        (watch_md + "\n" + ok_md.split("\n\n", 1)[1].replace("opp-547-3", "opp-547-9"), True),
    ]
    n = 0
    for text, want in cases:
        got, _why = check_file(text)
        assert got is want, (want, text[:80])
        n += 1
    assert check_file(empty)[1] == "no items"
    print(f"self-test: {n + 1}/{n + 1} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
