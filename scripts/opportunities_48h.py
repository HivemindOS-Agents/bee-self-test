#!/usr/bin/env python3
"""HB-056's 48-hour check (Liam's 18 Nov 2026 pack, section 7.6): each active agent's public OPPORTUNITIES.md has at
least one item whose Tier is exploratory or pickable and whose Asks line quotes an ask (not "none quoted yet").

Since the 20 Nov 2026 update (Part 2): an item with a quoted ask that went on to Building or Shipped inside the window
counts too, so shipping its one exploratory item does not turn an agent red. On 20 Nov, 547 shipped opp-547-16 and
1071 had shipped opp-1071-10, each for a quoted outside ask, and both read FAIL. A quoted ask is still required, and
the pick floor of 2 askers is not lowered.

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
# The date the 48-hour clock started: the first scouts after HB-056 landed.
WINDOW_START = "2026-11-18"
STAGE = re.compile(r"^- Status:\s*(Building|Shipped) since (\d{4}-\d\d-\d\d)", re.M | re.I)
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/hivepunk-{n}/main/OPPORTUNITIES.md"


def check_file(text, window_start=WINDOW_START):
    """(passes, why). An item block starts at '## opp-'. It passes with an Asks line that quotes something and either a
    Tier of exploratory or pickable, or a Status of Building or Shipped since a date inside the window."""
    blocks = re.split(r"\n(?=## opp-)", text or "")
    moved_on = None
    for block in blocks:
        if not block.startswith("## opp-"):
            continue
        asks = re.search(r"^- Asks:\s*(.+)$", block, re.M)
        if not asks or "none quoted yet" in asks.group(1).lower():
            continue
        name = block.split("\n", 1)[0][3:].strip()
        if re.search(r"^- Tier:\s*(exploratory|pickable)\b", block, re.M | re.I):
            return True, name
        stage = STAGE.search(block)
        if stage and stage.group(2) >= window_start and moved_on is None:
            moved_on = f"{name} ({stage.group(1)} since {stage.group(2)})"
    if moved_on:
        return True, moved_on
    if not re.search(r"^## opp-", text or "", re.M):
        return False, "no items"
    return False, "no exploratory, pickable, building or shipped item with a quoted ask"


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
    print("48-hour check:", "PASS" if not failed else f"FAIL: {failed} of {len(agents)} agents fail")
    return 0 if not failed else 1


def self_test():
    ok_md = "# HivePunk 547's opportunities\n\n## opp-547-3 · card check\n\n- Tier: exploratory (its one try at a single outside ask: no event, no paid path)\n- Demand: 1 distinct outside author (floor 2)\n- Asks: 1 quoted\n  - \"latest trading day is still 20261028\" by onesin507\n"
    pick_md = ok_md.replace("Tier: exploratory (its one try at a single outside ask: no event, no paid path)", "Tier: pickable")
    watch_md = ok_md.replace("Tier: exploratory", "Tier: watch (queue)")
    unquoted = ok_md.replace("- Asks: 1 quoted\n  - \"latest trading day is still 20261028\" by onesin507\n", "- Asks: none quoted yet\n")
    empty = "# HivePunk 667's opportunities\n\nNothing listed yet. Its next scout is within 72 hours.\n"
    # 20 Nov, Part 2: an item with a quoted ask that went on inside the window counts; one with no ask, one that
    # went on before the window, and one that ended some other way do not.
    stage = lambda status: watch_md.replace("- Tier: watch (queue) (its one try at a single outside ask: no event, no paid path)\n", f"- Status: {status}\n")
    shipped, building = stage("Shipped since 2026-11-20 · runner: https://example.invalid/runs/1"), stage("Building since 2026-11-19")
    cases = [
        (ok_md, True), (pick_md, True), (watch_md, False), (unquoted, False), (empty, False),
        (watch_md + "\n" + ok_md.split("\n\n", 1)[1].replace("opp-547-3", "opp-547-9"), True),
        (shipped, True), (building, True),
        (stage("Shipped since 2026-11-17"), False), (stage("Expired since 2026-11-20 (duplicate of opp-1-1)"), False),
        (building.replace("- Asks: 1 quoted\n  - \"latest trading day is still 20261028\" by onesin507\n", "- Asks: none quoted yet\n"), False),
    ]
    assert "- Tier:" not in shipped and "Shipped since 2026-11-20" in shipped
    assert check_file(shipped)[1].endswith("(Shipped since 2026-11-20)")
    # An exploratory item is named before one that moved on, whatever their order in the file.
    assert check_file(shipped + "\n" + ok_md.split("\n\n", 1)[1].replace("opp-547-3", "opp-547-9"))[1].startswith("opp-547-9")
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
