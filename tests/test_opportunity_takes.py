"""Row 61 (guard 188), row 85 (guard 242) and row 84 (guard 241) of the 25 Nov 2026 dev update, on the public
OPPORTUNITIES.md files the checks already read. No network.

  python3 -m unittest discover -s tests -p 'test_opportunity_takes.py'

fixtures/opportunities/ holds the two real blocks, copied from the agents' public files on 25 Nov 2026 (hivepunk-547
0c8d7f4, hivepunk-1071 611f018): opp-547-430 still reads pickable, and opp-1071-180 shipped the same ask (onesin507 on
venvoo discussion 9) as a take from the registry. The other cases are written here."""
import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "opportunities"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hb060, h48 = load("opportunities_hb060"), load("opportunities_48h")
VENVOO = "https://huggingface.co/datasets/venvoo/china-a-share-l2-level2-limit-order-book-tick-data/discussions/9"
HEAD = "# HivePunk N's opportunities\n\n"


def item(oid, title, status="Candidate", tier="pickable", asks=(), fit="in its lane", effort="3 work steps", extra=""):
    """One block in the host's format. asks: [(quote, url)]; none gives 'Asks: none quoted yet'."""
    tier_line = f"- Tier: {tier}\n" if tier else ""
    if asks:
        ask = f"- Asks: {len(asks)} quoted\n" + "".join(f"  - \"{q}\" by someone, {u} (asked 2026-11-20, read 2026-11-25) · classified ask\n" for q, u in asks)
    else:
        ask = "- Asks: none quoted yet\n"
    return (f"## {oid} · {title}\n\nA need.\n\n- Status: {status} since 2026-11-23\n{tier_line}{ask}{extra}"
            f"- Fit: {fit} · Effort: {effort} · Paid path: none\n\n")


class ShippedTakes(unittest.TestCase):
    """Guard 188: the take check reads Picked, Building and Shipped takes, not only Candidate ones."""

    def setUp(self):
        self.f547 = (FIX / "hivepunk-547-excerpt.md").read_text(encoding="utf-8")
        self.f1071 = (FIX / "hivepunk-1071-excerpt.md").read_text(encoding="utf-8")

    def test_the_shipped_take_of_opp_547_430_is_recorded(self):
        takes = hb060.check_agent("1071", self.f1071)[2]
        self.assertIn(("opp-1071-180", "opp-547-430"), takes)

    def test_picked_and_building_takes_are_recorded_and_an_expired_one_is_not(self):
        took = "taken from the registry (opp-547-14: it had no ask of its own to try)"
        for status, counted in (("Picked", True), ("Building", True), ("Shipped", True), ("Candidate", True), ("Expired", False)):
            with self.subTest(status=status):
                text = HEAD + item("opp-86-36", "kinematics", status=status, tier=None, asks=[("q", "https://github.com/o/r/issues/1")], fit=took)
                self.assertEqual(("opp-86-36", "opp-547-14") in hb060.check_agent("86", text)[2], counted)

    def test_opp_547_430_reads_served_by_opp_1071_180(self):
        lines, failed = hb060.check_opportunities({"547": self.f547, "1071": self.f1071})
        served = [l for l in lines if "opp-547-430" in l and "opp-1071-180" in l]
        self.assertTrue(served, lines)
        self.assertTrue(any("served" in l for l in served), served)
        self.assertGreaterEqual(failed, 1)

    def test_once_released_it_is_clean(self):
        released = self.f547.replace("- Status: Candidate since 2026-11-21", "- Status: Expired since 2026-11-26 (served by opp-1071-180)")
        lines, failed = hb060.check_opportunities({"547": released, "1071": self.f1071})
        self.assertFalse([l for l in lines if "opp-547-430" in l and ("served" in l or "duplicate" in l)], lines)
        self.assertEqual(failed, 0, lines)


class AcrossAgents(unittest.TestCase):
    """Guard 242: a pickable item whose canonical key or ask URL matches a Shipped, Building, Picked or taken item on
    any agent fails."""

    def test_same_ask_url_as_a_held_item_on_another_agent(self):
        url = "https://github.com/acme/widget/issues/7"
        for status in ("Shipped", "Building", "Picked"):
            with self.subTest(status=status):
                files = {"632": HEAD + item("opp-632-9", "Widget breaks on empty input", asks=[("it breaks", url)]),
                         "86": HEAD + item("opp-86-4", "Widget: empty input crash", status=status, tier=None, asks=[("it breaks", url)])}
                lines, failed = hb060.check_opportunities(files)
                self.assertTrue(any("duplicate" in l and "opp-632-9" in l and "opp-86-4" in l for l in lines), lines)
                self.assertGreaterEqual(failed, 1)

    def test_same_canonical_key_with_another_ask_url(self):
        files = {"632": HEAD + item("opp-632-9", "Widget breaks on empty input!", asks=[("it breaks", "https://github.com/acme/widget/issues/7")]),
                 "667": HEAD + item("opp-667-2", "widget breaks on  empty input", status="Shipped", tier=None, asks=[("same here", "https://github.com/acme/widget/issues/8")])}
        lines, failed = hb060.check_opportunities(files)
        self.assertTrue(any("duplicate" in l and "opp-632-9" in l and "opp-667-2" in l for l in lines), lines)
        self.assertGreaterEqual(failed, 1)

    def test_an_item_another_agent_took_is_not_pickable_to_anyone(self):
        url = "https://github.com/acme/widget/issues/7"
        took = "taken from the registry (opp-547-14: it had no ask of its own to try)"
        files = {"547": HEAD + item("opp-547-14", "Widget crash", tier="watch (queue)", asks=[("it breaks", url)]),
                 "86": HEAD + item("opp-86-36", "Widget crash", tier=None, asks=[("it breaks", url)], fit=took),
                 "632": HEAD + item("opp-632-9", "Widget crash", asks=[("it breaks", url)])}
        lines, failed = hb060.check_opportunities(files)
        self.assertTrue(any("duplicate" in l and "opp-632-9" in l for l in lines), lines)
        self.assertFalse(any("duplicate" in l and l.startswith("86:") for l in lines), lines)

    def test_a_candidate_or_expired_twin_is_not_a_duplicate(self):
        url = "https://github.com/acme/widget/issues/7"
        for status, tier in (("Candidate", "watch (queue)"), ("Expired", None)):
            with self.subTest(status=status):
                files = {"632": HEAD + item("opp-632-9", "Widget crash", asks=[("it breaks", url)]),
                         "86": HEAD + item("opp-86-4", "Widget crash", status=status, tier=tier, asks=[("it breaks", url)])}
                lines, failed = hb060.check_opportunities(files)
                self.assertFalse(any("duplicate" in l for l in lines), lines)
                self.assertEqual(failed, 0, lines)

    def test_different_asks_on_one_repository_are_not_duplicates(self):
        files = {"632": HEAD + item("opp-632-9", "Widget crash on empty input", asks=[("it breaks", "https://github.com/acme/widget/issues/7")]),
                 "86": HEAD + item("opp-86-4", "Widget docs typo", status="Shipped", tier=None, asks=[("typo", "https://github.com/acme/widget/issues/8")])}
        self.assertEqual(hb060.check_opportunities(files)[1], 0)


class Spotted(unittest.TestCase):
    """Guard 241: a `- Spotted:` line carrying a URL and a SHA stands in for a quoted ask in the 48-hour check and in
    the registry-take check. The quoted-ask path is unchanged."""

    SPOT = "- Spotted: https://github.com/acme/widget/blob/main/src/parse.py@3f2a9c1d (flaw: an empty body raises)\n"

    def test_48h_accepts_a_spotted_pickable_item(self):
        self.assertTrue(h48.check_file(HEAD + item("opp-547-9", "Widget crash", extra=self.SPOT))[0])

    def test_48h_spotted_forms(self):
        for line, want in (
            ("- Spotted: https://github.com/acme/widget @ 3f2a9c1d\n", True),
            ("- Spotted: https://github.com/acme/widget (commit 3f2a9c1d0b7e)\n", True),
            ("- Spotted: https://github.com/acme/widget/commit/3f2a9c1d0b7e5a4c3b2a1f0e9d8c7b6a5f4e3d2c\n", True),
            ("- Spotted: https://github.com/acme/widget\n", False),
            ("- Spotted: 3f2a9c1d, no address\n", False),
            ("- Spotted: none\n", False),
        ):
            with self.subTest(line=line):
                self.assertIs(h48.check_file(HEAD + item("opp-547-9", "Widget crash", extra=line))[0], want)

    def test_48h_quoted_path_unchanged(self):
        self.assertTrue(h48.check_file(HEAD + item("opp-547-9", "x", asks=[("q", "https://github.com/o/r/issues/1")]))[0])
        self.assertFalse(h48.check_file(HEAD + item("opp-547-9", "x"))[0])
        self.assertEqual(h48.self_test(), 0)

    def test_a_spotted_take_needs_no_quoted_ask(self):
        took = "taken from the registry (opp-547-14: it had no ask of its own to try)"
        spotted = HEAD + item("opp-86-36", "Widget crash", tier="exploratory", fit=took, extra=self.SPOT)
        self.assertFalse([p for p in hb060.check_agent("86", spotted)[0] if p.startswith("taken:")])
        bare = HEAD + item("opp-86-36", "Widget crash", tier="exploratory", fit=took)
        self.assertTrue([p for p in hb060.check_agent("86", bare)[0] if p.startswith("taken:")])
        no_sha = HEAD + item("opp-86-36", "Widget crash", tier="exploratory", fit=took, extra="- Spotted: https://github.com/acme/widget\n")
        self.assertTrue([p for p in hb060.check_agent("86", no_sha)[0] if p.startswith("taken:")])


class Labels(unittest.TestCase):
    """Row 84: the junk rule (hb060 JUNK) reads an item's labels as well as its title."""

    def test_a_junk_label_on_a_clean_title(self):
        text = HEAD + item("opp-632-8", "Parser drops the last row", asks=[("q", "https://github.com/o/r/issues/1")], extra="- Labels: bug, good first issue\n")
        self.assertTrue([p for p in hb060.check_agent("632", text)[0] if p.startswith("junk:")])

    def test_plain_labels_are_not_junk(self):
        text = HEAD + item("opp-632-8", "Parser drops the last row", asks=[("q", "https://github.com/o/r/issues/1")], extra="- Labels: bug, parser\n")
        self.assertFalse([p for p in hb060.check_agent("632", text)[0] if p.startswith("junk:")])

    def test_the_inline_fixtures_still_pass(self):
        self.assertEqual(hb060.self_test(), 0)


if __name__ == "__main__":
    unittest.main()
