"""Row 102, guard 263 (25 Nov 2026 dev update; replaces 24 Nov §26's generatedAt test, guard 26): a feed is current only
while its newest content timestamp (top-level updatedAt, or the newest per-item updatedAt or startedAt) is at most 48 h
old, whatever its generatedAt says. A stale feed that catches up is diffed against the 30-day backfill window, and a
caught-up feed with no diff is a fail. No network.

  python3 -m unittest discover -s tests -p 'test_feed_freshness.py'

fixtures/feed-freshness/pwn-watch-incidents-2026-11-25.json is pwn.watch/incidents.json's head as served on 26 Nov
2026: rebuilt on 25 Nov (generatedAt 2026-11-25T13:20:55Z) with its updatedAt and newest incident still at
2026-11-10T01:13:32Z."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "feed-freshness"
spec = importlib.util.spec_from_file_location("feed_freshness", ROOT / "scripts" / "feed_freshness.py")
ff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ff)

NOW = "2026-11-25T12:00:00Z"
PWN = json.loads((FIX / "pwn-watch-incidents-2026-11-25.json").read_text())


class Freshness(unittest.TestCase):
    def test_generated_now_updated_15_days_ago_is_stale(self):
        feed = {"generatedAt": NOW, "updatedAt": "2026-11-10T12:00:00Z", "incidents": [{"slug": "a", "updatedAt": "2026-11-09T00:00:00Z"}]}
        got = ff.freshness(feed, NOW)
        self.assertEqual(got["state"], "stale")
        self.assertEqual(got["newest"], "2026-11-10T12:00:00Z")
        self.assertEqual(round(got["ageHours"]), 15 * 24)

    def test_the_pwn_watch_snapshot_reads_stale(self):
        got = ff.freshness(PWN, "2026-11-25T13:30:00Z")
        self.assertEqual((got["state"], got["newest"]), ("stale", "2026-11-10T01:13:32Z"))

    def test_the_newest_item_wins_over_an_older_top_level_stamp(self):
        feed = {"generatedAt": "2026-11-01T00:00:00Z", "updatedAt": "2026-11-10T00:00:00Z",
                "incidents": [{"slug": "x", "startedAt": "2026-11-24"}, {"slug": "y", "updatedAt": "2026-11-25T01:00:00Z"}]}
        self.assertEqual(ff.freshness(feed, NOW)["newest"], "2026-11-25T01:00:00Z")
        self.assertEqual(ff.freshness(feed, NOW)["state"], "current")

    def test_generated_at_alone_never_makes_a_feed_current(self):
        for feed in ({"generatedAt": NOW}, {"generatedAt": NOW, "builtAt": NOW, "items": [{"title": "no time"}]}):
            with self.subTest(feed=feed):
                self.assertEqual(ff.freshness(feed, NOW)["state"], "no_content_time")
                self.assertFalse(ff.is_current(feed, NOW))

    def test_48_hours_is_the_edge(self):
        self.assertEqual(ff.freshness({"updatedAt": "2026-11-23T12:00:00Z"}, NOW)["state"], "current")
        self.assertEqual(ff.freshness({"updatedAt": "2026-11-23T11:59:59Z"}, NOW)["state"], "stale")

    def test_a_date_only_started_at_counts_from_its_day(self):
        self.assertEqual(ff.freshness({"incidents": [{"startedAt": "2026-11-24"}]}, NOW)["newest"], "2026-11-24T00:00:00Z")


class CatchUp(unittest.TestCase):
    BACKFILL = [
        {"title": "Office Party", "date": "2026-11-09", "source": "Dark Reading"},
        {"title": "bee-js / Swarm Desktop compromise", "date": "2026-11-09", "source": "Socket", "ids": ["GHSA-hh7j-5m3j-23pf"]},
        {"title": "An incident from August", "date": "2026-08-01", "source": "x"},
    ]

    def caught_up_feed(self):
        return {"generatedAt": "2026-11-26T09:00:00Z", "updatedAt": "2026-11-26T08:00:00Z",
                "incidents": [{"slug": "swarm-desktop-bee-js-npm-compromise", "title": "bee-js and Swarm Desktop npm compromise",
                               "cveIds": ["GHSA-hh7j-5m3j-23pf"], "updatedAt": "2026-11-26T08:00:00Z"}]}

    def test_a_caught_up_feed_is_diffed_and_its_gaps_reported(self):
        got = ff.catch_up({"state": "stale"}, self.caught_up_feed(), self.BACKFILL, "2026-11-26T10:00:00Z")
        self.assertTrue(got["caughtUp"] and got["diffed"])
        self.assertEqual([g["title"] for g in got["gaps"]], ["Office Party"])

    def test_a_caught_up_feed_with_no_backfill_fails(self):
        got = ff.catch_up({"state": "stale"}, self.caught_up_feed(), None, "2026-11-26T10:00:00Z")
        self.assertTrue(got["caughtUp"])
        self.assertFalse(got["diffed"])
        self.assertTrue(got["problems"])

    def test_no_catch_up_while_stale_or_when_it_never_lapsed(self):
        self.assertFalse(ff.catch_up({"state": "stale"}, PWN, self.BACKFILL, NOW)["caughtUp"])
        self.assertFalse(ff.catch_up({"state": "current"}, self.caught_up_feed(), None, "2026-11-26T10:00:00Z")["caughtUp"])
        self.assertFalse(ff.catch_up(None, self.caught_up_feed(), None, "2026-11-26T10:00:00Z")["caughtUp"])


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        done = subprocess.run([sys.executable, str(ROOT / "scripts" / "feed_freshness.py"), *map(str, args)], capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout + done.stderr

    def test_the_snapshot_file_reads_stale_and_exits_1(self):
        code, said = self.run_cli(FIX / "pwn-watch-incidents-2026-11-25.json", "--now", "2026-11-25T13:30:00Z")
        self.assertEqual(code, 1, said)
        self.assertIn("stale", said)

    def test_state_carries_a_lapse_to_the_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, feed = pathlib.Path(tmp) / "state.json", pathlib.Path(tmp) / "feed.json"
            code, said = self.run_cli(FIX / "pwn-watch-incidents-2026-11-25.json", "--now", "2026-11-25T13:30:00Z", "--state", state)
            self.assertEqual(code, 1, said)
            feed.write_text(json.dumps({"generatedAt": "2026-11-26T09:00:00Z", "updatedAt": "2026-11-26T08:00:00Z", "incidents": []}))
            code, said = self.run_cli(feed, "--now", "2026-11-26T10:00:00Z", "--state", state, "--name", "pwn-watch-incidents-2026-11-25.json")
            self.assertEqual(code, 1, said)
            self.assertIn("caught up", said)
            self.assertIn("not diffed", said)

    def test_an_empty_or_unparseable_feed_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            for text, reason in (("", "empty_security_setting"), ("{x", "unparseable_security_setting")):
                path = pathlib.Path(tmp) / "f.json"
                path.write_text(text)
                code, said = self.run_cli(path, "--now", NOW)
                self.assertEqual(code, 2, said)
                self.assertIn(reason, said)
                self.assertNotIn("Traceback", said)


if __name__ == "__main__":
    unittest.main()
