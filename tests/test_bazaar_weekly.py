"""Canned-response tests of scripts/bazaar_weekly.py: the rank parsing, the Inspect parsing, the pacing and the rule
that an incomplete run is never published as complete. No network.

  python3 -m unittest discover -s tests -p 'test_bazaar_weekly.py'"""
import base64, json, os, pathlib, sys, tempfile, unittest, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import bazaar_weekly as bw  # noqa: E402

HOSTS = ["api.hivemindos.app", "hivemindos-paid-agent-gateway.hivemindos.workers.dev"]
WEB = "https://api.hivemindos.app/v1/x402/web-data/web.search"
GW = "https://hivemindos-paid-agent-gateway.hivemindos.workers.dev/api/x402/catalog"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def res(url, payers=None, calls=None):
    r = {"resource": url}
    if payers is not None:
        r["quality"] = {"l30DaysUniquePayers": payers, "l30DaysTotalCalls": calls}
    return r


def search(*results, method="hybrid"):
    return {"resources": list(results), "partialResults": False, "searchMethod": method, "x402Version": 2}


class RankParsing(unittest.TestCase):
    def test_best_rank_is_the_first_hive_hit(self):
        data = search(res("https://other.example/search", 29, 56), res("https://x.example/a"), res(GW, 5, 9), res(WEB, 2, 22))
        row = bw.parse_rank(data, HOSTS, expected=[WEB])
        self.assertEqual(row["bestRank"], 3)
        self.assertEqual(row["resource"], GW)
        self.assertFalse(row["resourceIsExpected"])
        self.assertEqual(row["expectedFound"], [WEB])
        self.assertEqual((row["l30DaysUniquePayers"], row["l30DaysTotalCalls"]), (5, 9))
        self.assertEqual([h["rank"] for h in row["hiveHits"]], [3, 4])
        self.assertEqual(row["top"], {"host": "other.example", "resource": "https://other.example/search", "l30DaysUniquePayers": 29})
        self.assertEqual((row["resultCount"], row["searchMethod"]), (4, "hybrid"))

    def test_absent_when_no_hive_host(self):
        row = bw.parse_rank(search(res("https://a.example/x", 1, 1)), HOSTS)
        self.assertEqual(row["bestRank"], "absent")
        self.assertIsNone(row["resource"])
        self.assertEqual(row["hiveHits"], [])

    def test_lookalike_host_is_not_a_hit(self):
        row = bw.parse_rank(search(res("https://api.hivemindos.app.evil.example/v1"), res("https://evil.example/api.hivemindos.app")), HOSTS)
        self.assertEqual(row["bestRank"], "absent")

    def test_missing_quality_is_not_read_never_zero(self):
        row = bw.parse_rank({"resources": [res(WEB)]}, HOSTS)
        self.assertEqual(row["bestRank"], 1)
        self.assertEqual(row["l30DaysUniquePayers"], "not-read")
        self.assertEqual(row["l30DaysTotalCalls"], "not-read")
        self.assertEqual(row["searchMethod"], "not-read")
        self.assertEqual(row["partialResults"], "not-read")

    def test_empty_results(self):
        row = bw.parse_rank(search(), HOSTS)
        self.assertEqual((row["bestRank"], row["top"], row["resultCount"]), ("absent", None, 0))

    def test_answer_without_resources_is_incomplete(self):
        with self.assertRaises(bw.Incomplete):
            bw.parse_rank({"error": "x"}, HOSTS)


class InspectParsing(unittest.TestCase):
    OFFER = {"x402Version": 2, "accepts": [
        {"network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "amount": "1000", "asset": "EPj", "payTo": "4sy"},
        {"network": "eip155:8453", "amount": "1000", "asset": "0x8335", "payTo": "0x9636"}]}

    def test_402_is_indexed_with_the_base_quote(self):
        row = bw.parse_inspect(402, {}, json.dumps(self.OFFER).encode())
        self.assertEqual(row["status"], "indexed")
        self.assertEqual(row["quote"], {"network": "eip155:8453", "amount": "1000", "asset": "0x8335", "payTo": "0x9636"})

    def test_402_quote_from_the_header_when_the_body_has_none(self):
        header = base64.b64encode(json.dumps(self.OFFER).encode()).decode()
        row = bw.parse_inspect(402, {"payment-required": header}, b"{}")
        self.assertEqual(row["quote"]["amount"], "1000")

    def test_402_without_a_base_offer_keeps_quote_not_read(self):
        row = bw.parse_inspect(402, {}, b"{}")
        self.assertEqual((row["status"], row["quote"]), ("indexed", "not-read"))

    def test_404_not_indexed(self):
        body = json.dumps({"error": {"code": "ENDPOINT_NOT_INDEXED"}}).encode()
        self.assertEqual(bw.parse_inspect(404, {}, body)["status"], "not-indexed")

    def test_other_answers_are_neither(self):
        self.assertIsNone(bw.parse_inspect(404, {}, json.dumps({"error": {"code": "OTHER"}}).encode()))
        self.assertIsNone(bw.parse_inspect(502, {}, json.dumps({"error": {"code": "UPSTREAM_UNAVAILABLE"}}).encode()))
        self.assertIsNone(bw.parse_inspect(200, {}, b"{}"))


class Pacing(unittest.TestCase):
    def test_never_more_than_the_limit_in_a_minute(self):
        t = [0.0]
        sent = []

        def sleep(s):
            t[0] += s

        pace = bw.Pace(20, lambda: t[0], sleep)
        for _ in range(45):
            pace.wait()
            sent.append(t[0])
            t[0] += 0.1
        for i in range(len(sent) - 20):
            self.assertGreaterEqual(sent[i + 20] - sent[i], 60)


FIXTURE = json.loads((ROOT / "fixtures" / "bazaar-intents" / "bazaar-intents.json").read_bytes())


class FakeApis:
    """Canned Bazaar and Agents Trust answers. `search_failures` maps a query to how many non-200s it answers first."""

    def __init__(self, search_failures=None, inspect=None):
        self.search_failures = dict(search_failures or {})
        self.inspect = inspect or (lambda url: (402, {}, json.dumps(InspectParsing.OFFER).encode()))
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query))
        if parsed.path.endswith("/discovery/merchant"):
            return 200, {}, json.dumps({"resources": [res(WEB), res(GW), res("https://other.example/x")],
                                        "pagination": {"total": 3, "offset": 0, "limit": 100}}).encode()
        if parsed.path.endswith("/discovery/search") and "urlSubstring" in q:
            return 200, {}, json.dumps(search()).encode()
        if parsed.path.endswith("/discovery/search"):
            self.assertNoQ(q)
            left = self.search_failures.get(q["query"], 0)
            if left:
                self.search_failures[q["query"]] = left - 1
                return 503, {}, b'{"errorType":"unavailable"}'
            return 200, {}, json.dumps(search(res("https://other.example/s", 3, 4), res(WEB, 2, 22))).encode()
        if parsed.netloc == "api.agents-trust.com":
            return self.inspect(q["url"])
        raise AssertionError("unexpected url " + url)

    @staticmethod
    def assertNoQ(q):
        assert "q" not in q and "query" in q, "the search parameter is query, never q"


def run_with(fake):
    out = tempfile.mkdtemp()
    problems, written = bw.run(FIXTURE, bw.FIXTURE_SHA256, out, "2026-11-16", get=fake, sleep=lambda s: None, clock=lambda: 0.0)
    return out, problems, written


def not_indexed_control(url):
    if "never-listed" in url:
        return 404, {}, json.dumps({"error": {"code": "ENDPOINT_NOT_INDEXED"}}).encode()
    return 402, {}, json.dumps(InspectParsing.OFFER).encode()


class Incompleteness(unittest.TestCase):
    def test_a_search_failing_three_times_is_never_published_as_complete(self):
        query = FIXTURE["intents"][4]["query"]
        out, problems, written = run_with(FakeApis(search_failures={query: 3}, inspect=not_indexed_control))
        folder = os.path.join(out, "reports", "bazaar-intent-rank")
        self.assertFalse(os.path.exists(os.path.join(folder, "2026-11-16.json")))
        board = load_json(os.path.join(folder, "2026-11-16.incomplete.json"))
        self.assertFalse(board["complete"])
        self.assertIn("after 2 retries", board["incompleteReason"])
        self.assertTrue(any(p.startswith("rank board incomplete") for p in problems))
        self.assertIn("INCOMPLETE", pathlib.Path(folder, "2026-11-16.incomplete.md").read_text())

    def test_two_failures_then_200_completes(self):
        query = FIXTURE["intents"][0]["query"]
        fake = FakeApis(search_failures={query: 2}, inspect=not_indexed_control)
        out, problems, written = run_with(fake)
        board = load_json(os.path.join(out, "reports", "bazaar-intent-rank", "2026-11-16.json"))
        self.assertTrue(board["complete"])
        self.assertEqual(board["rows"][0]["attempts"], 3)
        self.assertEqual(board["counts"]["intents"], 20)
        self.assertEqual(board["counts"]["hiveInTop20"], 20)
        self.assertEqual(board["listed"]["count"], 2)

    def test_expected_resource_no_longer_listed_fails_a_complete_run(self):
        out, problems, written = run_with(FakeApis(inspect=not_indexed_control))
        board = load_json(os.path.join(out, "reports", "bazaar-intent-rank", "2026-11-16.json"))
        self.assertTrue(board["complete"])
        self.assertTrue(board["counts"]["expectedResourceNotListed"] > 0)
        self.assertTrue(any("no longer listed" in p for p in problems))

    def test_a_sweep_row_left_not_read_marks_the_index_board_incomplete(self):
        def flaky(url):
            if url == WEB:
                return 502, {}, json.dumps({"error": {"code": "UPSTREAM_UNAVAILABLE"}}).encode()
            return not_indexed_control(url)

        out, problems, written = run_with(FakeApis(inspect=flaky))
        folder = os.path.join(out, "reports", "agents-trust-index")
        self.assertFalse(os.path.exists(os.path.join(folder, "2026-11-16.json")))
        board = load_json(os.path.join(folder, "2026-11-16.incomplete.json"))
        self.assertEqual(board["counts"], {"listed": 2, "indexed": 1, "notIndexed": 0, "notRead": 1})
        self.assertEqual(next(r for r in board["rows"] if r["url"] == WEB)["status"], "not-read")

    def test_control_indexed_is_flagged(self):
        out, problems, written = run_with(FakeApis())
        board = load_json(os.path.join(out, "reports", "agents-trust-index", "2026-11-16.json"))
        self.assertFalse(board["control"]["ok"])
        self.assertTrue(any(p.startswith("control-not-as-expected") for p in problems))

    def test_never_sends_a_payment_header(self):
        req = []
        real = bw.urllib.request.urlopen
        bw.urllib.request.urlopen = lambda r, timeout=40: req.append(r) or (_ for _ in ()).throw(OSError("offline"))
        try:
            bw.http_get("https://api.agents-trust.com/inspect?url=x")
        finally:
            bw.urllib.request.urlopen = real
        headers = {k.lower() for k in req[0].headers}
        self.assertFalse(headers & {"x-payment", "payment-signature", "authorization"})


class FixtureShape(unittest.TestCase):
    def test_the_fixture_is_sound(self):
        raw = (ROOT / "fixtures" / "bazaar-intents" / "bazaar-intents.json").read_bytes()
        self.assertEqual(bw.check_fixture(json.loads(raw), raw), [])

    def test_nineteen_intents_fail(self):
        fx = json.loads(json.dumps(FIXTURE))
        fx["intents"].pop()
        self.assertIn("19 intents, not 20", bw.check_fixture(fx))

    def test_out_of_scope_needs_a_dated_note(self):
        fx = json.loads(json.dumps(FIXTURE))
        it = next(i for i in fx["intents"] if i["expect"] == "out_of_scope")
        it["note"] = "pending"
        self.assertTrue(any("dated note" in b for b in bw.check_fixture(fx)))


if __name__ == "__main__":
    unittest.main()
