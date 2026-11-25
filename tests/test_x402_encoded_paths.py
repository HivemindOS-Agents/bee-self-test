"""Guard 135 (24 Nov 2026 dev update, §45.7; 25 Nov row 41r3): for every keyless paid x402 operation in openapi.json,
unpaid requests with encoded path variants (%2F, %5C, %252F, and mixed case) never return 2xx. Fixture class: x402
issue #3850, where the paywall decoded the path while the router used the raw path. No network: the servers here are
functions.

  python3 -m unittest discover -s tests -p 'test_x402_encoded_paths.py'

fixtures/x402-encoded-paths/openapi-trimmed.json is 5 of the 125 paths of api.hivemindos.app/openapi.json as served
on 26 Nov 2026. The baseline it keeps: AI Research's unpaid check on 24 Nov, and ours on 26 Nov, sent 6 requests to
/v1/x402/web-data/web.search and got 402 for the plain path and 401 for the 5 encoded ones: no 2xx."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "x402-encoded-paths"
spec = importlib.util.spec_from_file_location("x402_encoded_paths", ROOT / "scripts" / "x402_encoded_paths.py")
xp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xp)

OPENAPI = json.loads((FIX / "openapi-trimmed.json").read_text())
PAID = {"/v1/x402/web-data/web.search", "/v1/x402/token-autopsy/reports.create"}


def views(path):
    """Every way a router might read the path: raw, decoded once, decoded until stable, backslashes as slashes."""
    out, p = {path}, path
    for _ in range(3):
        p = urllib.parse.unquote(p)
        out |= {p, p.replace("\\", "/")}
    return out


def routed(path):
    return any(v in PAID for v in views(path))


def vulnerable(method, url):
    """#3850's shape: the paywall asks for payment only when the once-decoded path is a paid route; the router serves
    any view that names one."""
    path = urllib.parse.urlsplit(url).path
    if urllib.parse.unquote(path) in PAID:
        return 402
    return 200 if routed(path) else 404


def fixed(method, url):
    """#3857's fix: payment is required if any view matches a paid route."""
    path = urllib.parse.urlsplit(url).path
    return 402 if routed(path) else 404


def hive_today(method, url):
    """What api.hivemindos.app answered on 26 Nov: 402 plain, 401 api_key_required for every encoded variant."""
    path = urllib.parse.urlsplit(url).path
    return 402 if path in PAID else 401


class PaidOperations(unittest.TestCase):
    def test_keyless_paid_x402_operations_are_read_from_openapi(self):
        ops = xp.paid_operations(OPENAPI)
        self.assertEqual([(o["method"], o["path"]) for o in ops if not o["templated"]],
                         [("post", "/v1/x402/token-autopsy/reports.create"), ("post", "/v1/x402/web-data/web.search")])
        self.assertEqual([o["path"] for o in ops if o["templated"]], ["/v1/x402/{serviceId}/{operationId}"])

    def test_an_empty_openapi_stops(self):
        with self.assertRaises(xp.si.Stop):
            xp.paid_operations({"openapi": "3.1.0", "paths": {}})

    def test_six_variants_per_operation(self):
        got = xp.variants("/v1/x402/web-data/web.search")
        self.assertEqual(got, ["/v1/x402/web-data/web.search", "/v1/x402/web-data%2Fweb.search", "/v1/x402/web-data%2fweb.search",
                               "/v1/x402/web-data%5Cweb.search", "/v1/x402/web-data%5cweb.search", "/v1/x402/web-data%252Fweb.search"])


class Probe(unittest.TestCase):
    def run_on(self, send):
        ops = [o for o in xp.paid_operations(OPENAPI) if not o["templated"]]
        return xp.probe(ops, "https://api.example.test", send)

    def test_the_3850_shape_is_caught(self):
        report = self.run_on(vulnerable)
        self.assertTrue(report["bypass"], report)
        self.assertTrue(all(b["status"] // 100 == 2 for b in report["bypass"]))
        self.assertIn("%5C", " ".join(b["path"] for b in report["bypass"]))

    def test_the_fix_and_hive_today_pass(self):
        for send in (fixed, hive_today):
            with self.subTest(send=send.__name__):
                report = self.run_on(send)
                self.assertEqual(report["bypass"], [], report)
                self.assertEqual(report["requests"], 12)

    def test_an_unreachable_variant_is_not_read_never_a_pass(self):
        report = self.run_on(lambda m, u: None)
        self.assertEqual((report["bypass"], len(report["notRead"])), ([], 12))

    def test_the_daily_cap_and_new_routes_first(self):
        ops = [{"method": "post", "path": f"/v1/x402/s/op{i}", "templated": False} for i in range(10)]
        seen = {"post /v1/x402/s/op0", "post /v1/x402/s/op1"}
        picked = xp.pick(ops, seen, cap_requests=40, day=0)
        self.assertEqual(len(picked), 6, "6 operations x 6 requests stays under a 40-request host cap")
        self.assertTrue(all(f"post {o['path']}" not in seen for o in picked), "routes not probed before go first")
        self.assertEqual(len(xp.pick(ops, {f"post {o['path']}" for o in ops}, cap_requests=40, day=3)), 1, "with none new, one a day keeps it live")


class Cli(unittest.TestCase):
    def test_a_bypass_exits_2_and_state_keeps_what_was_probed(self):
        import io, contextlib
        with tempfile.TemporaryDirectory() as tmp:
            state = pathlib.Path(tmp) / "state.json"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = xp.run(OPENAPI, "https://api.example.test", vulnerable, state_path=str(state))
            self.assertEqual(code, 2, out.getvalue())
            self.assertIn("BYPASS", out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(xp.run(OPENAPI, "https://api.example.test", hive_today, state_path=str(state)), 0)
            self.assertEqual(sorted(json.loads(state.read_text())["probed"]), ["post /v1/x402/token-autopsy/reports.create", "post /v1/x402/web-data/web.search"])


if __name__ == "__main__":
    unittest.main()
