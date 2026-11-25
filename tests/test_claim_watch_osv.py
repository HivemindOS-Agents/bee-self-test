"""Row 101, guard 262 (25 Nov 2026 dev update): OSV `MAL-` records are the authority in claim_watch's advisory family.
A package with a live OSV MAL record is ADVISORY_HIT whether or not npm still serves it and whether or not a GHSA exists
yet, and the daily re-check of locked and installed packages reads MAL records whose `modified` time is new even when
their `published` time is old. The network is mocked: OSV, GitHub and npm answer from the fixtures, and no package is
downloaded.

  python3 -m unittest discover -s tests -p 'test_claim_watch_osv.py'

fixtures/claim-watch/osv/ holds the two OSV records as api.osv.dev/v1/vulns served them on 26 Nov 2026 (advisory
records only): MAL-2026-13209 (@guangnao/claude-cli, published 2026-08-05, modified 2026-11-24 when GHSA-vfqh-3659-q56x
was added) and MAL-2026-20505 (@apexfdn/copilot-mcp). "As on 5 Aug" below is MAL-2026-13209 with no alias and its
modified time equal to its published time: what OSV said for the 111 days before GitHub's advisory."""
import importlib.util
import io
import json
import pathlib
import sys
import unittest
import urllib.error
import urllib.parse
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "claim-watch" / "osv"
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("claim_watch", ROOT / "scripts" / "claim_watch.py")
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

GUANGNAO = json.loads((FIX / "MAL-2026-13209.json").read_text())
APEX = json.loads((FIX / "MAL-2026-20505.json").read_text())
AS_ON_5_AUG = dict(GUANGNAO, aliases=[], modified=GUANGNAO["published"])
SKILL_URL = "https://raw.githubusercontent.com/someone/skills/0123456789abcdef0123456789abcdef01234567/x/SKILL.md"


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Net:
    """A fake urlopen. osv: {package name: [records]} or an exception to raise for OSV; ghsa: {name: [advisories]} or
    an exception; skill: the text a pinned skill URL serves. Every call is kept in .calls."""

    def __init__(self, osv=None, ghsa=None, skill=""):
        self.osv, self.ghsa, self.skill, self.calls = osv if osv is not None else {}, ghsa if ghsa is not None else {}, skill, []

    def __call__(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else request
        body = json.loads(request.data) if getattr(request, "data", None) else None
        self.calls.append((url, body))
        if url.startswith("https://api.osv.dev/"):
            if isinstance(self.osv, Exception):
                raise self.osv
            name = (body or {}).get("package", {}).get("name")
            version = (body or {}).get("version")
            vulns = [v for v in self.osv.get(name, []) if not version or any(version in a.get("versions", [version]) for a in v.get("affected", [{}]))]
            return Answer(json.dumps({"vulns": vulns} if vulns else {}).encode())
        if url.startswith("https://api.github.com/advisories"):
            if isinstance(self.ghsa, Exception):
                raise self.ghsa
            name = next((p.split("=", 1)[1] for p in url.split("?", 1)[1].split("&") if p.startswith("affects=")), "")
            name = urllib.parse.unquote(name)
            return Answer(json.dumps(self.ghsa.get(name, [])).encode())
        if url.startswith("https://registry.npmjs.org/"):
            return Answer(json.dumps({"name": url.rsplit("/", 1)[1], "dist-tags": {"latest": "1.0.13"}}).encode())
        if url == SKILL_URL:
            return Answer(self.skill.encode())
        raise urllib.error.URLError(f"no fake answer for {url}")



def with_net(net):
    return mock.patch.object(cw.urllib.request, "urlopen", net)


def replay_advisory(net, then="NO_HIT", refs=1):
    rows = [{"family": "skill", "target": "someone/x@1", "url": SKILL_URL, "outcome": "PIN_OK", "sha256": "0" * 64},
            {"family": "advisory", "target": "someone/x@1", "outcome": then, "refs": refs}]
    with with_net(net):
        return cw.replay_outward(rows[1], rows)


class OsvIsTheAuthority(unittest.TestCase):
    def test_guangnao_as_on_5_aug_is_a_hit_from_osv_alone(self):
        net = Net(osv={"@guangnao/claude-cli": [AS_ON_5_AUG]}, ghsa={})
        with with_net(net):
            found = cw.advisories_of({"ecosystem": "npm", "name": "@guangnao/claude-cli"})
        self.assertEqual(found, ["MAL-2026-13209"])
        self.assertFalse([u for u, _ in net.calls if "registry.npmjs.org" in u or u.endswith(".tgz")], "no package is fetched")

    def test_apexfdn_is_a_hit_from_osv_alone(self):
        net = Net(osv={"@apexfdn/copilot-mcp": [dict(APEX, aliases=[])]}, ghsa={})
        with with_net(net):
            self.assertEqual(cw.advisories_of({"ecosystem": "npm", "name": "@apexfdn/copilot-mcp"}), ["MAL-2026-20505"])

    def test_the_replay_says_advisory_hit_where_github_had_none(self):
        for name, record in (("@guangnao/claude-cli", AS_ON_5_AUG), ("@apexfdn/copilot-mcp", dict(APEX, aliases=[]))):
            with self.subTest(name=name):
                net = Net(osv={name: [record]}, ghsa={}, skill=f"Install it: `npx -y {name}`\n")
                target, verdict, why = replay_advisory(net)
                self.assertEqual((verdict, why), ("CHANGED", "NO_HIT then, ADVISORY_HIT now"))

    def test_the_advisory_row_names_the_osv_record(self):
        hits = [{"ecosystem": "npm", "name": "@guangnao/claude-cli", "osv": "MAL-2026-13209"}]
        row = cw.advisory_row("someone/x@1", [{"ecosystem": "npm", "name": "@guangnao/claude-cli"}], hits)
        self.assertEqual(row["outcome"], "ADVISORY_HIT")
        self.assertEqual(row["hits"], [{"package": "@guangnao/claude-cli", "ecosystem": "npm", "osv": "MAL-2026-13209"}])
        self.assertIn("malware", cw.protect("d", [row])["wouldBlock"][0]["why"])

    def test_a_ghsa_aliased_by_the_mal_record_is_one_hit(self):
        ghsa = [{"ghsa_id": "GHSA-vfqh-3659-q56x", "vulnerabilities": [{"package": {"name": "@guangnao/claude-cli"}}]}]
        net = Net(osv={"@guangnao/claude-cli": [GUANGNAO]}, ghsa={"@guangnao/claude-cli": ghsa})
        with with_net(net):
            self.assertEqual(cw.advisories_of({"ecosystem": "npm", "name": "@guangnao/claude-cli"}), ["MAL-2026-13209"])

    def test_github_alone_still_counts(self):
        ghsa = [{"ghsa_id": "GHSA-1111-2222-3333", "vulnerabilities": [{"package": {"name": "evil-pkg"}}]}]
        with with_net(Net(osv={}, ghsa={"evil-pkg": ghsa})):
            self.assertEqual(cw.advisories_of({"ecosystem": "npm", "name": "evil-pkg"}), ["GHSA-1111-2222-3333"])

    def test_osv_unreadable_is_not_read_never_no_hit(self):
        with with_net(Net(osv=urllib.error.URLError("down"), ghsa={})):
            self.assertIsNone(cw.advisories_of({"ecosystem": "npm", "name": "@guangnao/claude-cli"}))

    def test_github_unreadable_with_an_osv_hit_is_still_a_hit(self):
        with with_net(Net(osv={"@guangnao/claude-cli": [AS_ON_5_AUG]}, ghsa=urllib.error.URLError("rate limited"))):
            self.assertEqual(cw.advisories_of({"ecosystem": "npm", "name": "@guangnao/claude-cli"}), ["MAL-2026-13209"])

    def test_a_withdrawn_mal_record_and_a_plain_vulnerability_are_not_malware_hits(self):
        withdrawn = dict(AS_ON_5_AUG, withdrawn="2026-08-06T00:00:00Z")
        cve = {"id": "GHSA-aaaa-bbbb-cccc", "published": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z"}
        with with_net(Net(osv={"@guangnao/claude-cli": [withdrawn, cve]}, ghsa={})):
            self.assertEqual(cw.advisories_of({"ecosystem": "npm", "name": "@guangnao/claude-cli"}), [])

    def test_pip_packages_are_asked_as_pypi(self):
        net = Net(osv={}, ghsa={})
        with with_net(net):
            cw.advisories_of({"ecosystem": "pip", "name": "mem0-mcp-server"})
        self.assertIn({"package": {"name": "mem0-mcp-server", "ecosystem": "PyPI"}}, [b for u, b in net.calls if "osv.dev" in u])


class DailyRecheck(unittest.TestCase):
    """The locked and installed packages, read again every day against new and modified MAL records."""

    def test_new_by_modified_time_even_when_published_long_ago(self):
        since = "2026-11-24T00:00:00Z"
        self.assertEqual([r["id"] for r in cw.mal_new_since([GUANGNAO, AS_ON_5_AUG], since)], ["MAL-2026-13209"])
        self.assertEqual(cw.mal_new_since([AS_ON_5_AUG], since), [])
        self.assertEqual([r["id"] for r in cw.mal_new_since([APEX], since)], ["MAL-2026-20505"])

    def test_lockfile_manifest_and_mcp_config_are_read(self):
        refs = cw.lock_refs([FIX / "package-lock.json", FIX / "mcp.json", FIX / "requirements.txt"])
        got = sorted((r["ecosystem"], r["name"], r.get("version")) for r in refs)
        self.assertEqual(got, [("npm", "@apexfdn/copilot-mcp", None), ("npm", "@guangnao/claude-cli", "1.0.5"), ("npm", "left-pad", "1.3.0"),
                               ("pip", "mem0-mcp-server", None), ("pip", "requests", "2.32.3")])

    def test_recheck_reports_both_fixtures_as_hits_and_flags_the_modified_one_new(self):
        net = Net(osv={"@guangnao/claude-cli": [GUANGNAO], "@apexfdn/copilot-mcp": [APEX]}, ghsa={})
        with with_net(net):
            report, code = cw.recheck([FIX / "package-lock.json", FIX / "mcp.json"], since="2026-11-24T12:00:00Z")
        self.assertEqual(code, 1)
        hits = {(h["package"], h["osv"]): h for h in report["hits"]}
        self.assertEqual(set(hits), {("@guangnao/claude-cli", "MAL-2026-13209"), ("@apexfdn/copilot-mcp", "MAL-2026-20505")})
        self.assertTrue(hits[("@guangnao/claude-cli", "MAL-2026-13209")]["new"], "modified 24 Nov 19:30, published 5 Aug")
        self.assertEqual(report["outcome"], "ADVISORY_HIT")
        self.assertIn({"package": {"name": "@guangnao/claude-cli", "ecosystem": "npm"}, "version": "1.0.5"}, [b for u, b in net.calls if "osv.dev" in u])

    def test_recheck_clean_and_unread(self):
        with with_net(Net(osv={}, ghsa={})):
            report, code = cw.recheck([FIX / "requirements.txt"], since="2026-11-24T00:00:00Z")
        self.assertEqual((code, report["outcome"], report["packages"]), (0, "NO_HIT", 2))
        with with_net(Net(osv=urllib.error.URLError("down"), ghsa={})):
            report, code = cw.recheck([FIX / "requirements.txt"], since="2026-11-24T00:00:00Z")
        self.assertEqual((code, report["outcome"]), (2, "NOT_READ"))

    def test_recheck_github_unreadable_and_osv_clean_is_not_read(self):
        with with_net(Net(osv={}, ghsa=urllib.error.URLError("rate limited"))):
            report, code = cw.recheck([FIX / "requirements.txt"], since=None)
        self.assertEqual((code, report["outcome"]), (2, "NOT_READ"))

    def test_recheck_with_no_input_stops(self):
        with self.assertRaises(cw.si.Stop):
            cw.recheck([], since=None)


if __name__ == "__main__":
    unittest.main()
