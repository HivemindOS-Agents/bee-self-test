"""B-59 / HB-021: the Twigpine mirror's checks, on canned node answers. No network, no key of any real repository."""
import base64, copy, hashlib, json, os, shutil, stat, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import twigpine_mirror as t  # noqa: E402

FIXTURE = os.path.join(ROOT, "fixtures", "twigpine-mirror", "mirrors.json")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "twigpine-mirror.yml")


def sign(seed, message):
    """RFC 8032 signing, for canned certificates only (the script itself never signs)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = t._compress(t._mul(a, t._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % t._Q
    R = t._compress(t._mul(r, t._G))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), "little") % t._Q
    return R + int.to_bytes((r + k * a) % t._Q, 32, "little")


NODE_SEED = bytes(range(32))
NODE_DID = t.did_from_public(t.ed25519_public(NODE_SEED))
REPO_SEED = bytes(range(1, 33))
REPO_DID = t.did_from_public(t.ed25519_public(REPO_SEED))
OTHER_DID = t.did_from_public(t.ed25519_public(bytes(range(2, 34))))
SHA = "a" * 40
OLD = "b" * 40


def cert(new=SHA, pusher=REPO_DID, node_seed=NODE_SEED, at="2026-11-28T00:00:00+00:00", ref="refs/heads/main"):
    c = {"id": "c" * 64, "repo_id": "r-1", "ref_name": ref, "old_sha": OLD, "new_sha": new, "pusher_did": pusher,
         "node_did": NODE_DID, "issued_at": at, "version": 1}
    c["signature"] = base64.urlsafe_b64encode(sign(node_seed, t.cert_payload(c))).decode().rstrip("=")
    return c


def fixture(did=REPO_DID):
    return {"node": "https://node.example", "nodeDid": NODE_DID, "githubOrg": "HivemindOS-Agents", "branch": "main",
            "repos": [{"github": "hivepunk-1", "twigpine": "hivepunk-1", "seedName": "TWIGPINE_SEED_HIVEPUNK_1",
                       "did": did}]}


class Node:
    """A canned node: path -> (status, body)."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def __call__(self, url):
        self.seen.append(url)
        path = url.split("https://node.example", 1)[1]
        for key, answer in self.routes.items():
            if path == key or path.startswith(key + "?"):
                status, body = answer
                return status, json.dumps(body).encode()
        return 404, b"{}"


def node(protected=("main",), owner=REPO_DID, certs=None, repo_status=200, version="0.8.1", did=NODE_DID):
    base = f"/api/v1/repos/{REPO_DID}/hivepunk-1"
    return Node({"/": (200, {"did": did, "version": version}),
                 base: (repo_status, {"owner_did": owner}),
                 base + "/branches/protected": (200, {"protected_branches": list(protected)}),
                 base + "/certs": (200, {"certificates": certs if certs is not None else [cert()]})})


class Crypto(unittest.TestCase):
    def test_self_test(self):
        self.assertEqual(t.self_test(os.path.join(ROOT, "fixtures", "twigpine-mirror")), [])

    def test_canned_certificate_verifies_and_tampering_does_not(self):
        self.assertIsNone(t.verify_cert(cert(), NODE_DID))
        bad = dict(cert(), new_sha="0" * 40)
        self.assertIn("does not verify", t.verify_cert(bad, NODE_DID))
        self.assertIn("not the pinned", t.verify_cert(cert(), OTHER_DID))
        self.assertIn("version", t.verify_cert(dict(cert(), version=2), NODE_DID))
        self.assertIn("no signature", t.verify_cert({k: v for k, v in cert().items() if k != "signature"}, NODE_DID))

    def test_a_certificate_signed_by_another_key_claiming_the_node(self):
        self.assertIn("does not verify", t.verify_cert(cert(node_seed=REPO_SEED), NODE_DID))

    def test_pem_is_pkcs8_that_openssl_reads_as_the_same_key(self):
        if not shutil.which("openssl"):
            self.skipTest("no openssl")
        p = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=t.seed_pem(REPO_SEED).encode(),
                           capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout[-32:], t.ed25519_public(REPO_SEED))

    def test_did_key_rejects_other_methods(self):
        for bad in ("did:web:example.com", "did:key:zQ3s", "", None):
            with self.assertRaises(ValueError):
                t.public_from_did(bad)


class Fixture(unittest.TestCase):
    def test_committed_list_is_sound(self):
        fx = t.load_fixture(FIXTURE)
        self.assertEqual({r["github"] for r in fx["repos"]},
                         {"hivepunk-547", "hivepunk-632", "hivepunk-1071", "hivepunk-86", "hivepunk-667", "datacard-lint"})
        self.assertTrue(all(r.get("did") for r in fx["repos"]), "every repository has its own did:key")

    def test_committed_list_holds_no_secret(self):
        raw = open(FIXTURE).read()
        self.assertNotIn("PRIVATE KEY", raw)
        self.assertFalse([k for r in json.loads(raw)["repos"] for k in r if k not in ("github", "twigpine", "seedName", "did")])

    def test_a_shared_key_is_refused(self):
        fx = fixture()
        fx["repos"].append(dict(fx["repos"][0], github="hivepunk-2", twigpine="hivepunk-2", seedName="TWIGPINE_SEED_HIVEPUNK_2"))
        self.assertTrue(any("shared" in b for b in t.check_fixture(fx)))

    def test_a_shared_seed_name_is_refused(self):
        fx = fixture()
        fx["repos"].append(dict(fx["repos"][0], github="hivepunk-2", twigpine="hivepunk-2", did=OTHER_DID))
        self.assertTrue(any("seedName is shared" in b for b in t.check_fixture(fx)))

    def test_the_node_key_as_a_repo_key_is_refused(self):
        self.assertTrue(any("node's DID" in b for b in t.check_fixture(fixture(did=NODE_DID))))

    def test_only_main_and_https(self):
        fx = dict(fixture(), branch="dev", node="http://node.example")
        bad = t.check_fixture(fx)
        self.assertTrue(any("branch" in b for b in bad) and any("https" in b for b in bad))

    def test_empty_and_unparseable_lists_stop(self):
        d = os.path.join(ROOT, "fixtures", "twigpine-mirror")
        for text in ("", "{not json", "[]"):
            path = os.path.join(d, "_tmp_list.json")
            try:
                with open(path, "w") as f:
                    f.write(text)
                with self.assertRaises(t.Stop):
                    t.load_fixture(path)
            finally:
                os.remove(path)


class Gate(unittest.TestCase):
    def test_protected_main_passes(self):
        g = t.gate(fixture(), node())
        self.assertEqual(g["repos"][0]["state"], "protected")
        self.assertEqual(g["passes"], ["hivepunk-1"])
        self.assertTrue(g["nodeState"]["ownerPushDefaultOn"])
        self.assertEqual(g["nodeState"]["operatorOwnerPushSetting"], t.NOT_READ)

    def test_unprotected_main_does_not_pass_even_on_a_v0_8_node(self):
        g = t.gate(fixture(), node(protected=()))
        self.assertEqual(g["repos"][0]["state"], "unprotected")
        self.assertEqual(g["passes"], [])

    def test_a_node_answering_with_another_did_passes_nothing(self):
        g = t.gate(fixture(), node(did=OTHER_DID))
        self.assertFalse(g["nodeState"]["didMatchesPin"])
        self.assertEqual(g["passes"], [])

    def test_old_node_version_is_said(self):
        self.assertFalse(t.gate(fixture(), node(version="0.7.1"))["nodeState"]["ownerPushDefaultOn"])

    def test_missing_wrong_owner_and_unreadable(self):
        self.assertEqual(t.gate(fixture(), node(repo_status=404))["repos"][0]["state"], "not-bootstrapped")
        self.assertEqual(t.gate(fixture(), node(owner=OTHER_DID))["repos"][0]["state"], "wrong-owner")
        self.assertEqual(t.gate(fixture(), node(repo_status=403))["repos"][0]["state"], t.NOT_READ)
        self.assertEqual(t.gate(fixture(did=None), node())["repos"][0]["state"], "no-key")


class Check(unittest.TestCase):
    def run_check(self, n, sha=SHA):
        return t.check(fixture(), n, ls_remote=lambda r: sha)

    def test_in_sync(self):
        rep = self.run_check(node())
        self.assertEqual(rep["repos"][0]["state"], "in-sync")
        self.assertEqual(t.check_exit(rep, expect_live=True), t.EXIT_OK)

    def test_behind_fails_only_when_live_is_expected(self):
        rep = self.run_check(node(certs=[cert(new=OLD)]))
        self.assertEqual(rep["repos"][0]["state"], "behind")
        self.assertEqual(t.check_exit(rep, expect_live=False), t.EXIT_OK)
        self.assertEqual(t.check_exit(rep, expect_live=True), t.EXIT_FAIL)

    def test_latest_certificate_is_the_one_read(self):
        older, newer = cert(new=OLD, at="2026-11-27T00:00:00+00:00"), cert(at="2026-11-28T00:00:00+00:00")
        self.assertEqual(self.run_check(node(certs=[newer, older]))["repos"][0]["state"], "in-sync")
        self.assertEqual(self.run_check(node(certs=[older, newer]))["repos"][0]["state"], "in-sync")

    def test_other_branches_are_not_main(self):
        rep = self.run_check(node(certs=[cert(ref="refs/heads/dev")]))
        self.assertEqual(rep["repos"][0]["state"], "no-certificate")

    def test_a_push_by_another_did_fails(self):
        rep = self.run_check(node(certs=[cert(pusher=OTHER_DID)]))
        self.assertEqual(rep["repos"][0]["state"], "foreign-pusher")
        self.assertEqual(t.check_exit(rep, expect_live=False), t.EXIT_FAIL)

    def test_a_forged_certificate_fails(self):
        forged = dict(cert(), new_sha=SHA.replace("a", "c"))
        rep = self.run_check(node(certs=[forged]), sha=forged["new_sha"])
        self.assertEqual(rep["repos"][0]["state"], "bad-certificate")
        self.assertEqual(t.check_exit(rep, expect_live=False), t.EXIT_FAIL)

    def test_unread_github_is_not_a_pass(self):
        rep = self.run_check(node(), sha=None)
        self.assertEqual(rep["repos"][0]["state"], t.NOT_READ)
        self.assertEqual(t.check_exit(rep, expect_live=False), t.EXIT_STOP)

    def test_not_bootstrapped_is_fine_while_inert_and_fails_when_live(self):
        rep = self.run_check(node(repo_status=404))
        self.assertEqual(t.check_exit(rep, expect_live=False), t.EXIT_OK)
        self.assertEqual(t.check_exit(rep, expect_live=True), t.EXIT_FAIL)


class PushRefusals(unittest.TestCase):
    def setUp(self):
        self.saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)

    def test_inert_without_the_switch(self):
        os.environ.pop(t.SWITCH, None)
        with self.assertRaisesRegex(t.Stop, "inert"):
            t.push(fixture(), "hivepunk-1", node())

    def test_refused_when_main_is_unprotected(self):
        os.environ[t.SWITCH] = "on"
        with self.assertRaisesRegex(t.Stop, "unprotected"):
            t.push(fixture(), "hivepunk-1", node(protected=()))

    def test_refused_when_the_node_is_not_the_pinned_one(self):
        os.environ[t.SWITCH] = "on"
        with self.assertRaisesRegex(t.Stop, "pinned DID"):
            t.push(fixture(), "hivepunk-1", node(did=OTHER_DID))

    def test_a_seed_for_another_repository_is_refused(self):
        os.environ[t.SWITCH] = "on"
        os.environ["TWIGPINE_SEED_HIVEPUNK_1"] = base64.urlsafe_b64encode(bytes(range(2, 34))).decode()
        with self.assertRaisesRegex(t.Stop, "not the key of"):
            t.push(fixture(), "hivepunk-1", node())

    def test_unset_and_unparseable_seeds_stop(self):
        r = fixture()["repos"][0]
        for value in ("", "  ", "!!!", base64.urlsafe_b64encode(b"short").decode()):
            os.environ["TWIGPINE_SEED_HIVEPUNK_1"] = value
            with self.assertRaises(t.Stop):
                t.load_seed(r)

    def test_the_right_seed_loads(self):
        os.environ["TWIGPINE_SEED_HIVEPUNK_1"] = base64.urlsafe_b64encode(REPO_SEED).decode().rstrip("=")
        self.assertEqual(t.load_seed(fixture()["repos"][0]), REPO_SEED)

    def test_children_never_get_a_seed_or_an_old_key_path(self):
        os.environ.update({"TWIGPINE_SEED_X": "s", "GITLAWB_KEY": "/k", "TWIGPINE_KEY": "/k", "KEEP": "1"})
        env = t.child_env()
        self.assertFalse([k for k in env if k.startswith(("TWIGPINE_SEED_", "GITLAWB_")) or k == "TWIGPINE_KEY"])
        self.assertEqual(env["KEEP"], "1")

    def test_bootstrap_is_a_dry_run_without_yes_and_the_switch(self):
        os.environ.pop(t.SWITCH, None)
        out = t.bootstrap(fixture(), "hivepunk-1", yes=True)
        self.assertFalse(out["ran"])
        self.assertTrue(any("protect set main" in step for step in out["plan"]))


class Identity(unittest.TestCase):
    def test_pem_is_0600_in_a_0700_folder_and_gone_after(self):
        with t.Identity(REPO_SEED) as ident:
            self.assertEqual(stat.S_IMODE(os.stat(ident.pem).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(ident.dir).st_mode), 0o700)
            path, folder = ident.pem, ident.dir
        self.assertFalse(os.path.exists(path) or os.path.exists(folder))


class Receipt(unittest.TestCase):
    def test_receipt_links_the_sha_to_the_certificate(self):
        rec = t.receipt(fixture(), fixture()["repos"][0], SHA, cert(), "https://github.com/x/actions/runs/1")
        self.assertTrue(rec["verified"])
        self.assertEqual(rec["schema"], t.RECEIPT_SCHEMA)
        self.assertEqual(rec["github"]["sha"], rec["twigpine"]["newSha"])
        self.assertTrue(rec["twigpine"]["certUrl"].endswith("/certs/" + "c" * 64))
        self.assertIn("/repos/" + REPO_DID[len("did:key:"):] + "/hivepunk-1", rec["twigpine"]["explorerUrl"])

    def test_receipt_for_another_sha_is_not_verified(self):
        self.assertFalse(t.receipt(fixture(), fixture()["repos"][0], OLD, cert(), None)["verified"])


class Workflow(unittest.TestCase):
    def test_each_leg_gets_only_its_own_secret_and_the_mirror_is_switched(self):
        text = open(WORKFLOW).read()
        self.assertIn("secrets[matrix.seedName]", text)
        self.assertNotIn("toJSON(secrets)", text)
        self.assertIn("vars.TWIGPINE_MIRROR == 'on'", text)
        self.assertIn("environment: twigpine-mirror", text)
        self.assertNotIn("--force", text)


if __name__ == "__main__":
    unittest.main()
