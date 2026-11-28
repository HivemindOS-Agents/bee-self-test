"""The one chain config and GitChecker's Base-only blockers (24 Nov 2026 dev update, section 32.1, row 13): guards 53
to 56 and 78, each on the fixtures the spec names. No network: every chain and HTTP answer is canned.

  python3 -m unittest discover -s tests -p 'test_chains.py'"""
import contextlib, copy, io, json, pathlib, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import chains  # noqa: E402
import chain_literals  # noqa: E402
import claim_watch as cw  # noqa: E402
import lift_run as lr  # noqa: E402
import source_match as sm  # noqa: E402

FIX = ROOT / "fixtures" / "chain-config"
load = lambda name: json.loads((FIX / name).read_text())
BASE, HOOD = chains.CHAINS[chains.BASE], chains.CHAINS[chains.ROBINHOOD]


class HostWords(unittest.TestCase):
    def test_the_chain_words_ids_and_explorers_are_the_hosts(self):
        host = load("host-words.json")
        for want in host["chains"]:
            got = chains.get(want["slug"])
            self.assertIsNotNone(got, want["slug"])
            for key in ("chainId", "caip2", "explorer"):
                if key in want:
                    self.assertEqual(got[key], want[key], f"{want['slug']} {key}")
            self.assertEqual(int(got["hex"], 16), got["chainId"])
            self.assertEqual(got["caip2"], f"eip155:{got['chainId']}")
        hood = host["x402"]["robinhood"]
        self.assertEqual(HOOD["x402"]["v1"], hood["v1"])
        self.assertEqual(HOOD["x402"]["assets"], {hood["asset"]: hood["token"]})

    def test_base_is_the_only_enabled_chain_and_testnets_never_reach_a_mainnet_path(self):
        self.assertEqual([c["slug"] for c in chains.CHAINS.values() if c["enabled"]], [chains.BASE])
        self.assertEqual(chains.launchpad_slugs(), [chains.BASE, chains.ROBINHOOD])
        self.assertTrue(all(not c["testnet"] for c in chains.mainnets()))
        self.assertNotIn("USDC", HOOD["x402"]["assets"], "there is no USDC entry on Robinhood Chain")
        self.assertEqual(chains.HIVE_PAYMENTS, chains.BASE)


class Guard53NoBareLiteral(unittest.TestCase):
    def test_the_lines_the_guard_names_fail_and_their_fixes_pass(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = chain_literals.self_test()
        self.assertEqual(code, 0, out.getvalue())

    def test_todays_source_match_line_is_caught_with_what_it_holds(self):
        found = chain_literals.literals_in((ROOT / "fixtures/chain-literals/bad-source_match-7bc74dc.txt").read_text())
        self.assertIn(str(BASE["chainId"]), [what for _, what in found])
        self.assertIn(BASE["rpcIndependent"].split("//", 1)[1], [what for _, what in found])

    def test_an_eip155_string_and_a_hex_id_are_caught(self):
        for text in (f'net = "{HOOD["caip2"]}"', f'if cid == "{HOOD["hex"].upper().replace("0X", "0x")}":'):
            self.assertTrue(chain_literals.literals_in(text), text)

    def test_the_repository_has_none_outside_the_config(self):
        files, problems = chain_literals.lint(str(ROOT))
        self.assertGreater(files, 10)
        self.assertEqual(problems, [])


class Guard54SourceMatchReadsEveryChain(unittest.TestCase):
    def test_a_4663_coin_is_read_on_its_chain_and_an_unknown_chain_is_unable(self):
        reads = []
        rows = sm.coin_rows(load("market-coins.json")["coins"], lambda token, chain: reads.append((token, chain["slug"])) or {"family": "source", "chain": chain["chainId"], "address": token, "outcome": "MATCH"})
        self.assertEqual(reads, [("0x1111111111111111111111111111111111111111", chains.BASE), ("0x2222222222222222222222222222222222222222", chains.ROBINHOOD)])
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["coin HOODONE"]["chain"], HOOD["chainId"])
        for name in ("coin ELSEWHERE", "coin NOCHAIN"):
            self.assertEqual(by_name[name]["outcome"], "UNABLE", name)
            self.assertIn("not in the chain config", by_name[name]["detail"])
        self.assertNotIn("coin NOTATOKEN", by_name, "a row that is not a token is not a coin")

    def test_a_read_uses_that_chains_sourcify_path_and_rpc(self):
        asked = []

        def fetch(url, body=None):
            asked.append(url)
            return {"result": "0x60"} if body else {"match": "exact_match", "runtimeBytecode": {"recompiledBytecode": "0x60"}}
        row = sm.read("0x" + "ab" * 20, HOOD, fetch)
        self.assertEqual(asked, [chains.SOURCIFY_CONTRACT.format(chain=HOOD["chainId"], address="0x" + "ab" * 20), HOOD["rpcIndependent"]])
        self.assertEqual((row["chain"], row["outcome"]), (HOOD["chainId"], "MATCH"))

    def test_base_reads_as_it_did(self):
        asked = []
        sm.read("0x" + "ab" * 20, BASE, lambda url, body=None: asked.append(url) or {})
        self.assertEqual(asked[0], chains.SOURCIFY_CONTRACT.format(chain=BASE["chainId"], address="0x" + "ab" * 20))

    def test_named_is_built_per_chain_and_reports_its_empty_entries(self):
        named = sm.named_targets()
        self.assertEqual([what for chain, what, _ in named if chain["slug"] == chains.BASE], [what for what, _ in BASE["named"]])
        empty = sm.empty_rows()
        self.assertTrue(empty)
        self.assertTrue(all(r["outcome"] == "EMPTY" and r["chain"] == HOOD["chainId"] for r in empty), empty)

    def test_the_pinned_fixtures_still_pass(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sm.self_test(), 0)


class Guard55ClaimWatchErc8004(unittest.TestCase):
    regs = load("registrations.json")

    def test_a_base_registration_is_found_as_before(self):
        self.assertEqual(cw.registrations_reading(self.regs["base"]), {"outcome": "REGISTERED_SINCE", "agentId": 4211})

    def test_a_4663_agent_with_an_unfilled_registry_is_not_checkable_never_unregistered(self):
        got = cw.registrations_reading(self.regs["robinhood"])
        self.assertEqual(got["outcome"], cw.NOT_CHECKABLE)
        self.assertIn("Robinhood Chain", got["why"])
        self.assertNotEqual(got["outcome"], "NOT_REGISTERED")

    def test_an_unknown_chain_and_a_testnet_are_not_checkable(self):
        for name in ("unknownChain", "testnet"):
            self.assertEqual(cw.registrations_reading(self.regs[name])["outcome"], cw.NOT_CHECKABLE, name)

    def test_no_registration_and_another_contract_are_not_registered(self):
        for name in ("none", "otherContractOnBase"):
            self.assertEqual(cw.registrations_reading(self.regs[name])["outcome"], "NOT_REGISTERED", name)

    def test_the_match_is_not_base_only_once_a_registry_is_filled(self):
        table = copy.deepcopy(chains.CHAINS)
        table[chains.ROBINHOOD]["erc8004"] = BASE["erc8004"]
        got = cw.registrations_reading(self.regs["robinhood"], table)
        self.assertEqual(got, {"outcome": "REGISTERED_SINCE", "agentId": 17, "agentRegistry": self.regs["robinhood"][0]["agentRegistry"]})
        # A Base registration beside it is still the one a Base row is read on.
        self.assertEqual(cw.registrations_reading(self.regs["both"])["agentId"], 4211)

    def test_a_registration_is_read_on_its_own_chains_registry_and_rpc(self):
        sent = []

        class Answer:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"result": "0x" + "00" * 32}).encode()

        real = cw.urllib.request.urlopen
        cw.urllib.request.urlopen = lambda req, timeout=None: sent.append((req.full_url, json.loads(req.data)["params"][0]["to"])) or Answer(req)
        try:
            table = copy.deepcopy(chains.CHAINS)
            cw.rpc_call("0x6352211e", table[chains.BASE])
        finally:
            cw.urllib.request.urlopen = real
        self.assertEqual(sent, [(BASE["rpc"], BASE["erc8004"])])

    def test_a_sample_on_a_chain_with_no_registry_is_not_checkable(self):
        self.assertEqual(cw.sample_chain("erc8004:base:2026-11-22")["slug"], chains.BASE)
        verdict = cw.replay_outward({"family": "record", "target": "sample", "seed": "erc8004:robinhood:2026-11-28", "sampled": 3, "maxId": 9, "outcome": "RESOLVES", "count": 1}, [])
        self.assertEqual(verdict[1], "UNABLE")
        self.assertIn("not checkable", verdict[2])

    def test_the_claim_watch_self_test_still_passes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cw.self_test(), 0)


class Guard56LiftRunChain(unittest.TestCase):
    def rpc(self, hex_id):
        def call(url, method, params, timeout=20):
            if method not in lr.RPC_METHODS:
                raise ValueError(method)
            if method == "eth_chainId":
                return hex_id
            return None
        return call

    def main(self, argv, hex_id):
        real = lr.rpc_call
        lr.rpc_call = self.rpc(hex_id)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = lr.main(argv)
        finally:
            lr.rpc_call = real
        return code, out.getvalue()

    def test_a_base_tx_sent_to_the_robinhood_rpc_is_refused(self):
        code, out = self.main(["--verify-tasks", str(ROOT / "lift/tx-explain/tasks.json"), "--rpc", HOOD["rpc"]], HOOD["hex"])
        self.assertEqual(code, 2)
        self.assertIn("refused", out)

    def test_a_robinhood_request_on_a_base_task_set_is_refused(self):
        code, out = self.main(["--verify-tasks", str(ROOT / "lift/tx-explain/tasks.json"), "--chain", chains.ROBINHOOD], HOOD["hex"])
        self.assertEqual(code, 2)
        self.assertIn("task set", out)

    def test_the_rpc_and_the_requested_chain_must_agree(self):
        self.assertIsNone(lr.chain_problem(lambda m, p: BASE["hex"], chains.BASE))
        self.assertIn("answered", lr.chain_problem(lambda m, p: HOOD["hex"], chains.BASE))
        self.assertIn("did not answer", lr.chain_problem(lambda m, p: (_ for _ in ()).throw(OSError("down")), chains.ROBINHOOD))

    def test_the_default_is_base_on_bases_own_rpc(self):
        a = lr.parser().parse_args(["--verify-tasks", "x"])
        self.assertEqual((a.chain, lr.rpc_for(a)), (chains.BASE, BASE["rpc"]))
        a = lr.parser().parse_args(["--verify-tasks", "x", "--chain", chains.ROBINHOOD])
        self.assertEqual(lr.rpc_for(a), HOOD["rpc"])

    def test_a_matching_chain_goes_on_to_the_reads(self):
        code, out = self.main(["--verify-tasks", str(ROOT / "lift/tx-explain/tasks.json")], BASE["hex"])
        self.assertNotIn("refused", out)
        self.assertIn('"verified"', out)

    def test_the_method_allow_list_is_kept(self):
        with self.assertRaises(ValueError):
            lr.rpc_call(BASE["rpc"], "eth_sendRawTransaction", ["0x"])


class Guard78LabX402Reader(unittest.TestCase):
    fx = load("x402-priors-usdg.json")

    def listing(self, name):
        return [cw.accept(a) for a in self.fx[name]["accepts"]]

    def test_a_usdg_listing_on_4663_is_read_in_v2_and_v1(self):
        v2, v1 = self.listing("v2"), self.listing("v1")
        self.assertEqual(v1[0]["network"], HOOD["caip2"], "v1's robinhood is its CAIP-2 id")
        self.assertEqual(cw.lab_listing("priors", v2, 402, v2)["outcome"], "MATCH")
        self.assertEqual(cw.lab_listing("priors", v1, 402, v2)["outcome"], "MATCH")
        self.assertEqual(cw.lab_listing("priors", v2, 402, [dict(v2[0], amount="1")])["outcome"], "PRICE_DIFF")

    def test_usdc_on_4663_and_an_unknown_network_are_not_checkable_never_skipped(self):
        for name in ("usdcLookalike", "unknownNetwork"):
            row = cw.lab_listing("x", self.listing(name), 402, self.listing(name))
            self.assertEqual(row["outcome"], cw.NOT_CHECKABLE, name)
            self.assertEqual(row["target"], "x")
            self.assertTrue(row["why"])

    def test_hives_own_base_usdc_listing_is_unchanged(self):
        hive = self.listing("hiveBaseUsdc")
        self.assertEqual(hive[0]["asset"], chains.x402_asset(chains.HIVE_PAYMENTS, chains.HIVE_PAYMENT_ASSET))
        self.assertEqual(cw.lab_listing("hive", hive, 402, hive), cw.check_listing("hive", hive, 402, hive))


if __name__ == "__main__":
    unittest.main()
