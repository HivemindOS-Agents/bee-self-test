"""Canned-answer tests of scripts/lift_run.py (HB-036 Phase 0): the task set's shape, hashes and review rule, the
deterministic checks, both arms on the same model, tools, attempts and budget, stubbed notifications, the budget flags,
and the rule that a partial, incomplete, unreviewed or stale run is never shown as lift. No network and no model.

  python3 -m unittest discover -s tests -p 'test_lift_run.py'"""
import copy, json, pathlib, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import lift_run as lr  # noqa: E402

TASKS = lr.load_json(ROOT / "lift/tx-explain/tasks.json")
CHAIN = lr.load_json(ROOT / "fixtures/lift/tx-explain-chain.json")["chain"]
SKILL = "---\nname: tx-explain\n---\nA stand-in skill text for the tests.\n"
SKILL_SHA = lr.sha256_bytes(SKILL.encode())


def taskset(reviewed=True, skill_sha=SKILL_SHA):
    """The real task set, pinned to the stand-in skill, reviewed by a different owner unless told otherwise."""
    ts = copy.deepcopy(TASKS)
    ts["skillSha256"] = skill_sha
    if reviewed:
        ts["reviewedBy"] = {"agent": "632", "owner": "0x00000000000000000000000000000000000000aa"}
        ts["reviewedAt"] = "2026-11-18T00:00:00Z"
    ts["tasksetSha256"] = lr.taskset_sha256(ts)
    return ts


def fake_rpc(method, params):
    if method not in lr.RPC_METHODS:
        raise ValueError("method not allowed")
    entry = CHAIN.get(params[0]) if params else None
    if method == "eth_getTransactionByHash":
        return entry and entry["tx"]
    if method == "eth_getTransactionReceipt":
        return entry and entry["receipt"]
    return None


def reference(tx_hash):
    entry = CHAIN[tx_hash]
    return lr.reference_answer(entry["tx"], entry["receipt"])


def completion(content=None, tool_calls=None, finish="stop", usage=(1000, 200)):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
        finish = "tool_calls"
    return {"choices": [{"finish_reason": finish, "message": message}], "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}}


def tool_call(name, args, cid="c1"):
    return [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]


class CannedModel:
    """A model that reads the tx with the tool, notifies once, then answers: right with the skill in its prompt, and
    for the without arm right only on the tasks named in `right_without`."""

    def __init__(self, right_without=(), cut_off=(), refuse_after=None):
        self.right_without, self.cut_off, self.refuse_after = set(right_without), set(cut_off), refuse_after
        self.bodies = []

    def __call__(self, body):
        self.bodies.append(body)
        if self.refuse_after is not None and len(self.bodies) > self.refuse_after:
            raise RuntimeError("upstream 503")
        messages = body["messages"]
        with_skill = any(m["role"] == "system" and m["content"].startswith("Skill ") for m in messages)
        tx_hash = messages[-1]["content"].split()[-1].rstrip(".") if messages[-1]["role"] == "user" else next(m for m in messages if m["role"] == "user")["content"].split()[-1].rstrip(".")
        tools_done = sum(1 for m in messages if m["role"] == "tool")
        if tools_done == 0:
            return completion(tool_calls=tool_call("base_rpc", {"method": "eth_getTransactionReceipt", "params": [tx_hash]}))
        if tools_done == 1:
            return completion(tool_calls=tool_call("notify", {"text": "Tx Explain"}, "c2"))
        task_id = next(t["id"] for t in TASKS["tasks"] if t["txHash"] == tx_hash)
        if task_id in self.cut_off:
            return completion(content='{"status": "succ', finish="length")
        answer = reference(tx_hash)
        if not with_skill and task_id not in self.right_without:
            answer = {**answer, "movements": [], "unlimitedApproval": None, "status": "success"}
        return completion(content="```json\n" + json.dumps(answer) + "\n```")


CFG = {"model": "test/model-1", "attempts": 1, "max_turns": 6, "max_tokens": 1500}


class TaskSet(unittest.TestCase):
    def test_the_real_task_set_is_sound_pins_the_live_skill_and_awaits_review(self):
        self.assertEqual(lr.taskset_problems(TASKS), [])
        self.assertEqual(len(TASKS["tasks"]), 5)
        self.assertEqual(TASKS["skillSha256"], "eafd1ae43bdf5fcacc8c5c02bcb6f7848eb533c34bfeb3e7f2b06dbf9bf4df94")
        self.assertEqual(TASKS["tasksetSha256"], lr.taskset_sha256(TASKS))
        self.assertIsNone(TASKS["reviewedBy"])
        self.assertEqual(lr.review_problem(TASKS), "not reviewed yet")

    def test_every_check_holds_on_the_chains_own_answer(self):
        self.assertEqual(lr.verify_tasks(TASKS, fake_rpc), [])

    def test_a_wrong_expectation_is_caught_by_verification(self):
        ts = copy.deepcopy(TASKS)
        ts["tasks"][0]["checks"][6]["movement"]["amountRaw"] = "1"
        problems = lr.verify_tasks(ts, fake_rpc)
        self.assertEqual(len(problems), 1)
        self.assertIn("usdc-transfer", problems[0])

    def test_a_changed_task_set_or_skill_is_refused(self):
        ts = copy.deepcopy(TASKS)
        ts["tasks"][1]["checks"].pop()
        self.assertIn("tasksetSha256 does not match the task set", lr.taskset_problems(ts))
        self.assertIn("the skill file is not the one the task set pins (stale)", lr.taskset_problems(TASKS, "another skill"))

    def test_the_reviewer_must_have_another_owner_than_writer_and_publisher(self):
        ts = taskset()
        self.assertIsNone(lr.review_problem(ts))
        same_writer = {**ts, "reviewedBy": {"agent": "547", "owner": ts["writtenBy"]["owner"].upper()}}
        self.assertEqual(lr.review_problem(same_writer), "the reviewer has the same owner as the task set's writer")
        same_publisher = {**ts, "reviewedBy": {"agent": "547", "owner": "aeonfun"}}
        self.assertEqual(lr.review_problem(same_publisher), "the reviewer has the same owner as the skill's publisher")


class Checks(unittest.TestCase):
    def test_an_answer_is_its_last_json_object_fenced_or_bare(self):
        self.assertEqual(lr.answer_from_text('Done.\n```json\n{"status": "success"}\n```'), {"status": "success"})
        self.assertEqual(lr.answer_from_text('{"status": "reverted"}'), {"status": "reverted"})
        self.assertEqual(lr.answer_from_text('Here it is: {"status": "success", "movements": []}'), {"status": "success", "movements": []})
        self.assertIsNone(lr.answer_from_text("no json here"))

    def test_checks_are_exact_on_addresses_amounts_and_null(self):
        ref = reference(TASKS["tasks"][0]["txHash"])
        upper = {**ref, "from": ref["from"].upper().replace("0X", "0x")}
        for check in TASKS["tasks"][0]["checks"]:
            self.assertTrue(lr.check_holds(upper, check), check)
        wrong_amount = {**ref, "movements": [{**ref["movements"][0], "amountRaw": "36.93"}]}
        self.assertFalse(lr.check_holds(wrong_amount, TASKS["tasks"][0]["checks"][6]), "a decimal amount is not the raw integer")
        self.assertFalse(lr.check_holds({}, {"field": "unlimitedApproval.spender", "equalsAddress": "0x" + "1" * 40}))

    def test_the_rpc_tool_is_read_only(self):
        with self.assertRaises(ValueError):
            lr.rpc_call("https://mainnet.base.org", "eth_sendRawTransaction", ["0x"])


class Runs(unittest.TestCase):
    def budget(self, max_cost=1.0, judge=0):
        return lr.Budget(max_cost, {"test/model-1": {"inputUsdPerMTok": 0.5, "outputUsdPerMTok": 2.0}}, "test/model-1", judge)

    def test_a_complete_run_counts_lift_with_the_same_model_tools_and_limits_in_both_arms(self):
        model = CannedModel(right_without={"native-transfer", "reverted-call"})
        lift, results, budget = lr.run(taskset(), SKILL, CFG, model, fake_rpc, self.budget(), now=0, report="https://example.test/run/1")
        self.assertEqual(lift["state"], "complete")
        self.assertEqual(lift["with"], {"passed": 5, "failed": 0, "incomplete": 0, "of": 5})
        self.assertEqual(lift["without"]["passed"], 2)
        self.assertEqual(lift["lift"], 3)
        self.assertEqual(lift["model"], "test/model-1")
        self.assertEqual(lift["reviewedBy"], "632")
        self.assertEqual(lift["skillSha256"], SKILL_SHA)
        self.assertEqual(lift["runAt"], "1970-01-01T00:00:00Z")
        self.assertEqual(set(lift) - {"stoppedBecause"}, {"skillSha256", "tasksetSha256", "model", "with", "without", "lift", "state", "runAt", "report", "reviewedBy",
                                                          "tune", "heldOut", "gap", "previousSkillSha256", "calibration"})
        # HB-036 +: a run with no held-out file and no runtime record says so, and is no promote test.
        self.assertEqual(lift["tune"], {"with": lift["with"], "without": lift["without"]})
        self.assertEqual(lift["heldOut"], {"state": "missing"})
        self.assertIsNone(lift["gap"])
        self.assertEqual(lift["calibration"]["label"], "proxy-uncalibrated")
        # Same model, tools and output limit in every call; only the with arm carries the skill.
        self.assertEqual({b["model"] for b in model.bodies}, {"test/model-1"})
        self.assertEqual({json.dumps(b["tools"]) for b in model.bodies}, {json.dumps(lr.TOOLS)})
        self.assertEqual({b["max_tokens"] for b in model.bodies}, {1500})
        self.assertTrue(all(r["notifications"] == 1 for arms in results.values() for r in arms.values()), "notify was called and stubbed in both arms")
        self.assertGreater(budget.spent, 0)
        self.assertEqual(lr.lift_block_problems(lift, SKILL_SHA, taskset()), [])

    def test_a_cut_off_answer_is_incomplete_and_the_run_is_partial_never_lift(self):
        lift, results, _ = lr.run(taskset(), SKILL, CFG, CannedModel(cut_off={"router-swap"}), fake_rpc, self.budget(), now=0)
        self.assertEqual(results["router-swap"]["with"]["outcome"], "incomplete")
        self.assertEqual(lift["state"], "partial")
        self.assertIsNone(lift["lift"])

    def test_a_gateway_failure_is_incomplete_not_a_failed_task(self):
        lift, results, _ = lr.run(taskset(), SKILL, CFG, CannedModel(refuse_after=6), fake_rpc, self.budget(), now=0)
        self.assertEqual(results["native-transfer"]["without"]["outcome"], "incomplete")
        self.assertEqual(lift["state"], "partial")
        self.assertIsNone(lift["lift"])

    def test_a_gateway_failure_takes_the_next_attempt_and_says_its_status(self):
        class Flaky(CannedModel):
            def __init__(self):
                super().__init__(right_without={"native-transfer", "reverted-call", "usdc-transfer", "unlimited-approve", "router-swap"})
                self.failed = False
            def __call__(self, body):
                if not self.failed:
                    self.failed = True
                    self.bodies.append(body)
                    raise lr.GatewayError("502 MODEL_NO_OUTPUT")
                return super().__call__(body)
        cfg = {**CFG, "attempts": 2}
        lift, results, _ = lr.run(taskset(), SKILL, cfg, Flaky(), fake_rpc, self.budget(), now=0)
        self.assertEqual(lift["with"]["incomplete"] + lift["without"]["incomplete"], 0, "the second attempt ran")
        one = lr.run_arm(TASKS["tasks"][0], "with", SKILL, CFG, lambda body: (_ for _ in ()).throw(lr.GatewayError("502 MODEL_NO_OUTPUT")), fake_rpc, self.budget())
        self.assertEqual((one["outcome"], one["why"]), ("incomplete", "gateway: 502 MODEL_NO_OUTPUT"))

    def test_a_reasoning_effort_is_the_same_in_both_arms(self):
        model = CannedModel()
        lr.run(taskset(), SKILL, {**CFG, "reasoning_effort": "low"}, model, fake_rpc, self.budget(), now=0)
        self.assertEqual({json.dumps(b.get("reasoning")) for b in model.bodies}, {json.dumps({"effort": "low"})})

    def test_the_cost_cap_stops_the_run_and_it_is_incomplete(self):
        lift, results, budget = lr.run(taskset(), SKILL, CFG, CannedModel(), fake_rpc, self.budget(max_cost=0.01), now=0)
        self.assertEqual(lift["state"], "incomplete")
        self.assertIsNone(lift["lift"])
        self.assertIn("budget", lift["stoppedBecause"])
        self.assertLessEqual(budget.spent, 0.01)

    def test_an_unreviewed_task_set_runs_only_to_counts(self):
        lift, _, _ = lr.run(taskset(reviewed=False), SKILL, CFG, CannedModel(), fake_rpc, self.budget(), now=0)
        self.assertEqual(lift["state"], "unreviewed")
        self.assertIsNone(lift["lift"])
        self.assertIsNone(lift["reviewedBy"])

    def test_a_skill_file_that_is_not_the_pinned_one_is_stale_and_nothing_runs(self):
        model = CannedModel()
        lift, results, _ = lr.run(taskset(skill_sha="0" * 64), SKILL, CFG, model, fake_rpc, self.budget(), now=0)
        self.assertEqual(lift["state"], "stale")
        self.assertIsNone(lift["lift"])
        self.assertEqual(model.bodies, [])

    def test_judge_checks_stop_at_the_judge_call_cap(self):
        ts = taskset()
        ts["tasks"][0]["checks"].append({"judge": "The summary says who sent how much USDC to whom."})
        ts["tasksetSha256"] = lr.taskset_sha256(ts)
        calls = []
        lift, results, budget = lr.run(ts, SKILL, CFG, CannedModel(), fake_rpc, self.budget(judge=1), judge=lambda rubric, answer: calls.append(rubric) or True, now=0)
        self.assertEqual(budget.judge_calls, 1)
        self.assertEqual([r["outcome"] for r in results["usdc-transfer"].values()], ["pass", "incomplete"])
        self.assertEqual(lift["state"], "partial")


class LiftCI(unittest.TestCase):
    def lift(self, **over):
        base = {"skillSha256": SKILL_SHA, "tasksetSha256": taskset()["tasksetSha256"], "model": "m", "with": {"passed": 4, "failed": 1, "incomplete": 0, "of": 5},
                "without": {"passed": 2, "failed": 3, "incomplete": 0, "of": 5}, "lift": 2, "state": "complete", "runAt": "t", "report": "r", "reviewedBy": "632"}
        return {**base, **over}

    def test_a_changed_skill_sha_must_be_marked_stale(self):
        self.assertIn("the skill's sha256 changed and the lift is not marked stale", lr.lift_block_problems(self.lift(), "f" * 64))
        self.assertNotIn("the skill's sha256 changed and the lift is not marked stale", lr.lift_block_problems(self.lift(state="stale", lift=None), "f" * 64))

    def test_a_partial_or_incomplete_run_is_never_shown_as_lift(self):
        self.assertIn("a partial run is shown as lift", lr.lift_block_problems(self.lift(state="partial"), SKILL_SHA))
        self.assertIn("a incomplete run is shown as lift", lr.lift_block_problems(self.lift(state="incomplete"), SKILL_SHA))
        self.assertIn("a complete run has incomplete tasks in its with arm", lr.lift_block_problems(self.lift(**{"with": {"passed": 4, "failed": 0, "incomplete": 1, "of": 5}}), SKILL_SHA))

    def test_a_same_owner_reviewer_never_makes_a_complete_lift(self):
        ts = taskset()
        ts["reviewedBy"] = {"agent": "547", "owner": ts["writtenBy"]["owner"]}
        problems = lr.lift_block_problems(self.lift(), SKILL_SHA, ts)
        self.assertTrue(any("review does not count" in p for p in problems), problems)


class Flags(unittest.TestCase):
    def test_the_budget_flags_are_set_together_and_the_cost_cap_needs_prices(self):
        base = ["--taskset", "lift/tx-explain/tasks.json", "--skill-file", "x", "--model", "m", "--endpoint", "https://e", "--out", "o"]
        for argv in (base + ["--max-cost-usd", "1"], base + ["--max-judge-calls", "0"], base + ["--max-cost-usd", "1", "--max-judge-calls", "0"]):
            with self.assertRaises(SystemExit) as stopped:
                lr.main(argv)
            self.assertEqual(stopped.exception.code, 2, argv)

    def test_a_price_file_without_the_models_price_is_refused(self):
        with self.assertRaises(ValueError):
            lr.Budget(1.0, {"other/model": {"inputUsdPerMTok": 1, "outputUsdPerMTok": 1}}, "test/model-1", 0)


# ---- HB-036 +: held-out tasks and a calibrated proxy -----------------------------------------------------------------

EDIT_AT = "2026-11-01T00:00:00Z"
EDIT = lr.iso_seconds(EDIT_AT)
FIRST = 60_000_000          # the first block after the edit in the made-up chain: mined 1 second after it
A, B_, C, TOKEN, TOKEN2 = ("0x" + c * 40 for c in "abcde")
PAD = lambda address: "0x" + "0" * 24 + address[2:]


def made_tx(kind, n, i):
    """One made-up transaction of a kind, with the logs the chain reader classifies it by."""
    h = "0x" + f"{n:x}".rjust(60, "0") + f"{i:x}".rjust(4, "0")
    tx = {"hash": h, "from": A, "to": TOKEN, "value": "0x0", "input": "0x", "blockNumber": hex(n)}
    receipt = {"status": "0x1", "logs": []}
    move = lambda token, frm, to, amount: {"address": token, "topics": [lr.TRANSFER, PAD(frm), PAD(to)], "data": hex(amount)}
    if kind == "transfer":
        tx["input"] = "0xa9059cbb" + "00" * 64
        receipt["logs"] = [move(TOKEN, A, B_, 5)]
    elif kind == "native-transfer":
        tx.update(to=B_, value=hex(7))
    elif kind == "reverted":
        tx["input"] = "0x3593564c" + "00" * 32
        receipt["status"] = "0x0"
    elif kind == "approve":
        tx["input"] = "0x095ea7b3" + "00" * 64
        receipt["logs"] = [{"address": TOKEN, "topics": [lr.APPROVAL, PAD(A), PAD(C)], "data": hex(lr.MAX_UINT)}]
    elif kind == "swap":
        tx.update(to=C, input="0x3593564c" + "00" * 32)
        receipt["logs"] = [move(TOKEN, A, C, 9), move(TOKEN2, C, A, 4)]
    elif kind == "busy-swap":      # more movements than a held-out task may have
        tx.update(to=C, input="0x3593564c" + "00" * 32)
        receipt["logs"] = [move(TOKEN, A, C, k + 1) for k in range(3)] + [move(TOKEN2, C, A, k + 1) for k in range(3)]
    else:                          # "call": a contract call that moves one token
        tx.update(to=C, input="0x12345678")
        receipt["logs"] = [move(TOKEN, A, C, 1)]
    return tx, receipt


class MadeChain:
    """Blocks FIRST-2 .. , one every 2 seconds, each a list of kinds; `pick` says which transaction the block's hash selects."""

    def __init__(self, blocks):
        self.blocks, self.txs, self.calls = {}, {}, 0
        for offset, (kinds, pick) in enumerate(blocks):
            n = FIRST - 2 + offset
            made = [made_tx(kind, n, i) for i, kind in enumerate(kinds)]
            # A hash whose integer value modulo the transaction count is `pick`.
            block_hash = "0x" + f"{(n * 1000 * max(1, len(kinds))) + pick:x}".rjust(64, "0")
            self.blocks[n] = {"number": hex(n), "hash": block_hash, "timestamp": hex(EDIT - 3 + 2 * offset), "transactions": [tx for tx, _ in made]}
            for tx, receipt in made:
                self.txs[tx["hash"]] = (tx, receipt)

    def __call__(self, method, params):
        self.calls += 1
        if method == "eth_getBlockByNumber":
            n = max(self.blocks) if params[0] == "latest" else int(params[0], 16)
            block = self.blocks.get(n)
            return block and ({**block, "transactions": block["transactions"] if params[1] else [tx["hash"] for tx in block["transactions"]]})
        entry = self.txs.get(params[0])
        if method == "eth_getTransactionByHash":
            return entry and entry[0]
        if method == "eth_getTransactionReceipt":
            return entry and entry[1]
        raise ValueError("method not allowed")


# Two blocks before the edit, then: a block whose pick is a plain call (skipped), the transfer, an empty block, a native
# transfer, a busy swap (skipped: too many movements), a revert, an approve, a swap, and spare blocks.
BLOCKS = [(["transfer", "swap"], 0), (["native-transfer"], 0),
          (["transfer", "call"], 1), (["call", "transfer"], 1), ([], 0), (["native-transfer", "call"], 0), (["busy-swap"], 0), (["call", "reverted"], 1),
          (["approve"], 0), (["swap", "call", "call"], 0)] + [(["call"], 0)] * 6


def held_taskset(types=None, max_scan=None):
    ts = taskset()
    ts["heldOut"] = {"editAt": EDIT_AT, **({"types": types} if types else {}), **({"maxScan": max_scan} if max_scan else {})}
    return ts


def reviewed(held):
    held = copy.deepcopy(held)
    held["reviewedBy"] = {"agent": "632", "owner": "0x00000000000000000000000000000000000000aa"}
    held["reviewedAt"] = "2026-11-02T00:00:00Z"
    return held


class BothModel:
    """A model for tune and held-out tasks: it answers the chain's own answer, except where told to be wrong.
    `wrong` is a set of (task id, arm); the arm is read from the prompt (the skill text names it)."""

    def __init__(self, held, chain, wrong=()):
        self.ids = {t["txHash"]: t["id"] for t in TASKS["tasks"] + held["tasks"]}
        self.chain, self.wrong = chain, set(wrong)

    def __call__(self, body):
        messages = body["messages"]
        skill = next((m["content"] for m in messages if m["role"] == "system" and m["content"].startswith("Skill ")), None)
        arm = "without" if skill is None else "previous" if "OLDER" in skill else "with"
        tx_hash = next(m for m in messages if m["role"] == "user")["content"].split()[-1].rstrip(".")
        if tx_hash in CHAIN:
            answer = reference(tx_hash)
        else:
            answer = lr.reference_answer(*self.chain.txs[tx_hash])
        if (self.ids[tx_hash], arm) in self.wrong:
            answer = {**answer, "status": "reverted" if answer["status"] == "success" else "success"}
        return completion(content=json.dumps(answer))


class HeldOut(unittest.TestCase):
    def budget(self):
        return lr.Budget(5.0, {"test/model-1": {"inputUsdPerMTok": 0.5, "outputUsdPerMTok": 2.0}}, "test/model-1", 0)

    def test_the_first_block_after_the_edit_is_read_from_the_chain(self):
        chain = MadeChain(BLOCKS)
        self.assertEqual(lr.first_block_after(chain, EDIT), FIRST)
        self.assertEqual(int(chain.blocks[FIRST]["timestamp"], 16), EDIT + 1)
        self.assertEqual(int(chain.blocks[FIRST - 1]["timestamp"], 16), EDIT - 1)
        self.assertIsNone(lr.first_block_after(chain, EDIT + 10_000), "no block that late has been mined")

    def test_the_rule_picks_one_task_of_each_type_after_the_edit_by_block_hash(self):
        held = lr.pick_held_out(held_taskset(), MadeChain(BLOCKS), now=0)
        self.assertEqual([p["type"] for p in held["picks"]], ["transfer", "native-transfer", "reverted", "approve", "swap"])
        self.assertEqual([p["blockNumber"] - FIRST for p in held["picks"]], [1, 3, 5, 6, 7])
        self.assertEqual([p["index"] for p in held["picks"]], [1, 0, 1, 0, 0], "the transaction the block's hash selects, never another")
        self.assertEqual(held["skipped"], 3, "a call, an empty block and a swap with too many movements")
        self.assertEqual(held["notFound"], [])
        self.assertEqual(held["afterBlock"], FIRST)
        self.assertTrue(all(lr.iso_seconds(p["blockTime"]) > EDIT for p in held["picks"]))
        self.assertEqual(lr.held_out_problems(held, held_taskset()), [])
        # The checks are written from the chain's own answer, and it passes them.
        chain = MadeChain(BLOCKS)
        self.assertEqual(lr.verify_tasks(held, chain), [])
        self.assertEqual(lr.review_problem(held), "not reviewed yet")

    def test_the_same_rule_picks_the_same_tasks_again_and_a_swapped_task_is_caught(self):
        ts = held_taskset()
        held = lr.pick_held_out(ts, MadeChain(BLOCKS), now=0)
        self.assertEqual(lr.verify_held_out(held, ts, MadeChain(BLOCKS)), [])
        # A task from before the edit, put in a held-out task's place and rehashed.
        early = made_tx("transfer", FIRST - 2, 0)[0]
        swapped = copy.deepcopy(held)
        swapped["tasks"][0].update(txHash=early["hash"], blockNumber=FIRST - 2)
        swapped["picks"][0].update(txHash=early["hash"], blockNumber=FIRST - 2, blockTime="2026-10-31T23:59:57Z")
        swapped["heldOutSha256"] = lr.held_out_sha256(swapped)
        problems = lr.verify_held_out(swapped, ts, MadeChain(BLOCKS))
        self.assertTrue(any("not after the edit" in p for p in problems), problems)
        self.assertTrue(any("mined at or before the edit" in p for p in problems), problems)
        self.assertIn("the rule does not pick these transactions", problems)
        # A later transaction of the right type that the block's hash did not select.
        cherry = copy.deepcopy(held)
        other = made_tx("call", FIRST + 9, 0)[0]
        cherry["tasks"][4]["txHash"] = cherry["picks"][4]["txHash"] = other["hash"]
        cherry["heldOutSha256"] = lr.held_out_sha256(cherry)
        self.assertIn("the rule does not pick these transactions", lr.verify_held_out(cherry, ts, MadeChain(BLOCKS)))
        # An edited file that was not rehashed, and one picked for another skill version or another edit time.
        edited = copy.deepcopy(held)
        edited["tasks"][1]["checks"] = edited["tasks"][1]["checks"][:1]
        self.assertIn("heldOutSha256 does not match the held-out tasks", lr.held_out_problems(edited, ts))
        self.assertIn("the held-out tasks were picked for another version of the skill", lr.held_out_problems(held, taskset(skill_sha="0" * 64)))
        self.assertIn("the held-out tasks were picked from another editAt than the task set's", lr.held_out_problems(held, {**ts, "heldOut": {"editAt": "2026-11-02T00:00:00Z"}}))

    def test_a_type_the_chain_does_not_give_is_listed_and_too_few_tasks_is_a_problem(self):
        held = lr.pick_held_out(held_taskset(types=["transfer", "approve", "unknown"], max_scan=4), MadeChain(BLOCKS), now=0)
        self.assertEqual([p["type"] for p in held["picks"]], ["transfer"])
        self.assertEqual(held["notFound"], ["approve", "unknown"])
        self.assertIn("1 held-out tasks, fewer than 3", lr.held_out_problems(held))

    def test_a_run_counts_tune_and_held_out_side_by_side(self):
        chain, ts = MadeChain(BLOCKS), held_taskset()
        held = reviewed(lr.pick_held_out(ts, chain, now=0))
        model = BothModel(held, chain, wrong={("held-reverted", "with"), ("held-swap", "with"), ("held-swap", "without"), ("usdc-transfer", "without")})
        lift, results, _ = lr.run(ts, SKILL, CFG, model, chain, self.budget(), now=0, held=held)
        self.assertEqual(lift["state"], "complete")
        self.assertEqual(lift["tune"]["with"], {"passed": 5, "failed": 0, "incomplete": 0, "of": 5})
        self.assertEqual(lift["lift"], 1, "lift stays the tune set's, as before")
        self.assertEqual(lift["heldOut"]["with"], {"passed": 3, "failed": 2, "incomplete": 0, "of": 5})
        self.assertEqual(lift["heldOut"]["without"]["passed"], 4)
        self.assertEqual(lift["heldOut"]["state"], "complete")
        self.assertEqual(lift["heldOut"]["reviewedBy"], "632")
        self.assertEqual(lift["gap"], {"tuneMissed": 0, "heldOutMissed": 2})
        self.assertEqual([p["txHash"] for p in lift["heldOut"]["picks"]], [t["txHash"] for t in held["tasks"]])
        self.assertEqual(lift["heldOut"]["rule"], "block-hash-v1")
        self.assertIsNone(lift["heldOut"]["previous"])
        self.assertEqual(lr.lift_block_problems(lift, SKILL_SHA, ts), [])

    def test_unreviewed_or_invalid_held_out_tasks_never_read_complete(self):
        chain, ts = MadeChain(BLOCKS), held_taskset()
        held = lr.pick_held_out(ts, chain, now=0)
        lift, _, _ = lr.run(ts, SKILL, CFG, BothModel(held, chain), chain, self.budget(), now=0, held=held)
        self.assertEqual(lift["heldOut"]["state"], "unreviewed")
        broken = copy.deepcopy(held)
        broken["tasks"][0]["blockNumber"] = FIRST - 1
        lift, results, _ = lr.run(ts, SKILL, CFG, BothModel(held, chain), chain, self.budget(), now=0, held=broken)
        self.assertEqual(lift["heldOut"]["state"], "invalid")
        self.assertIsNone(lift["gap"])
        self.assertNotIn("held-transfer", results, "invalid held-out tasks are not run")

    def test_the_proxy_is_uncalibrated_until_a_runtime_record_agrees(self):
        chain, ts = MadeChain(BLOCKS), held_taskset()
        held = reviewed(lr.pick_held_out(ts, chain, now=0))
        record = {"runtime": "hivepunkz-agents step runner", "model": "test/model-1", "proxySha256": lr.proxy_sha256(), "tasksetSha256": ts["tasksetSha256"],
                  "ranAt": "2026-11-21T00:00:00Z", "results": {t["id"]: "pass" for t in ts["tasks"]}}
        run = lambda calibration, wrong=(): lr.run(ts, SKILL, CFG, BothModel(held, chain, wrong), chain, self.budget(), now=0, held=held, calibration=calibration)[0]["calibration"]
        self.assertEqual(run(None)["label"], "proxy-uncalibrated")
        agreed = run(record)
        self.assertEqual((agreed["label"], agreed["agree"], agreed["disagree"], agreed["of"]), ("calibrated", 5, 0, 5))
        self.assertEqual(agreed["tasks"]["router-swap"], {"proxy": "pass", "runtime": "pass"})
        one = run({**record, "results": {**record["results"], "router-swap": "fail"}})
        self.assertEqual((one["label"], one["disagree"]), ("calibrated", 1), "one task apart is inside the bar")
        two = run({**record, "results": {**record["results"], "router-swap": "fail", "usdc-transfer": "fail"}})
        self.assertEqual((two["label"], two["disagree"]), ("proxy-uncalibrated", 2))
        self.assertIn("another model", run({**record, "model": "test/model-2"})["why"])
        self.assertIn("prompt or tools changed", run({**record, "proxySha256": "0" * 64})["why"])
        self.assertIn("another task set", run({**record, "tasksetSha256": "0" * 64})["why"])
        missing = dict(record["results"]); missing.pop("router-swap")
        self.assertEqual(run({**record, "results": missing})["label"], "proxy-uncalibrated")

    def promotable(self, wrong=(), previous="OLDER skill text\n", calibrate=True):
        chain, ts = MadeChain(BLOCKS), held_taskset()
        held = reviewed(lr.pick_held_out(ts, chain, now=0))
        record = {"runtime": "hivepunkz-agents step runner", "model": "test/model-1", "proxySha256": lr.proxy_sha256(), "tasksetSha256": ts["tasksetSha256"],
                  "ranAt": "2026-11-21T00:00:00Z", "results": {t["id"]: "pass" for t in ts["tasks"]}}
        return lr.run(ts, SKILL, CFG, BothModel(held, chain, wrong), chain, self.budget(), now=0, held=held, calibration=record if calibrate else None, previous_skill_text=previous)[0]

    def test_a_promotion_holds_on_held_out_tasks_against_the_previous_skill(self):
        lift = self.promotable(wrong={("held-swap", "previous"), ("held-swap", "with")})
        self.assertEqual(lift["heldOut"]["previous"], {"skillSha256": lr.sha256_bytes(b"OLDER skill text\n"), "passed": 4, "failed": 1, "incomplete": 0, "of": 5})
        self.assertEqual(lift["previousSkillSha256"], lr.sha256_bytes(b"OLDER skill text\n"))
        self.assertEqual(lr.promotion_problems(lift), [], "the same held-out count as the previous skill is not a drop")
        self.assertEqual(lr.lift_block_problems(lift, SKILL_SHA, held_taskset()), [])

    def test_a_promotion_fails_on_a_held_out_drop(self):
        lift = self.promotable(wrong={("held-swap", "with"), ("held-approve", "with")})
        self.assertEqual(lr.promotion_problems(lift), ["the held-out count dropped: 3 against the previous skill's 5, of 5"])

    def test_a_promotion_fails_without_held_out_tasks_or_with_tasks_from_before_the_edit(self):
        lift = self.promotable()
        self.assertIn("no held-out block", lr.promotion_problems({**lift, "heldOut": {"state": "missing"}}))
        self.assertIn("no held-out block", lr.promotion_problems({k: v for k, v in lift.items() if k != "heldOut"}))
        early = copy.deepcopy(lift)
        early["heldOut"]["picks"][0]["blockNumber"] = FIRST - 1
        self.assertIn(f"held-out task held-transfer is from block {FIRST - 1}, not after the edit", lr.promotion_problems(early))
        self.assertTrue(any("not after the edit" in p for p in lr.lift_block_problems(early, SKILL_SHA)))
        stamped = copy.deepcopy(lift)
        stamped["heldOut"]["picks"][0]["blockTime"] = EDIT_AT
        self.assertIn("held-out task held-transfer was mined at or before the edit", lr.promotion_problems(stamped))
        few = copy.deepcopy(lift)
        few["heldOut"]["picks"] = few["heldOut"]["picks"][:2]
        for arm in ("with", "without"):
            few["heldOut"][arm]["of"] = 2
        self.assertIn("2 held-out tasks, fewer than 3", lr.promotion_problems(few))

    def test_a_promotion_fails_on_a_missing_or_failed_calibration_and_an_unfinished_run(self):
        self.assertEqual(lr.promotion_problems(self.promotable(calibrate=False)), ["the proxy is not calibrated: the tasks have not been run through the agent runtime"])
        lift = self.promotable()
        self.assertIn("no calibration record", lr.promotion_problems({k: v for k, v in lift.items() if k != "calibration"}))
        forged = {**lift, "calibration": {"label": "calibrated", "proxySha256": lr.proxy_sha256()}}
        self.assertIn("the calibration record does not back its label", lr.promotion_problems(forged))
        self.assertIn("a calibrated label without the agreement that backs it", lr.lift_block_problems(forged, SKILL_SHA))
        self.assertIn("the run is unreviewed, not complete", lr.promotion_problems({**lift, "state": "unreviewed", "lift": None}))
        norun = self.promotable(previous=None)
        self.assertEqual(lr.promotion_problems({**norun, "previousSkillSha256": "9" * 64}), ["the previous skill was not run on the held-out tasks"])
        self.assertEqual(lr.promotion_problems(norun), [], "a first version has no previous skill to hold against")

    def test_the_audit_says_what_a_record_lacks(self):
        self.assertEqual(lr.audit(lr.load_json(ROOT / "lift/tx-explain/runs/2026-11-17.json")["lift"]), ["no held-out counts", "no calibration label"])
        self.assertEqual(lr.audit(self.promotable(calibrate=False)), ["proxy-uncalibrated"])
        self.assertEqual(lr.audit(self.promotable()), [])


if __name__ == "__main__":
    unittest.main()
