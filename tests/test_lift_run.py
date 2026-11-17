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
        self.assertEqual(set(lift) - {"stoppedBecause"}, {"skillSha256", "tasksetSha256", "model", "with", "without", "lift", "state", "runAt", "report", "reviewedBy"})
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


if __name__ == "__main__":
    unittest.main()
