"""Security inputs fail closed (HB-136, HB-137, HB-138): every public security reader, run as the workflows run it, on
each input in four states (empty, only commas or whitespace, unparseable, absent), and on the fixtures that once read
as clean. A supplied but empty or unparseable input stops the run with exit 2 and a named reason
(`empty_security_setting`, `unparseable_security_setting`), never a traceback and never a pass; only an absent input
with a documented default goes on, and says `default_used`. No network: health files are read with --health.

  python3 -m unittest discover -s tests -p 'test_security_inputs.py'

check_skill_files.py needs PyYAML (pyyaml==6.0.2, as the skill-files workflow installs it)."""
import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
EMPTY, UNPARSEABLE, DEFAULT_USED = "empty_security_setting", "unparseable_security_setting", "default_used"
# The four states of one input. None is absent: the file is not written at all.
STATES = {"empty": "", "commas": " ,, \n,\t\n", "unparseable": "{not json\n", "absent": None}
WANT = {"empty": EMPTY, "commas": EMPTY, "unparseable": UNPARSEABLE, "absent": EMPTY}


def run(*args, cwd=ROOT):
    done = subprocess.run([sys.executable, *map(str, args)], cwd=cwd, capture_output=True, text=True, timeout=120,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return done.returncode, done.stdout, done.stderr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="security-inputs-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, name, text):
        """Writes text at tmp/name, or nothing when text is None (absent). Returns the path either way."""
        path = self.tmp / name
        if text is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return path

    def assertStops(self, result, reason, where=None):
        code, out, err = result
        said = out + err
        self.assertNotIn("Traceback", said, said[-1500:])
        self.assertEqual(code, 2, f"want exit 2 (a STOP), got {code}: {said[-1500:]}")
        self.assertIn(reason, said, said[-1500:])
        if where:
            self.assertIn(where, said, said[-1500:])


class RuleMap(Base):
    """scripts/rule_map_check.py MAP AUTONOMY."""

    def test_map_four_states(self):
        for state, text in STATES.items():
            with self.subTest(state=state):
                path = self.put(f"map-{state}.json", text)
                self.assertStops(run("scripts/rule_map_check.py", path, FIX / "rule-map/AUTONOMY.md"), WANT[state], path.name)

    def test_autonomy_four_states(self):
        states = dict(STATES, unparseable="# notes\n\nNothing here is a numbered rule or a checked list.\n")
        for state, text in states.items():
            with self.subTest(state=state):
                path = self.put(f"AUTONOMY-{state}.md", text)
                self.assertStops(run("scripts/rule_map_check.py", FIX / "rule-map/rule_map.json", path), WANT[state], path.name)

    def test_map_of_the_wrong_shape(self):
        for name, text in [("a list", "[1]\n"), ("an entry that is not an object", '{"rules":[1],"counts":{}}\n')]:
            with self.subTest(name=name):
                path = self.put("map.json", text)
                self.assertStops(run("scripts/rule_map_check.py", path, FIX / "rule-map/AUTONOMY.md"), UNPARSEABLE, "map.json")

    def test_the_fixture_pair_passes(self):
        code, out, err = run("scripts/rule_map_check.py", FIX / "rule-map/rule_map.json", FIX / "rule-map/AUTONOMY.md")
        self.assertEqual(code, 0, out + err)
        self.assertIn("PASS", out)

    def test_autonomy_without_the_deny_line_fails(self):
        """HB-137: every preflight:* entry in the map appears in AUTONOMY.md's checked list, both ways."""
        code, out, err = run("scripts/rule_map_check.py", FIX / "rule-map/rule_map.json", FIX / "rule-map/AUTONOMY-no-deny.md")
        self.assertEqual(code, 1, out + err)
        self.assertIn("preflight:deny: in the map and not in AUTONOMY.md's \"Checked before every call\"", out)

    def test_an_empty_or_missing_checked_section_stops(self):
        md = (FIX / "rule-map/AUTONOMY.md").read_text()
        head = md.split("## Checked before every call")[0]
        for name, text in [("missing", head), ("empty", head + "## Checked before every call\n\nIn code.\n")]:
            with self.subTest(name=name):
                path = self.put(f"AUTONOMY-{name}.md", text)
                self.assertStops(run("scripts/rule_map_check.py", FIX / "rule-map/rule_map.json", path), EMPTY, "Checked before every call")


class ClaimWatch(Base):
    """scripts/claim_watch.py --run, --replay, --coverage and --newest."""

    def test_run_registry_four_states(self):
        for state, text in STATES.items():
            with self.subTest(state=state):
                path = self.put(f"registry-{state}.json", text)
                self.assertStops(run("scripts/claim_watch.py", "--run", path), WANT[state], path.name)

    def test_zero_pinned_skills_is_not_clean(self):
        """HB-138: {"v":1} and zero pins never print an empty day file as a clean one."""
        for name in ("registry-no-skills.json", "registry-zero-skills.json"):
            with self.subTest(name=name):
                self.assertStops(run("scripts/claim_watch.py", "--run", FIX / "claim-watch" / name), EMPTY, name)

    def test_a_pin_with_no_url_is_unparseable(self):
        path = self.put("registry.json", json.dumps({"v": 1, "skills": [{"version": "a/b@1", "sha256": "0" * 64}]}))
        self.assertStops(run("scripts/claim_watch.py", "--run", path), UNPARSEABLE, "registry.json")

    def test_replay_and_coverage_four_states(self):
        for mode in ("--replay", "--coverage"):
            for state, text in STATES.items():
                with self.subTest(mode=mode, state=state):
                    path = self.put(f"day-{state}.jsonl", text)
                    self.assertStops(run("scripts/claim_watch.py", mode, path), WANT[state], path.name)

    def test_an_empty_day_file_is_not_clean(self):
        for mode in ("--replay", "--coverage"):
            with self.subTest(mode=mode):
                self.assertStops(run("scripts/claim_watch.py", mode, FIX / "claim-watch/empty-day.jsonl"), EMPTY, "empty-day.jsonl")

    def test_a_row_of_the_wrong_shape_stops_before_any_read(self):
        path = self.put("day.jsonl", '[1]\n{"day":"2026-11-24","family":"record","target":"sample","outcome":"RESOLVES"}\n')
        self.assertStops(run("scripts/claim_watch.py", "--replay", path), UNPARSEABLE, "day.jsonl")

    def test_coverage_with_no_record_sample_is_not_clean(self):
        path = self.put("day.jsonl", '{"day":"2026-11-21","family":"skill","outcome":"PIN_OK","sha256":"%s","target":"a/b@1","url":"https://x/y"}\n' % ("a" * 64))
        self.assertStops(run("scripts/claim_watch.py", "--coverage", path), EMPTY, "record sample")

    def test_newest_day_from_the_index(self):
        for state, text in dict(STATES, nodays='{"v":1,"days":[]}\n').items():
            with self.subTest(state=state):
                path = self.put(f"index-{state}.json", text)
                self.assertStops(run("scripts/claim_watch.py", "--newest", path), EMPTY if state == "nodays" else WANT[state], path.name)
        path = self.put("index.json", json.dumps({"v": 1, "days": [{"day": "2026-11-24", "sha256": "b" * 64}]}))
        code, out, err = run("scripts/claim_watch.py", "--newest", path)
        self.assertEqual((code, out.strip()), (0, "2026-11-24 " + "b" * 64), err)


class SkillFiles(Base):
    """scripts/check_skill_files.py --fixtures DIR and ROOT."""

    def test_fixtures_absent_stops(self):
        self.assertStops(run("scripts/check_skill_files.py", "--fixtures", self.tmp / "nowhere"), EMPTY, "SKILL.md")

    def test_a_root_that_is_absent_or_holds_no_file_stops(self):
        (self.tmp / "empty-root").mkdir()
        for root in (self.tmp / "absent-root", self.tmp / "empty-root"):
            with self.subTest(root=root.name):
                self.assertStops(run("scripts/check_skill_files.py", root), EMPTY, root.name)

    def test_a_skills_folder_with_no_skill_md_is_bad(self):
        code, out, err = run("scripts/check_skill_files.py", FIX / "skill-files/no-skill-md")
        self.assertNotIn("Traceback", out + err)
        self.assertEqual(code, 1, out + err)
        report = json.loads(out)
        self.assertEqual([(b["repo"], b["skill"]) for b in report["bad"]], [("hivepunk-0", "orphan")])

    def test_an_empty_skill_md_is_bad(self):
        for state in ("empty", "commas"):
            with self.subTest(state=state):
                self.put(f"{state}/hivepunk-1/skills/x/SKILL.md", STATES[state])
                code, out, err = run("scripts/check_skill_files.py", self.tmp / state)
                self.assertEqual(code, 1, out + err)
                self.assertEqual(len(json.loads(out)["bad"]), 1)

    def test_the_regression_fixtures_still_hold(self):
        code, out, err = run("scripts/check_skill_files.py", "--fixtures", FIX / "skill-files")
        self.assertEqual(code, 0, out + err)


class RepairReceipts(Base):
    """scripts/repair_receipts.py DIR --health HEALTH_DIR: a STOP names its file and keeps the rest of the report."""

    def agent(self, latest="ok", health="ok", lessons="- Failed: Research a token, protocol or project · Reason: x · 2026-11-21 06:14 UTC\n", receipts=None):
        repo = self.tmp / "hivepunk-547"
        if latest is not None:
            text = json.dumps({"v": 1, "findings": []}) if latest == "ok" else latest
            self.put("hivepunk-547/watchdog/latest.json", text)
        if lessons is not None:
            self.put("hivepunk-547/LESSONS.md", lessons)
        for name, text in (receipts or {}).items():
            self.put(f"hivepunk-547/repairs/{name}", text)
        if health is not None:
            self.put("health/547.json", json.dumps({"agent": "547", "status": "ok", "repairs": []}) if health == "ok" else health)
        else:
            (self.tmp / "health").mkdir(exist_ok=True)
        return repo

    def report(self, out):
        return json.loads(out)["agents"][0]

    def test_watchdog_latest_four_states(self):
        for state, text in STATES.items():
            with self.subTest(state=state):
                shutil.rmtree(self.tmp, ignore_errors=True); self.tmp.mkdir()
                repo = self.agent(latest=text)
                result = run("scripts/repair_receipts.py", repo, "--health", self.tmp / "health")
                self.assertStops(result, WANT[state], "watchdog/latest.json")
                agent = self.report(result[1])
                self.assertEqual(agent["lessons"]["lines"], 1, "the rest of the agent's report is kept")
                self.assertEqual([s["file"] for s in agent["stops"]], ["watchdog/latest.json"])

    def test_latest_without_findings_stops(self):
        """HB-138: the fixture's latest.json has no findings key; it is not "no findings"."""
        result = run("scripts/repair_receipts.py", FIX / "repair-receipts/watchdog-no-findings/hivepunk-547", "--health", FIX / "repair-receipts/health")
        self.assertStops(result, EMPTY, "findings")
        agent = self.report(result[1])
        self.assertEqual(agent["health"]["status"], "ok", "the rest of the agent's report is kept")

    def test_health_four_states(self):
        for state, text in STATES.items():
            with self.subTest(state=state):
                shutil.rmtree(self.tmp, ignore_errors=True); self.tmp.mkdir()
                repo = self.agent(health=text)
                result = run("scripts/repair_receipts.py", repo, "--health", self.tmp / "health")
                self.assertStops(result, WANT[state], "547.json")
                self.assertEqual(self.report(result[1])["lessons"]["lines"], 1)

    def test_an_unparseable_receipt_stops_and_the_others_are_read(self):
        good = json.loads((FIX / "repair-receipts/one-of-each/repairs/rp-1071-t-reentrancy-cases--e1.json").read_text())
        repo = self.agent(receipts={"rp-1071-t-reentrancy-cases--e1.json": json.dumps(good), "rp-547-t-x--e1.json": "{not json"})
        result = run("scripts/repair_receipts.py", repo, "--health", self.tmp / "health")
        self.assertStops(result, UNPARSEABLE, "repairs/rp-547-t-x--e1.json")
        self.assertEqual(self.report(result[1])["receipts"], 1)

    def test_absent_lessons_and_repairs_use_their_documented_default(self):
        repo = self.agent(lessons=None)
        code, out, err = run("scripts/repair_receipts.py", repo, "--health", self.tmp / "health")
        self.assertNotIn("Traceback", out + err)
        self.assertEqual(code, 0, out + err)
        self.assertIn(DEFAULT_USED, out + err)
        self.assertEqual(sorted(self.report(out)["unread"]), ["LESSONS.md", "repairs/"])

    def test_an_empty_lessons_file_stops(self):
        for state in ("empty", "commas"):
            with self.subTest(state=state):
                shutil.rmtree(self.tmp, ignore_errors=True); self.tmp.mkdir()
                repo = self.agent(lessons=STATES[state])
                self.assertStops(run("scripts/repair_receipts.py", repo, "--health", self.tmp / "health"), EMPTY, "LESSONS.md")


if __name__ == "__main__":
    unittest.main()
