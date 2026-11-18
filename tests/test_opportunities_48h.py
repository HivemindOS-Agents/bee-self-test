import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("opportunities_48h", pathlib.Path(__file__).resolve().parent.parent / "scripts" / "opportunities_48h.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FortyEightHourCheck(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(mod.self_test(), 0)

    def test_exploratory_with_a_quoted_ask_passes_and_watch_does_not(self):
        item = "## opp-632-4 · x\n\n- Tier: {tier}\n- Asks: 1 quoted\n  - \"a quote\" by someone\n"
        self.assertTrue(mod.check_file("# f\n\n" + item.format(tier="exploratory"))[0])
        self.assertFalse(mod.check_file("# f\n\n" + item.format(tier="watch (queue)"))[0])


if __name__ == "__main__":
    unittest.main()
