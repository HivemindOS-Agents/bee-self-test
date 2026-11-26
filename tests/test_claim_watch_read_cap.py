"""HB-083 s0 r1 (24 Nov 2026 update, section 18; 25 Nov row HB-087r1): the 40-read cap a host has its failing-first test.

The cap landed in 4005818 with a check of the budget alone. This runs the replay's whole sample path, sample_again,
on a fake chain and a fake clock, so nothing leaves the machine: one host serves every registration file, and the
sample is bigger than the cap. The 41st read of that host is refused, the refused registration is a NOT_READ row
(never RESOLVES and never dropped), the aggregated day row carries it, and the coverage check names it once more than
a tenth of the sample went unread with no host slowed and time left.

    python3 -m unittest discover -s tests -p 'test_claim_watch_read_cap.py'
"""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import claim_watch as cw  # noqa: E402

BODY = '{"type": "agent", "services": [{"name": "a2a", "endpoint": "https://central.example/a2a"}]}'


class FakeChain:
    """Every sampled id is registered, and its file is on one host."""

    def __init__(self):
        self.reads = []
        self.clock = [0.0]

    def registration(self, agent_id):
        return True, f"https://central.example/registrations/{agent_id}.json"

    def read(self, url):
        self.reads.append(url)
        return BODY, hashlib.sha256(BODY.encode()).hexdigest()

    def budget(self, host_cap):
        def sleep(seconds):
            self.clock[0] += seconds
        return ORIGINAL_BUDGET(host_cap, lambda: self.clock[0], sleep)


ORIGINAL_BUDGET = cw.ReadBudget


class ReadCap(unittest.TestCase):
    def setUp(self):
        self.chain = FakeChain()
        self.saved = (cw.registration, cw.read_body_or_slowed, cw.ReadBudget)
        cw.registration, cw.read_body_or_slowed, cw.ReadBudget = self.chain.registration, self.chain.read, self.chain.budget

    def tearDown(self):
        cw.registration, cw.read_body_or_slowed, cw.ReadBudget = self.saved

    def day_rows(self, rows):
        extra = {"seed": "erc8004:base:test", "maxId": 1000, "hostCap": cw.HOST_READS, "slowedHosts": 0, "readsRanOut": 0}
        return cw.aggregate("record", rows, extra)

    def test_the_41st_read_of_a_host_is_refused_and_counted(self):
        rows = cw.sample_again("erc8004:base:test", 41, 1000, host_cap=cw.HOST_READS)
        self.assertEqual(len(rows), 41)
        self.assertEqual(len(self.chain.reads), 40, "the 41st file of one host must not be read")
        outcomes = [r["outcome"] for r in rows]
        self.assertEqual(outcomes.count("RESOLVES"), 40)
        self.assertEqual(outcomes.count("NOT_READ"), 1, "the refused read is a NOT_READ row, never RESOLVES or dropped")
        day = {r["outcome"]: r["count"] for r in self.day_rows(rows)}
        self.assertEqual(day, {"NOT_READ": 1, "RESOLVES": 40})
        self.assertEqual(cw.coverage_problems(self.day_rows(rows)), [], "1 of 41 is under a tenth: shown, not a failure")

    def test_a_cap_that_bites_shows_in_coverage(self):
        rows = cw.sample_again("erc8004:base:test", 60, 1000, host_cap=cw.HOST_READS)
        self.assertEqual(len(self.chain.reads), 40)
        self.assertEqual(cw.coverage_problems(self.day_rows(rows)),
                         ["record sample: 20 of 60 not read (33%), with no host slowed and time left"])

    def test_the_cap_is_forty(self):
        self.assertEqual(cw.HOST_READS, 40)


if __name__ == "__main__":
    unittest.main()
