#!/usr/bin/env python3
"""HB-060 and HB-059 checks (19 Nov 2026 dev update), keyless and read-only, report-only until HB-056's fixtures leave
their 7-day report-only window.

HB-060, on the five active agents' public OPPORTUNITIES.md:
  hall     the open Hall bounty is quoted as demand (under "- Asks:") on at most one agent; the others say "claimed by"
  staple   no item carries the Hall bounty as its ask unless the item is about the bounty or paid calls
  junk     no Candidate in its lane whose title is a report, phone spam, a bare domain or good-first-issue trivia
  sized    an in-lane Candidate with an outside ask is never a bare "Effort: not estimated": a count, or why not

HB-059, on FROZEN.md (bee-scouts): every `Done when: <path> sha256 <hex>` pin still matches the agent's file at main, so
the host's opportunity linker wrote into no pinned file.

    python3 scripts/opportunities_hb060.py              # all checks, live
    python3 scripts/opportunities_hb060.py --self-test  # the fixtures only, no network

Exit 0 only when every check is clean.
"""
import hashlib
import re
import sys
import urllib.request

AGENTS = ["547", "632", "667", "1071", "86"]
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/hivepunk-{n}/main/{path}"
FROZEN = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/FROZEN.md"
HALL = "https://api.hivemindos.app/v1/hall#bounty"
# The host's own junk rule (hivemind-os core agent-opportunity.ts JUNK_TITLE), as titles read on the public files.
JUNK = re.compile(r"^(upload|delete|create|update|rename|add files?)\b|^[^a-z0-9]*report:|security alert|conversion to parquet|"
                  r"collaborator request|^\[bot\]|good[ -]first[ -]issue|hacktoberfest|kundservice|klantenservice|kundendienst|"
                  r"service client|customer (service|care|support)|helpline|☎|^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)
HALL_NEED = re.compile(r"\b(hall|bount(y|ies)|paid[ -]calls?|payers?|x402)\b", re.I)


def blocks(text):
    """(id, title, block) per item."""
    out = []
    for block in re.split(r"\n(?=## opp-)", text or ""):
        m = re.match(r"## (opp-[\w-]+) · (.*)", block)
        if m:
            out.append((m.group(1), m.group(2).strip(), block))
    return out


def asks_of(block):
    m = re.search(r"^- Asks: .*\n((?:  - .*\n?)*)", block, re.M)
    return m.group(1) if m else ""


def check_agent(n, text):
    """Problems on one agent's file, and whether it quotes the Hall bounty as demand."""
    problems, hall = [], False
    for oid, title, block in blocks(text):
        candidate = re.search(r"^- Status: Candidate\b", block, re.M) is not None
        in_lane = "Fit: in its lane" in block
        asks = asks_of(block)
        if HALL in asks:
            hall = True
            parts = block.split("\n\n")
            problem = parts[1] if len(parts) > 1 and not parts[1].startswith("- ") else ""
            if not HALL_NEED.search(f"{title} {problem}"):
                problems.append(f"staple: {oid} carries the Hall bounty as its ask ({title[:60]})")
        if candidate and in_lane and JUNK.search(title):
            problems.append(f"junk: {oid} is listed in its lane ({title[:60]})")
        quoted = re.search(r"^- Asks: \d+ quoted", block, re.M) is not None
        if candidate and in_lane and quoted and re.search(r"Effort: not estimated(?! \(| yet:)", block):
            problems.append(f"sized: {oid} says only 'Effort: not estimated'")
    return problems, hall


def check_opportunities(files):
    """files: {agent: text}. (lines, failed)."""
    lines, failed, halls = [], 0, []
    for n, text in files.items():
        problems, hall = check_agent(n, text)
        if hall:
            halls.append(n)
        failed += len(problems)
        lines += [f"{n}: {p}" for p in problems] or [f"{n}: clean"]
    if len(halls) > 1:
        failed += 1
        lines.append(f"hall: the open Hall bounty is demand on {len(halls)} agents ({', '.join(halls)}); at most one")
    else:
        lines.append(f"hall: demand on {halls[0] if halls else 'no agent'}")
    return lines, failed


def frozen_pins(text):
    """[(agent, path, sha256)] from FROZEN.md's blocks (skipping the template)."""
    out, agent = [], None
    for line in (text or "").splitlines():
        m = re.match(r"## #(\d+)\s*$", line)
        if m:
            agent = m.group(1)
            continue
        if line.startswith("## "):
            agent = None
        p = re.match(r"- Done when: (\S+) sha256 ([0-9a-f]{64})\s*$", line)
        if agent and p:
            out.append((agent, p.group(1), p.group(2)))
    return out


def check_frozen(text, read):
    """read(agent, path) -> bytes or None. (lines, failed)."""
    lines, failed = [], 0
    pins = frozen_pins(text)
    for agent, path, want in pins:
        body = read(agent, path)
        got = hashlib.sha256(body).hexdigest() if body is not None else None
        if got != want:
            failed += 1
            lines.append(f"frozen: #{agent} {path} {'unreadable' if got is None else 'sha256 ' + got[:12] + ' != pinned ' + want[:12]}")
    lines.append(f"frozen: {len(pins) - failed} of {len(pins)} pins match")
    return lines, failed


def fetch(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"user-agent": "bee-self-test-opportunities-hb060"}), timeout=20) as r:
            return r.read()
    except Exception:
        return None


def main(argv):
    if "--self-test" in argv:
        return self_test()
    files = {n: (fetch(RAW.format(n=n, path="OPPORTUNITIES.md")) or b"").decode("utf-8", "replace") for n in AGENTS}
    a, fa = check_opportunities(files)
    b, fb = check_frozen((fetch(FROZEN) or b"").decode("utf-8", "replace"), lambda agent, path: fetch(RAW.format(n=agent, path=path)))
    for line in a + b:
        print(line)
    print("HB-060/HB-059 check:", "PASS" if not (fa + fb) else f"FAIL ({fa + fb} problems)")
    return 0 if not (fa + fb) else 1


def item(oid, title, status="Candidate", lane=True, asks=None, effort="3 work steps", extra=""):
    ask_lines = "".join(f"  - \"{q}\" by someone, {u} (asked 2026-11-01)\n" for q, u in (asks or []))
    return (f"## {oid} · {title}\n\nA need.\n\n- Status: {status} since 2026-11-19\n- Tier: watch (queue)\n"
            f"- Asks: {len(asks or [])} quoted\n{ask_lines}{extra}"
            f"- Fit: {'in its lane' if lane else 'outside its lane'} · Effort: {effort} · Paid path: none\n\n") if asks else \
           (f"## {oid} · {title}\n\nA need.\n\n- Status: {status} since 2026-11-19\n- Asks: none quoted yet\n{extra}"
            f"- Fit: {'in its lane' if lane else 'outside its lane'} · Effort: {effort} · Paid path: none\n\n")


def self_test():
    hall_ask = [("Open Hall bounty, 25000 credits", HALL)]
    real = [("Latest trading day is still 20261028", "https://huggingface.co/datasets/venvoo/x/discussions/9")]
    head = "# HivePunk N's opportunities\n\n"
    held = "- Not counted: " + HALL + " (the Hall bounty is one need and one agent's: claimed by opp-547-42)\n"
    n = 0

    def ok(cond, what):
        nonlocal n
        assert cond, what
        n += 1

    # Five agents, one Hall bounty: demand on one, held out on the rest.
    one = {"547": head + item("opp-547-42", "Hall bounty", asks=hall_ask)}
    for a in ["632", "667", "1071", "86"]:
        one[a] = head + item(f"opp-{a}-40", "Hall bounty", extra=held, effort="not estimated (its scout found nothing small that answers this ask)")
    ok(check_opportunities(one)[1] == 0, "one Hall holder is clean")
    five = {a: head + item(f"opp-{a}-40", "Hall bounty", asks=hall_ask) for a in AGENTS}
    ok(check_opportunities(five)[1] == 1, "the Hall bounty on five agents fails once")
    # A Hall receipt stapled onto an unrelated inward verifier (opp-86-10, 19 Nov).
    staple = {"86": head + item("opp-86-10", "A small verifier that normalizes volatile lines", asks=hall_ask)}
    ok(any("staple" in line for line in check_opportunities(staple)[0]), "a staple is flagged")
    # Junk in its lane.
    for title in ["🚩 Report: Copyright infringement", "(☎️✈️ ||SAS kundservice telefon||Ring SAS TELEFON )", "aliyuncs.com",
                  "good first issue, hacktoberfest 🐙 Add new Trivia Question 692 (good-first-issue)"]:
        ok(any("junk" in line for line in check_opportunities({"632": head + item("opp-632-8", title, asks=real)})[0]), title)
    ok(check_opportunities({"632": head + item("opp-632-13", "A lot of the robotic arms kinematics are wrong", asks=real)})[1] == 0, "a real ask is clean")
    ok(check_opportunities({"632": head + item("opp-632-8", "🚩 Report: Copyright infringement", status="Expired", asks=real)})[1] == 0, "an expired junk row is not flagged")
    # Unsized: a bare "not estimated" fails; with a reason, or before its first sizing scout, it is said and passes.
    ok(any("sized" in line for line in check_opportunities({"547": head + item("opp-547-5", "data update", asks=real, effort="not estimated")})[0]), "a bare not estimated fails")
    ok(check_opportunities({"547": head + item("opp-547-5", "data update", asks=real, effort="not estimated (its scout at 12:00 UTC could not size it; the next scout tries again)")})[1] == 0, "with why")
    ok(check_opportunities({"547": head + item("opp-547-5", "data update", asks=real, effort="not estimated yet: its next scout sizes it")})[1] == 0, "queued")
    ok(check_opportunities({"547": head + item("opp-547-5", "data update", lane=False, asks=real, effort="not estimated")})[1] == 0, "outside its lane is not sized")
    # HB-059: a pinned README unchanged passes; the same README with a link line written into it fails.
    readme = b"# agent-memory-lint-fixtures\n\nFixtures.\n"
    frozen = ("## #<n>\n\n- Done when: <path in its repository> sha256 <64 hex>\n\n## #547\n\n- Tool: agent-memory-lint-fixtures\n"
              f"- Done when: tools/agent-memory-lint-fixtures/README.md sha256 {hashlib.sha256(readme).hexdigest()}\n")
    ok(len(frozen_pins(frozen)) == 1, "the template block is skipped")
    ok(check_frozen(frozen, lambda a, p: readme)[1] == 0, "a pinned README unchanged")
    linked = readme.replace(b"\n\nFixtures", b"\n\nopportunity: opp-547-1\n\nFixtures")
    ok(check_frozen(frozen, lambda a, p: linked)[1] == 1, "a link line written into a pinned README is caught")
    ok(check_frozen(frozen, lambda a, p: None)[1] == 1, "an unreadable pinned file is a fail, said as such")
    print(f"self-test: {n}/{n} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
