#!/usr/bin/env python3
"""bee-scouts' issues against its own rules (the 15 Nov proposal bundle, BS2). The agents service refuses these before
an issue is opened (hivemind-os core/bee-scouts-gate.ts); this is the outside check that the gate held.

Fails on any of:
  own-todo       an agent's issue about its own repository, tool folder or dataset (they live in its own repository)
  kind           an open issue with no kind label (hivemind-decision or outside-pr-candidate)
  twin           two open agent issues on the same artifact (the title's longest hyphenated name), same agent
  unconfirmed    an open agent issue with a sentence saying it could not confirm a page it names (a URL)
  cap            more than one new agent issue per agent, or more than three in all, on one UTC day
  untriaged      an issue open more than 14 days with none of triaged, accepted, rejected, outside-pr-candidate
  triage-md      TRIAGE.md last written more than 8 days ago

Every check but untriaged and triage-md reads only agent issues opened since the gate went live (GATE_SINCE); the ones
before it were closed or kept by hand in the 16 Nov triage (#25 and #30, kept, would fail unconfirmed and twin).

own-todo does not read the disclosure footer (HB-064): the host ends every agent issue with "HivePunk #N is a HivemindOS
agent. Its card: ... Its code: https://github.com/HivemindOS-Agents/hivepunk-N." (hivemind-os core/agent-disclosure.ts,
agentDisclosureLine), which names the agent's own repository by design. The check failed on that line alone on every
agent issue from #193, 16 to 20 Nov 2026. Only a whole line in the host's own shape is left out; any other mention of
its repository, tool folder or dataset still fails.

  check_bee_scouts_issues.py --fixtures DIR     the regression cases: DIR/issues.json must give DIR/expected.json, and
                                                so must every folder under DIR that has a case.json
  check_bee_scouts_issues.py ISSUES.json TRIAGE_AT [NOW]
      ISSUES.json is GitHub's issue list (state=all); TRIAGE_AT is TRIAGE.md's last commit time (ISO); prints JSON,
      exits 1 on any problem. Only reads text."""
import json, pathlib, re, sys
from datetime import datetime, timezone

GATE_SINCE = "2026-11-15T16:00:00Z"  # agents release 376eaf66 went live at 15:40 UTC
KINDS = {"hivemind-decision", "outside-pr-candidate"}
TRIAGED = {"triaged", "accepted", "rejected", "outside-pr-candidate"}
AGENT_KINDS = {"bee-proposal", "bee-docs", "bee-benchmark"}
# Kept in step with BEE_SCOUTS_OWN and BEE_SCOUTS_UNCONFIRMED in hivemind-os core/bee-scouts-gate.ts.
OWN = re.compile(r"\bgithub\.com/HivemindOS-Agents/hivepunk-\d+|\bhuggingface\.co/(?:datasets/|spaces/)?hivepunk-\d+|\bhivepunk-\d+(?:-[0-9a-f]{6,})?\b|(?:^|[\s(`\"'])tools/[a-z0-9][a-z0-9-]+/", re.I)
UNCONFIRMED = re.compile(r"\b(?:could not|couldn't|cannot|can't|was unable to|unable to) (?:confirm|verify)\b", re.I)
# HB-064: the disclosure footer as the host writes it (hivemind-os core/agent-disclosure.ts, agentDisclosureLine): a
# whole line, the agent's name, then its card, its code and, when the issue announces one artifact, its receipt.
DISCLOSURE = re.compile(r"^[ \t]*(?P<name>[^\n]{1,80}?) is a HivemindOS agent\. Its card: https://hivemindos\.app/agents/hivepunkz/\d+\. Its code: https://github\.com/HivemindOS-Agents/hivepunk-\d+\.(?: What it did, checkable: \S+\.)?[ \t]*$", re.M)

def when(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))
def labels(i): return {l["name"] if isinstance(l, dict) else l for l in i.get("labels", [])}
def agent(i): return next((l for l in sorted(labels(i)) if re.fullmatch(r"bee-\d+", l)), None)
def by_agent(i):
    u = i.get("user") or {}
    return u.get("type") == "Bot" or str(u.get("login", "")).endswith("[bot]") or bool(labels(i) & AGENT_KINDS)
def artifact(title):
    names = sorted(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", title.lower()), key=len, reverse=True)
    return names[0] if names else None
def without_disclosure(body):
    """The body without its disclosure footer. A line whose name part itself names a repository, tool or dataset is
    not the footer and stays."""
    return DISCLOSURE.sub(lambda m: m.group(0) if OWN.search(m.group("name")) else "", body)
def unconfirmed(text):
    return any(UNCONFIRMED.search(s) and re.search(r"https?://", s) for s in re.split(r"(?<=[.!?])\s+|\n", text))

def check(issues, triage_at, now):
    issues = [i for i in issues if "pull_request" not in i]
    since = when(GATE_SINCE)
    found = []
    def say(kind, i, why): found.append({"check": kind, "issue": i["number"] if i else None, "why": why})
    open_ = [i for i in issues if i["state"] == "open"]
    new = [i for i in issues if by_agent(i) and when(i["created_at"]) >= since]
    for i in new:
        if OWN.search(f"{i['title']}\n{without_disclosure(i.get('body') or '')}"): say("own-todo", i, "names the agent's own repository, tool or dataset")
    for i in open_:
        if not labels(i) & KINDS and when(i["created_at"]) >= since: say("kind", i, "no hivemind-decision or outside-pr-candidate label")
        if i in new and unconfirmed(i.get("body") or ""): say("unconfirmed", i, "says it could not confirm a page it names")
        age = (now - when(i["created_at"])).days
        if age > 14 and not labels(i) & TRIAGED: say("untriaged", i, f"open {age} days with no triage label")
    seen = {}
    for i in sorted((i for i in open_ if by_agent(i)), key=lambda i: i["number"]):
        key = (agent(i), artifact(i["title"]))
        if key[1] is None: continue
        if key in seen and i in new: say("twin", i, f"same agent and artifact as #{seen[key]} ({key[1]})")
        else: seen[key] = i["number"]
    days = {}
    for i in new: days.setdefault(i["created_at"][:10], []).append(i)
    for day, group in sorted(days.items()):
        if len(group) > 3: say("cap", None, f"{len(group)} agent issues on {day} (at most 3)")
        per = {}
        for i in group: per.setdefault(agent(i), []).append(i["number"])
        for a, nums in sorted(per.items(), key=lambda kv: str(kv[0])):
            if len(nums) > 1: say("cap", None, f"{a} opened {len(nums)} on {day} (#{', #'.join(map(str, nums))}; at most 1)")
    if triage_at is None: say("triage-md", None, "TRIAGE.md has never been written")
    elif (now - when(triage_at)).days > 8: say("triage-md", None, f"TRIAGE.md last written {triage_at}, over 8 days ago")
    return found

def fixture(folder, name):
    case = json.loads((folder / "case.json").read_text())
    got = check(json.loads((folder / "issues.json").read_text()), case["triage_at"], when(case["now"]))
    want = json.loads((folder / "expected.json").read_text())
    print(json.dumps(got, indent=1))
    if got != want:
        print(f"{name}: does not match expected.json"); return 1
    print(f"{name}: {len(got)} problems, as expected"); return 0
def fixtures(folder):
    """The folder's own case, then every folder under it that has a case.json. All of them run; any miss fails."""
    cases = [(folder, "regression case")] + [(d, d.name) for d in sorted(folder.iterdir()) if (d / "case.json").is_file()]
    return 1 if sum([fixture(d, name) for d, name in cases]) else 0

if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixtures"]: sys.exit(fixtures(pathlib.Path(sys.argv[2])))
    issues = json.loads(pathlib.Path(sys.argv[1]).read_text())
    triage_at = sys.argv[2] or None
    now = when(sys.argv[3]) if len(sys.argv) > 3 else datetime.now(timezone.utc)
    problems = check(issues, triage_at, now)
    print(json.dumps({"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "open": sum(1 for i in issues if i["state"] == "open" and "pull_request" not in i), "problems": problems}, indent=2))
    sys.exit(1 if problems else 0)
