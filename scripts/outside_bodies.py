#!/usr/bin/env python3
"""B-43r: every outside act names itself, and none promotes (B-43, GP-1; HB-026).

Each row of bee-scouts outside/LEDGER.jsonl is a PR or issue an agent opened elsewhere. Its body, read back from GitHub,
must carry the disclosure the host writes (core agent-outside-gate.ts agentOutsideDisclosed: "AI agent (HivePunk #<n>,
HivemindOS)") and none of the words or links the host's preflight refuses (agentOutsidePromotion: airdrops, tokens,
holders, rewards, launches, USDC, wallets, giveaways, a request to star or follow, any hivemindos.app link other than
the agent's own page). The two rules are ported from the host; --self-test holds the cases the dev update asks for (a
promo-word body and a body with no disclosure, both refused) and fails if the port drifts.

  python3 scripts/outside_bodies.py --self-test
  python3 scripts/outside_bodies.py [--ledger <path or URL>]   exit 0 every row passes, 1 a row fails, 2 a row unread
"""
import json
import os
import re
import sys
import urllib.request

ORG = os.environ.get("GITHUB_REPOSITORY_OWNER", "HivemindOS-Agents")
LEDGER = "https://raw.githubusercontent.com/%s/bee-scouts/main/outside/LEDGER.jsonl" % ORG
PROMO_WORDS = re.compile(r"\b(?:airdrops?|tokens?|holders?|rewards?|launch(?:es|ed|pad)?|USDC|wallets?|giveaways?)\b", re.I)
PROMO_ASKS = re.compile(r"\b(?:star|follow)\s+(?:us|this|the repo|our)\b", re.I)
SITE_LINKS = re.compile(r"""https?://(?:www\.)?hivemindos\.app[^\s)\]>"']*""", re.I)


def disclosed(body, agent):
    return ("AI agent (HivePunk #%s, HivemindOS)" % agent) in body


def promotion(body, agent):
    out = []
    for m in list(PROMO_WORDS.finditer(body)) + list(PROMO_ASKS.finditer(body)):
        w = m.group(0).lower()
        if w not in out:
            out.append(w)
    own = "https://hivemindos.app/agents/hivepunkz/%s" % agent
    for m in SITE_LINKS.finditer(body):
        if m.group(0).rstrip("/").lower() != own and m.group(0) not in out:
            out.append(m.group(0))
    return out


def problems(body, agent):
    out = []
    if not disclosed(body, agent):
        out.append("the disclosure is missing")
    out += ["promotion in the body (%s)" % w for w in promotion(body, agent)]
    return out


def get(url, accept="application/json"):
    headers = {"user-agent": "bee-self-test outside-bodies", "accept": accept}
    token = os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def body_of(url):
    m = re.match(r"^https://github\.com/([\w.-]+)/([\w.-]+)/(?:pull|issues)/(\d+)", url or "")
    if not m:
        return None
    return json.loads(get("https://api.github.com/repos/%s/%s/issues/%s" % m.groups())).get("body") or ""


def self_test():
    n = 0
    good = "Fixes the off-by-one in parse().\n\nThis PR was prepared by an AI agent (HivePunk #547, HivemindOS) and independently reproduced by a second agent with a different owner. Reproducer and receipt: https://github.com/x/y and https://hivemindos.app/agents/hivepunkz/547"
    assert problems(good, "547") == [], problems(good, "547"); n += 1
    # The dev update's two fixtures: a promo-word body and a body with no disclosure, both refused.
    assert problems(good + "\nHolders get a reward airdrop, star us!", "547") == ["promotion in the body (holders)", "promotion in the body (reward)", "promotion in the body (airdrop)", "promotion in the body (star us)"]; n += 1
    assert problems("Fixes the off-by-one in parse().", "547") == ["the disclosure is missing"]; n += 1
    # Another agent's disclosure is not its own; a hivemindos.app link other than its own page is promotion.
    assert problems(good.replace("#547", "#632"), "547")[0] == "the disclosure is missing"; n += 1
    assert problems(good + " See https://hivemindos.app/launchpad", "547") == ["promotion in the body (launchpad)", "promotion in the body (https://hivemindos.app/launchpad)"]; n += 1
    assert body_of("https://example.com/x") is None; n += 1
    print("outside bodies: %d cases pass" % n)


def main(argv):
    if argv[:1] == ["--self-test"]:
        self_test()
        return 0
    ledger = argv[argv.index("--ledger") + 1] if "--ledger" in argv else LEDGER
    try:
        text = open(ledger).read() if os.path.exists(ledger) else get(ledger, "text/plain")
    except Exception as e:
        print("UNREAD the ledger: %s" % str(e)[:120])
        return 2
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    failed = unread = 0
    for row in rows:
        try:
            body = body_of(row.get("url"))
        except Exception:
            body = None
        if body is None:
            unread += 1
            print("UNREAD %s" % row.get("url"))
            continue
        found = problems(body, str(row.get("agent", "")))
        if found:
            failed += 1
            print("FAIL %s: %s" % (row.get("url"), "; ".join(found)))
    print("outside bodies: %d rows, %d fail, %d unread" % (len(rows), failed, unread))
    return 2 if unread else 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
