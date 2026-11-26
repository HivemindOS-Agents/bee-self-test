#!/usr/bin/env python3
"""HB-087 (23 Nov 2026 v5 update, section 2; 25 Nov HB-087r1): the launch fixes are live, and each has a guard.

Nine launch fixes passed live on 23 Nov with no CI test or monitor, so any of them could quietly come back. These are
their public guards, read from the public files and endpoints with no key, each with a seeded bad fixture that must
fail and a good one that must pass (--self-test):

  M1  no agent-facing source says the agent wakes at $20 (llms.txt, the AgentPad llms.txt and SKILL.md, openapi.json,
      /v1/catalog); "buy $20" examples are fine
  M2  every live coin's fees.wakesAtUsd is the approved $10
  M3  the fee and burn lines keep "first $10" (the site's llms.txt, the AgentPad llms.txt and SKILL.md)
  M4  no incident on /v1/status stays open over 3 days with no update (the monitor the v5 table names)
  M6  openapi.json has no duplicate operationId, and every Launchpad POST has a requestBody
  M9  every service /v1/catalog lists answers /v1/pricing?service=<id> with a price
  HB-076  every coin-holding agent has its health/<n>.json in bee-scouts

Not here, and why: M5 (one tool count across the MCP docs, llms.txt and SKILL.md) has no single public count to hold
since AgentPad's SKILL.md lists ten tools and the others name none; M7 (the documented API slippage default against
the API's real default) and M8 (docs search "AgentPad launch" finds passages) need an endpoint that answers them
without a key, which is not public. Those three stay with the host's own build checks.

    python3 scripts/launch_fix_guards.py --self-test     # the fixtures only, no network
    python3 scripts/launch_fix_guards.py                 # the live public files

Exit 0: every guard holds. 1: one does not. 2: a source could not be read (never counted as a pass).
"""
import datetime
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "HivemindOS-launch-fix-guards/0.1 (read-only; https://hivemindos.app)"
SITE, API, AGENTS = "https://hivemindos.app", "https://api.hivemindos.app", "https://agents.hivemindos.app"
HEALTH = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/health/{}.json"
WAKE_USD = 10
STALE_INCIDENT = datetime.timedelta(days=3)
# M1, from the v5 suggested code, widened to "the first $20" written with markdown bold.
WAKE_20 = re.compile(r"(?:first|after|wakes?\s+(?:at|after)?|threshold\D{0,20})\s*\**\s*\$\s*20\b", re.I)
FIRST_10 = re.compile(r"first\s*\**\s*\$\s*10\b", re.I)


def m1_no_20_wake(texts):
    return [f"M1: $20 wake wording in {name}: {m.group(0)!r}" for name, t in texts.items() for m in [WAKE_20.search(t)] if m]


def m3_first_10(texts):
    return [f"M3: {name} no longer says the first $10" for name, t in texts.items() if not FIRST_10.search(t)]


def m2_wake_threshold(coins):
    """coins: {agent: coin record from /agents/<n>/coin}."""
    out = []
    for agent, rec in sorted(coins.items()):
        fees = rec.get("fees") if isinstance(rec, dict) else None
        wake = fees.get("wakesAtUsd") if isinstance(fees, dict) else None
        if wake != WAKE_USD:
            out.append(f"M2: coin of #{agent} wakes at {wake!r}, not ${WAKE_USD}")
    return out


def m4_incidents(status, now):
    out = []
    incidents = status.get("incidents") if isinstance(status, dict) else None
    active = incidents.get("active") if isinstance(incidents, dict) else None
    if not isinstance(active, list):
        return ["M4: /v1/status has no incidents.active list"]
    for inc in active:
        stamps = [inc.get("startedAt"), inc.get("updatedAt")] + [u.get("at") for u in inc.get("updates") or [] if isinstance(u, dict)]
        times = [parse(s) for s in stamps if s]
        newest = max([t for t in times if t] or [None]) if times else None
        if newest is None or now - newest > STALE_INCIDENT:
            out.append(f"M4: incident {inc.get('id')} ({inc.get('title')!r}) open with no update since {newest}")
    return out


def m6_openapi(spec):
    errs, ids = [], {}
    for path, ops in (spec.get("paths") or {}).items():
        for method, op in (ops or {}).items():
            if not isinstance(op, dict):
                continue
            if op.get("operationId"):
                ids[op["operationId"]] = ids.get(op["operationId"], 0) + 1
            if method.lower() == "post" and "launchpad" in path and "requestBody" not in op:
                errs.append(f"M6: POST {path} has no requestBody")
    return errs + [f"M6: duplicate operationId {k}" for k, n in sorted(ids.items()) if n > 1]


def m9_priced(prices):
    """prices: {service id: /v1/pricing body or None}."""
    out = []
    for sid, body in sorted(prices.items()):
        pricing = body.get("pricing") if isinstance(body, dict) else None
        if isinstance(body, dict) and "unread" in body:
            out.append(f"M9: /v1/pricing?service={sid} could not be read twice (HTTP {body['unread']}), so its price is unknown")
            continue
        if not (isinstance(body, dict) and body.get("ok") is True and isinstance(pricing, dict) and pricing):
            out.append(f"M9: {sid} is in /v1/catalog and /v1/pricing gives it no price")
    return out


def hb076_health(coin_agents, present):
    return [f"HB-076: #{n} holds a coin and bee-scouts has no health/{n}.json" for n in sorted(coin_agents) if n not in present]


def parse(stamp):
    try:
        return datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None


def get(url, as_json=True):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "accept": "application/json" if as_json else "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(8 * 1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, None
    except (OSError, ValueError):
        return None, None
    if not as_json:
        return 200, data
    try:
        return 200, json.loads(data)
    except ValueError:
        return 200, None


def live():
    unread, problems = [], []

    def need(url, as_json=True):
        code, body = get(url, as_json)
        if body is None:
            unread.append(f"{url} ({code})")
        return body

    texts = {name: need(url, False) for name, url in [
        ("llms.txt", f"{SITE}/llms.txt"), ("launchpad/llms.txt", f"{SITE}/launchpad/llms.txt"),
        ("launchpad/agents/SKILL.md", f"{SITE}/launchpad/agents/SKILL.md")]}
    spec, catalog = need(f"{API}/openapi.json"), need(f"{API}/v1/catalog")
    texts = {k: v for k, v in texts.items() if v is not None}
    problems += m3_first_10(texts)
    if spec is not None:
        problems += m6_openapi(spec)
        texts["openapi.json"] = json.dumps(spec)
    if catalog is not None:
        texts["/v1/catalog"] = json.dumps(catalog)
    problems += m1_no_20_wake(texts)
    status = need(f"{API}/v1/status")
    if status is not None:
        problems += m4_incidents(status, datetime.datetime.now(datetime.timezone.utc))
    listed = need(f"{AGENTS}/coins")
    agents = [str(c.get("bee")) for c in (listed or {}).get("coins") or [] if isinstance(c, dict) and c.get("bee")]
    if listed is not None and not agents:
        unread.append(f"{AGENTS}/coins (no coin listed: zero is not clean)")
    coins = {}
    for n in agents:
        rec = need(f"{AGENTS}/agents/{n}/coin")
        if rec is not None:
            coins[n] = rec
    problems += m2_wake_threshold(coins)
    present = {n for n in agents if get(HEALTH.format(n))[1] is not None}
    problems += hb076_health(agents, present)
    services = [s.get("id") for s in (catalog or {}).get("services") or [] if isinstance(s, dict) and s.get("id")]
    if catalog is not None and not services:
        unread.append(f"{API}/v1/catalog (no service listed)")
    prices = {}
    for sid in services:
        url = f"{API}/v1/pricing?service={urllib.parse.quote(sid)}"
        code, body = get(url)
        if code != 200 and code not in (400, 404):
            # A 429, a 5xx or no answer says nothing about the price (26 Nov 2026: media-studio once, in CI): ask again once.
            time.sleep(3)
            code, body = get(url)
        prices[sid] = body if code in (200, 400, 404) else {"unread": code}
        time.sleep(0.3)
    problems += m9_priced(prices)
    print(json.dumps({"coins": agents, "services": len(services), "problems": problems, "unread": unread}, indent=2))
    for line in unread:
        print(f"STOP empty_security_setting: {line}: could not be read", file=sys.stderr)
    print(f"launch-fix guards: {len(problems)} problems, {len(unread)} sources unread", file=sys.stderr)
    return 2 if unread else 1 if problems else 0


def self_test():
    bad = []
    now = datetime.datetime(2026, 11, 26, 12, tzinfo=datetime.timezone.utc)
    cases = [
        ("M1 bad: the agent wakes after the first $20", len(m1_no_20_wake({"llms.txt": "the first $20 of fees wakes it"})), 1),
        ("M1 bad: bold markdown", len(m1_no_20_wake({"SKILL.md": "the coin's first **$20** of fees all go to the agent"})), 1),
        ("M1 bad: wakes at $20", len(m1_no_20_wake({"openapi.json": '"description": "It wakes at $20 of fees."'})), 1),
        ("M1 good: a buy $20 example and the $10 wake", len(m1_no_20_wake({"x": "buy $20 of the coin; the first $10 wakes it"})), 0),
        ("M3 bad: the line lost first $10", len(m3_first_10({"launchpad/llms.txt": "the fees go to the agent's thinking"})), 1),
        ("M3 good: bold first $10", len(m3_first_10({"SKILL.md": "the coin's first **$10** of fees all go to the agent"})), 0),
        ("M2 bad: a coin wakes at 20", len(m2_wake_threshold({"104": {"fees": {"wakesAtUsd": 20}}})), 1),
        ("M2 bad: no wake value read", len(m2_wake_threshold({"65": {"fees": {}}})), 1),
        ("M2 good", len(m2_wake_threshold({"104": {"fees": {"wakesAtUsd": 10}}, "65": {"fees": {"wakesAtUsd": 10}}})), 0),
        ("M4 bad: open 4 days with no update", len(m4_incidents({"incidents": {"active": [{"id": "i1", "startedAt": "2026-11-22T10:00:00Z", "updates": [{"at": "2026-11-22T10:00:00Z"}]}]}}, now)), 1),
        ("M4 good: open 4 days, updated today", len(m4_incidents({"incidents": {"active": [{"id": "i1", "startedAt": "2026-11-22T10:00:00Z", "updatedAt": "2026-11-26T09:00:00Z"}]}}, now)), 0),
        ("M4 bad: no incidents list is not 'no incident'", len(m4_incidents({"incidents": {}}, now)), 1),
        ("M6 bad: a duplicate operationId", len(m6_openapi({"paths": {"/a": {"get": {"operationId": "x"}}, "/b": {"get": {"operationId": "x"}}}})), 1),
        ("M6 bad: a Launchpad POST with no requestBody", len(m6_openapi({"paths": {"/launchpad/ballpit/quote": {"post": {"operationId": "q"}}}})), 1),
        ("M6 good", len(m6_openapi({"paths": {"/launchpad/ballpit/quote": {"post": {"operationId": "q", "requestBody": {}}}}})), 0),
        ("M9 bad: a listed service with no price", len(m9_priced({"studio": {"ok": False, "error": "unknown service"}, "x": None})), 2),
        ("M9 good", len(m9_priced({"studio": {"ok": True, "pricing": {"model": "per-operation"}}})), 0),
        ("HB-076 bad: 104 and 65 hold coins, 65 has no health file", len(hb076_health(["104", "65"], {"104"})), 1),
        ("HB-076 good", len(hb076_health(["104", "65"], {"104", "65"})), 0),
    ]
    for name, got, want in cases:
        if got != want:
            bad.append(f"{name}: {got} problems, want {want}")
    for line in bad:
        print("FAIL:", line)
    print(f"launch-fix guards self-test: {len(cases) - len(bad)} of {len(cases)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        print(__doc__)
        sys.exit(2)
    sys.exit(live())
