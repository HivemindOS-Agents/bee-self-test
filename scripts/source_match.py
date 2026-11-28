#!/usr/bin/env python3
"""HB-054 "+": a "verified source" label is a claim, so recompute it.

Sourcify published three advisories on 17 Nov 2026. Two are false "Exact Match" cases: a match on an old creation
transaction stored for an address that holds different code (GHSA-w97v-g4q9-998q), and library call protection that left
the first 21 bytes unchecked (GHSA-mg7q-xhfh-rmfq). So the label alone never counts here.

The rule: take the runtime code Sourcify says it compiled, apply only the transformations Sourcify lists, each held to a
place and size Sourcify's own compiler output lists for that kind, and compare every byte with the code a Base node
that is not Sourcify returns for the address. The outcome is MATCH, DIFFERENT or UNABLE. Anything the rule cannot follow
is UNABLE, and UNABLE is never "verified".

What MATCH does not prove: that the published source compiles to that code. The compile is Sourcify's, taken on trust.

Keyless and read-only: one Sourcify GET and one eth_getCode per address, on the address's own chain. The chains, their
Sourcify paths, RPCs and the contracts HivemindOS names on each are scripts/chains.py's (guard 54): a coin on Robinhood
Chain is read there, a coin on a chain the config does not know is UNABLE, and a named contract with no address yet
is reported EMPTY.

    python3 scripts/source_match.py                 # the contracts HivemindOS's pages name on each chain, and every
                                                    # coin its market lists, each on its own chain
    python3 scripts/source_match.py 0xADDRESS ...   # these Base contracts instead
    python3 scripts/source_match.py --self-test     # the fixtures only

Exit 0: every contract HivemindOS names read MATCH, and no coin its market calls verified read otherwise.
Exit 1: something could not be recomputed or is not listed on Sourcify (a reading to look at, not a mismatch).
Exit 2: a DIFFERENT, or a coin the market calls verified that did not read MATCH.

The rule's one home is HivemindOS's shared core (core/agent-source-match.ts agentSourceMatch), which the agents service
runs before a coin's page may say "Source code verified". This is its second copy, for anyone to run without HivemindOS:
the fixtures are the same bytes as the core's tests/agent-source-match-fixtures.json, pinned below and there by sha256,
and both copies must pass them, so the two cannot drift without one failing.
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chains  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "source-match", "fixtures.json")
FIXTURES_SHA256 = "46f5f40fa28a15ea4dad203bd144184989d9b3090cae4020d79e672252ab7144"
# The chain, its Sourcify path, its second RPC and the contracts HivemindOS names on it all come from scripts/chains.py
# (24 Nov 2026 dev update, section 32.1 B1, guard 54). Before it, this file read Base alone and skipped any coin on
# another chain without a row.
SOURCIFY = chains.SOURCIFY_CONTRACT
MARKETS = "https://agents.hivemindos.app/coins/markets"
MARKET = "https://agents.hivemindos.app/coins/{token}/market"
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def named_targets():
    """(chain, what, address or None): the contracts HivemindOS's own pages and docs name, chain by chain. A contract
    Sourcify does not list reads UNLISTED: nothing is claimed for it, and it is shown so the list is whole."""
    return chains.named()


def empty_rows():
    """A named contract with no address in the config yet (Robinhood Chain's spend cap and agent account today): one
    EMPTY row each, so the gap is reported and never read as nothing to check."""
    return [{"family": "source", "chain": chain["chainId"], "name": what, "outcome": "EMPTY",
             "detail": f"no address on {chain['name']} in scripts/chains.py yet"} for chain, what, address in named_targets() if not address]


def hex_of(value):
    """A 0x hex string as lower-case hex without the prefix, or None when it is not whole bytes of hex."""
    if not isinstance(value, str) or not re.match(r"^0x", value, re.I):
        return None
    h = value[2:].lower()
    return h if len(h) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", h) is not None else None


def whole(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def places(value):
    """The {start, length} places the compiler output lists, as (start, length). A length may arrive as text."""
    out = []
    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue
        length = entry.get("length")
        if isinstance(length, str) and re.fullmatch(r"\d+", length):
            length = int(length)
        start, length = whole(entry.get("start")), whole(length)
        if start is not None and length is not None and length > 0:
            out.append((start, length))
    return out


def rows(value):
    return list(value.values()) if isinstance(value, dict) else []


def source_match(answer, live_code, address):
    """Sourcify's answer for one address and the chain's code for it, recomputed. The same rule, case for case, as
    core/agent-source-match.ts agentSourceMatch."""
    answer = answer if isinstance(answer, dict) else {}
    label = answer["match"][:40] if isinstance(answer.get("match"), str) else None
    base = {"outcome": "UNABLE", "label": label, "transformations": [], "codeBytes": 0, "transformedBytes": 0, "metadataDiffers": False,
            "firstDifference": None, "detail": None}

    def unable(detail):
        return dict(base, detail=detail)

    runtime = answer.get("runtimeBytecode") if isinstance(answer.get("runtimeBytecode"), dict) else None
    code = hex_of(runtime.get("recompiledBytecode")) if runtime else None
    if not code:
        return unable("Sourcify gave no compiled runtime code")
    live = hex_of(live_code)
    if live is None:
        return unable("the chain's code could not be read")
    if not live:
        return unable("there is no code at the address")
    own = hex_of(address)
    if not own or len(own) != 40:
        return unable("the address is not an address")

    values = runtime.get("transformationValues") if isinstance(runtime.get("transformationValues"), dict) else {}
    # A place is matched by where it is, never by its id: on a partial match the two can carry different ids.
    immutable_at = [p for row in rows(runtime.get("immutableReferences")) for p in places(row)]
    link_at = [p for file in rows(runtime.get("linkReferences")) for row in rows(file) for p in places(row)]
    cbor_at = []
    for entry in rows(runtime.get("cborAuxdata")):
        start = whole(entry.get("offset")) if isinstance(entry, dict) else None
        compiled = hex_of(entry.get("value")) if isinstance(entry, dict) else None
        if start is not None and compiled:
            cbor_at.append((start, len(compiled) // 2))
    listed = runtime.get("transformations")
    listed = [] if listed is None else listed
    if not isinstance(listed, list):
        return unable("the transformations are not a list")
    written, applied, metadata = [], set(), False
    for entry in listed:
        if not isinstance(entry, dict):
            return unable("a transformation is not an object")
        reason = entry.get("reason") if isinstance(entry.get("reason"), str) else ""
        offset = whole(entry.get("offset"))
        tid = entry.get("id") if isinstance(entry.get("id"), str) else ""
        if entry.get("type") != "replace":
            return unable(f"a transformation ({reason or 'nameless'}) is not a replace")
        if offset is None:
            return unable(f"a transformation ({reason or 'nameless'}) has no offset")
        of = lambda key: values.get(key).get(tid) if isinstance(values.get(key), dict) else None
        if reason == "immutable":
            value = hex_of(of("immutables"))
            if not value or (offset, len(value) // 2) not in immutable_at:
                return unable("an immutable is not at a place the compiler listed for it")
            if code[offset * 2:offset * 2 + len(value)].strip("0"):
                return unable("an immutable would overwrite code that is not a placeholder")
        elif reason == "library":
            value = hex_of(of("libraries"))
            if not value or len(value) != 40 or (offset, 20) not in link_at:
                return unable("a library address is not at a link the compiler listed for it")
        elif reason == "cborAuxdata":
            value = hex_of(of("cborAuxdata"))
            if not value or (offset, len(value) // 2) not in cbor_at:
                return unable("a metadata change is not where the compiled metadata is")
            metadata = True
        elif reason == "callProtection":
            # GHSA-mg7q-xhfh-rmfq: only PUSH20 at byte 0, a zero placeholder after it, and the contract's own address.
            value = hex_of(values.get("callProtection"))
            if offset != 1 or not value or value != own:
                return unable("call protection would write something other than the contract's own address")
            if code[:2] != "73" or code[2:42].strip("0"):
                return unable("call protection is not over a library's own-address placeholder")
        else:
            return unable(f"a transformation of a kind this check does not know: {reason[:40] or 'nameless'}")
        length = len(value) // 2
        if offset + length > len(code) // 2:
            return unable(f"a transformation ({reason}) runs past the end of the code")
        if any(offset < start + size and start < offset + length for start, size in written):
            return unable("two transformations write the same bytes")
        written.append((offset, length))
        applied.add(reason)
        code = code[:offset * 2] + value + code[(offset + length) * 2:]
    done = dict(base, transformations=sorted(applied), codeBytes=len(live) // 2, transformedBytes=sum(size for _, size in written), metadataDiffers=metadata)
    if code == live:
        return dict(done, outcome="MATCH")
    at, shorter = 0, min(len(code), len(live))
    while at < shorter and code[at] == live[at]:
        at += 1
    return dict(done, outcome="DIFFERENT", firstDifference=at // 2)


def get_json(url, body=None):
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                     headers={"content-type": "application/json", "accept": "application/json", "user-agent": "bee-self-test-source-match"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def read(address, chain=None, fetch=None):
    """One address on one chain (Base when none is named), live: its row, with outcome MATCH, DIFFERENT, UNABLE or
    UNLISTED (Sourcify does not know it). Sourcify's path and the second RPC are that chain's."""
    chain = chain or chains.get(chains.BASE)
    fetch = fetch or get_json
    row = {"family": "source", "chain": chain["chainId"], "address": address}
    try:
        answer = fetch(SOURCIFY.format(chain=chain["chainId"], address=address))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return dict(row, outcome="UNLISTED", label=None, detail="Sourcify does not list this contract")
        return dict(row, outcome="UNABLE", label=None, detail=f"Sourcify answered {error.code}")
    except Exception as error:  # a network fault: never guess
        return dict(row, outcome="UNABLE", label=None, detail=f"Sourcify could not be read: {type(error).__name__}")
    try:
        live = fetch(chain["rpcIndependent"], {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]}).get("result")
    except Exception as error:
        live = None
        row["rpc"] = type(error).__name__
    answer = answer if isinstance(answer, dict) else {}
    result = source_match(answer, live, address)
    proxy = answer.get("proxyResolution") if isinstance(answer.get("proxyResolution"), dict) else {}
    return dict(row, **result, isProxy=proxy.get("isProxy"))


def coin_rows(coins, read_fn=read):
    """Every coin the market lists, each read on its own chain. A coin on a chain the config does not know, or naming
    none, is UNABLE: never skipped, never verified. An entry with no token address is not a coin."""
    rows = []
    for coin in coins:
        token = coin.get("token") if isinstance(coin, dict) else None
        if not isinstance(token, str) or not ADDRESS.match(token):
            continue
        name = f"coin {coin.get('symbol')}"
        chain = chains.by_id(coin.get("chainId"))
        if chain is None or chain not in chains.mainnets():
            rows.append({"family": "source", "chain": coin.get("chainId"), "address": token, "name": name, "outcome": "UNABLE", "label": None,
                         "detail": f"the coin's chain {str(coin.get('chainId'))[:20]} is not in the chain config"})
            continue
        rows.append(dict(read_fn(token, chain), name=name))
    return rows


def self_test():
    raw = open(FIXTURES, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != FIXTURES_SHA256:
        print(f"self-test: FAIL, the fixtures are not the pinned bytes ({digest})")
        return 1
    cases, bad = json.loads(raw)["cases"], 0
    for case in cases:
        got = source_match(case["answer"], case["liveCode"], case["address"])
        if got != case["expect"]:
            bad += 1
            print(f"FAIL {case['name']}: got {json.dumps(got)} expected {json.dumps(case['expect'])}")
    outcomes = {c["expect"]["outcome"] for c in cases}
    if outcomes != {"MATCH", "DIFFERENT", "UNABLE"}:
        bad += 1
        print(f"FAIL the fixtures do not hold every outcome: {sorted(outcomes)}")
    print(f"self-test: {len(cases) - bad}/{len(cases)} {'PASS' if not bad else 'FAIL'}")
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    given = [a for a in argv if ADDRESS.match(a)]
    look, mismatch = 0, 0
    base = chains.get(chains.BASE)
    # Given addresses are read on Base, as before; the named list on every chain that has one.
    named = [(base, "given", a) for a in given] if given else [(c, what, a) for c, what, a in named_targets() if a]
    for chain, name, address in named:
        row = dict(read(address, chain), name=name)
        print(json.dumps(row))
        mismatch += row["outcome"] == "DIFFERENT"
        look += row["outcome"] in ("UNABLE", "UNLISTED")
    if not given:
        # A gap in the config is reported, and counts as nothing read rather than as something to look at: it is a
        # known gap until the chain's contracts are filled (section 32.4).
        empty = empty_rows()
        for row in empty:
            print(json.dumps(row))
        # Every coin the market lists, on its own chain: what its page says, and what the recompute says.
        try:
            coins = get_json(MARKETS).get("coins") or []
        except Exception as error:
            coins = []
            look += 1
            print(json.dumps({"family": "source", "outcome": "UNABLE", "detail": f"the coin market could not be read: {type(error).__name__}"}))
        for row in coin_rows(coins):
            if "isProxy" in row:
                try:
                    market = get_json(MARKET.format(token=row["address"]))
                    safety = (market.get("market") or market).get("safety") or {}
                    row["pageSaysVerified"] = safety.get("sourceVerified")
                except Exception as error:
                    row["pageSaysVerified"] = f"unread: {type(error).__name__}"
                # The page may say "verified" only on a MATCH.
                row["pageBacked"] = row["pageSaysVerified"] is not True or row["outcome"] == "MATCH"
            print(json.dumps(row))
            mismatch += row["outcome"] == "DIFFERENT" or not row.get("pageBacked", True)
            look += row["outcome"] == "UNABLE"
        print(f"source: {mismatch} not backed, {look} to look at, {len(empty)} empty in the chain config")
        return 2 if mismatch else 1 if look else 0
    print(f"source: {mismatch} not backed, {look} to look at")
    return 2 if mismatch else 1 if look else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
