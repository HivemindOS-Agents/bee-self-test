#!/usr/bin/env python3
"""The one chain config (24 Nov 2026 dev update, section 32.1, row 13). Every chain id, CAIP-2 id, RPC, explorer and
contract address a script here uses is in this file and nowhere else: scripts/chain_literals.py (guard 53) fails CI on
a bare one anywhere outside it, and the scripts and tests import what they need from here.

The chain words are the host's: `base` 8453, `ethereum` 1, `robinhood` 4663 (hivemind-os core/chain-marks.ts for the
names, CAIP-2 ids and explorers; hivemindos-website lib/nft/chains.ts for the public RPCs). Base is the only enabled
chain. Robinhood Chain is read and checked, never written to, while its flag is off; nothing in this repository writes
to any chain.

Per chain:
  chainId, hex, caip2   the id three ways (eip155:<chainId>)
  enabled               Base only: the chain HivemindOS's own launches, payments and receipts use
  launchpad             a chain the host's launchpad API names (`chain` base or robinhood)
  testnet, dryRunOnly   a test network; never reachable from a mainnet path (mainnets() leaves it out)
  rpc                   the chain's own public RPC
  rpcIndependent        a second public RPC run by someone else (source_match.py compares Sourcify against it)
  explorer              the chain's explorer
  sourcify              Sourcify lists contracts on it
  erc8004               the ERC-8004 identity registry, or None while it is unfilled or unverified: a registration on
                        a chain with no registry here is "not checkable", never "unregistered" (guard 55)
  x402                  {"v1": the x402 v1 network name, "assets": {symbol: token}}; a listing on another network or
                        asset is "not checkable" (guard 78). Robinhood Chain's x402 asset is USDG; it has no USDC.
  named                 the contracts HivemindOS's own pages name on that chain, (what, address); an address of
                        None is a known gap that source_match.py reports as EMPTY

    python3 scripts/chains.py      # the table, as JSON
"""
import json
import re
import sys

BASE, ETHEREUM, ROBINHOOD = "base", "ethereum", "robinhood"
# The three Base rails stay on Base (section 32.1): $HIVE, x402 pay-per-call and rewards in USDC, and the Bazaar search.
HIVE_PAYMENTS = BASE
HIVE_PAYMENT_ASSET = "USDC"

SOURCIFY_CONTRACT = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=runtimeBytecode,proxyResolution"

CHAINS = {
    BASE: {
        "slug": BASE, "name": "Base", "chainId": 8453, "hex": "0x2105", "caip2": "eip155:8453",
        "enabled": True, "launchpad": True, "testnet": False, "dryRunOnly": False,
        "rpc": "https://mainnet.base.org", "rpcIndependent": "https://base-rpc.publicnode.com",
        "explorer": "https://basescan.org", "sourcify": True,
        "erc8004": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
        "x402": {"v1": "base", "assets": {"USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"}},
        "named": [
            ("HivePunkzAgentsV2 (agents and their spend cap)", "0x28600B0e17cB51EcCDd77BE45723Db3Ca550212f"),
            ("HivePunkzAgentAccountV2 (an agent's wallet)", "0x4eB66Da8C2909F9c936D9E4602eAC1151B7dAf5d"),
            ("AgentPad launch factory, version 3", "0xa4b03e8dD636902d588C7875d5743421159DF34D"),
            ("AgentPad launch factory, version 2", "0x0791F5D582B89435Bf7f81Ae4cf79Bd6838D4073"),
            ("AgentPad pool hook, version 3", "0x13E916f95892b08c65bF50Bf5b4d72E294F7A080"),
            ("AgentPad pool hook, version 2", "0xF2DadEc4f7b4AaC2a3B0669DE19EB555dc83A080"),
            ("AgentPad liquidity locker", "0xb4E0E8427b92b24814F268E80F4b5735fe915324"),
            ("AgentPad liquidity locker (earlier)", "0x4f9e401b1eff02464686b4462E65DFf95f61CCd7"),
            ("HiveBeeReceipts (daily work receipts)", "0x3f36DEae5da90068b3AE7c028b2EFFeC907aB6c0"),
            ("Agent ID keeper", "0x8e87E1221C21b31433BDE68A56C0f1F8Db80F62B"),
        ],
    },
    ROBINHOOD: {
        "slug": ROBINHOOD, "name": "Robinhood Chain", "chainId": 4663, "hex": "0x1237", "caip2": "eip155:4663",
        "enabled": False, "launchpad": True, "testnet": False, "dryRunOnly": False,
        "rpc": "https://rpc.mainnet.chain.robinhood.com", "rpcIndependent": "https://robinhood-rpc.publicnode.com",
        "explorer": "https://robinhoodchain.blockscout.com", "sourcify": True,
        # The erc-8004-contracts README lists Base's address here too, and code is there, but that it is the genuine
        # registry (its proxy's implementation) is unverified (section 32.4). Unfilled until it is.
        "erc8004": None,
        "x402": {"v1": "robinhood", "assets": {"USDG": "0x5fc5360d0400a0fd4f2af552add042d716f1d168"}},
        # The host's platform-api BALLPIT_DEPLOYMENTS.robinhood. No spend-cap contract or agent account is published
        # on 4663 yet (section 32.2 R1): known gaps, reported as EMPTY.
        "named": [
            ("HivePunkzAgentsV2 (agents and their spend cap)", None),
            ("HivePunkzAgentAccountV2 (an agent's wallet)", None),
            ("AgentPad launch factory", "0x1eC287ECc0ce8e395B17a6bEfEf5D1B86B120215"),
            ("AgentPad pool hook", "0xD8548F98bC9d02F5cAEc5e02E5ea6be0fAC26080"),
            ("AgentPad liquidity locker", "0x69a16846657d9B5fA35431c48b4aD85534d7784f"),
        ],
    },
    ETHEREUM: {
        "slug": ETHEREUM, "name": "Ethereum", "chainId": 1, "hex": "0x1", "caip2": "eip155:1",
        "enabled": False, "launchpad": False, "testnet": False, "dryRunOnly": False,
        "rpc": "https://ethereum-rpc.publicnode.com", "rpcIndependent": "https://eth.drpc.org",
        "explorer": "https://etherscan.io", "sourcify": True,
        "erc8004": None, "x402": None, "named": [],
    },
    "base-sepolia": {
        "slug": "base-sepolia", "name": "Base Sepolia", "chainId": 84532, "hex": "0x14a34", "caip2": "eip155:84532",
        "enabled": False, "launchpad": False, "testnet": True, "dryRunOnly": True,
        "rpc": None, "rpcIndependent": None, "explorer": None, "sourcify": False,
        "erc8004": None, "x402": {"v1": "base-sepolia", "assets": {}}, "named": [],
    },
    "robinhood-testnet": {
        # Row 16's dry run (section 32.3): its own entry, testnet only. The testnet ERC-8004 registry is not the
        # mainnet one, and there is no USDG here (the run deploys a token labelled MOCK).
        "slug": "robinhood-testnet", "name": "Robinhood Chain testnet", "chainId": 46630, "hex": "0xb626", "caip2": "eip155:46630",
        "enabled": False, "launchpad": False, "testnet": True, "dryRunOnly": True,
        "rpc": None, "rpcIndependent": None, "explorer": None, "sourcify": False,
        "erc8004": "0x8004A818BFB912233c491871b3d84c89A494BD9e", "x402": None, "named": [],
    },
}

CAIP2 = re.compile(r"^eip155:(\d+)$")
CAIP10 = re.compile(r"^eip155:(\d+):(0x[0-9a-fA-F]{40})$")


def get(slug, table=None):
    """A chain by its word, or None."""
    return (table or CHAINS).get(slug)


def by_id(chain_id, table=None):
    """A chain by its id (an int, a decimal string or 0x hex), or None. A bool is not an id."""
    if isinstance(chain_id, bool):
        return None
    if isinstance(chain_id, str):
        text = chain_id.strip().lower()
        try:
            chain_id = int(text, 16) if text.startswith("0x") else int(text) if text.isdigit() else None
        except ValueError:
            chain_id = None
    if not isinstance(chain_id, int):
        return None
    return next((c for c in (table or CHAINS).values() if c["chainId"] == chain_id), None)


def by_caip2(text, table=None):
    m = CAIP2.match(str(text or "").strip().lower())
    return by_id(int(m.group(1)), table) if m else None


def by_network(text, table=None):
    """An x402 network, v2 (eip155:<id>) or v1 (its name), as its chain, or None."""
    text = str(text or "").strip().lower()
    return by_caip2(text, table) or next((c for c in (table or CHAINS).values() if c.get("x402") and c["x402"]["v1"] == text), None)


def caip2(slug):
    return CHAINS[slug]["caip2"]


def rpc(slug):
    return CHAINS[slug]["rpc"]


def mainnets(table=None):
    """Every chain a mainnet path may read: no testnet or dry-run entry."""
    return [c for c in (table or CHAINS).values() if not c["testnet"] and not c["dryRunOnly"]]


def launchpad_slugs():
    return [c["slug"] for c in mainnets() if c["launchpad"]]


def v1_networks():
    """x402 v1 network names as their CAIP-2 ids (claim_watch.py's accept)."""
    return {c["x402"]["v1"]: c["caip2"] for c in CHAINS.values() if c.get("x402")}


def x402_asset(slug, symbol):
    return CHAINS[slug]["x402"]["assets"][symbol]


def x402_not_checkable(network, asset, table=None):
    """Why an x402 listing's network and asset cannot be checked here, or None when they can (guard 78): its network is a
    configured mainnet and its asset is one of that chain's x402 assets. USDC on Robinhood Chain is not checkable."""
    chain = by_network(network, table)
    if chain is None:
        return f"the network {str(network)[:40] or 'named nowhere'} is not in the chain config"
    if chain["testnet"] or chain["dryRunOnly"]:
        return f"{chain['name']} is a test network"
    assets = (chain.get("x402") or {}).get("assets") or {}
    if not assets:
        return f"no x402 asset is configured on {chain['name']}"
    if str(asset or "").lower() not in {a.lower() for a in assets.values()}:
        return f"the asset is not {' or '.join(sorted(assets))} on {chain['name']}"
    return None


def registry_reading(agent_registry, table=None):
    """An ERC-8004 `agentRegistry` (eip155:<chainId>:<registry>) as (chain, state): "checkable" when it names that
    chain's configured registry, "unfilled" when the chain is configured with no registry yet, "unknown" when the chain
    is not configured (or is a test network), and "other" when it names another contract on a configured chain."""
    m = CAIP10.match(str(agent_registry or "").strip())
    chain = by_id(int(m.group(1)), table) if m else None
    if chain is None or chain["testnet"] or chain["dryRunOnly"]:
        return chain, "unknown"
    if not chain["erc8004"]:
        return chain, "unfilled"
    return chain, "checkable" if m.group(2).lower() == chain["erc8004"].lower() else "other"


def named(table=None):
    """(chain, what, address or None) for every contract HivemindOS names, chain by chain."""
    return [(c, what, address) for c in mainnets(table) for what, address in c["named"]]


def literal_patterns(table=None):
    """What guard 53 looks for outside this file: each configured chain id as a number (Ethereum's 1 aside, which is any
    count) and as hex, and every RPC and explorer host."""
    out = []
    for c in (table or CHAINS).values():
        if c["chainId"] != 1:
            out.append((str(c["chainId"]), re.compile(r"(?<![\w.])" + str(c["chainId"]) + r"(?![\w])")))
            out.append((c["hex"], re.compile(r"(?<![\w])" + re.escape(c["hex"]) + r"(?![0-9a-f])", re.I)))
        for url in (c["rpc"], c["rpcIndependent"], c["explorer"]):
            if url:
                host = re.sub(r"^https?://", "", url).split("/")[0]
                out.append((host, re.compile(re.escape(host), re.I)))
    return out


if __name__ == "__main__":
    json.dump(CHAINS, sys.stdout, indent=1)
    print()
