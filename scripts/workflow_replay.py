#!/usr/bin/env python3
"""Re-runs one agent workflow's replay as a peer, from public sources only (B-27, S17 of the 24 Nov 2026 dev update).

The agents service writes a replay bundle into the builder agent's repository,
workflows/<slug>/replay/<digest>.json: the workflow's verdict on each published folder it replayed on, with writes
stopped. A workflow is served only after a peer of a different owner re-runs that replay and gets the same verdicts
(core agent-workflow.ts agentWorkflowServable). This script is that re-run. For each input the bundle names it reads,
on its own:

  - the tool folder's files, from the builder's repository tree at main (tools/<tool>/...),
  - the folder's README.md card, raw from main,
  - the tool's runner verdict from this repository's results/<repo>/<tool>.json (the host assumes "passed"; the peer
    reads it),

and runs the workflow's deterministic checks as a replay does (core agentWorkflowRunOn with writes false): input_check
(a README card, front matter, every file the card refers to in the folder), runner_verdict (passed), licence_gate (a
licence that is not null, none, unknown or other). Host request, upload, receipt and fetch-back are skipped in a replay,
as they are in the service. The ported checks follow agent-workflow.ts (agentWorkflowFrontMatter,
agentWorkflowReferenced, agentWorkflowRunOn); fixtures/workflow-replay holds cases that fail when the two drift.

Result: REPRODUCED when every input's outcome matches the bundle's, DIFFERENT when one does not, UNABLE when the bundle
or an input could not be read.

  python3 scripts/workflow_replay.py <bundle raw URL> --repo <repo> [--json out.json]
  python3 scripts/workflow_replay.py --fixtures fixtures/workflow-replay
"""
import json
import os
import re
import sys
import urllib.request

ORG = os.environ.get("GITHUB_REPOSITORY_OWNER", "HivemindOS-Agents")
FRONT = re.compile(r"^---\r?\n([\s\S]*?)\r?\n---")
KV = re.compile(r"^([A-Za-z_][\w-]*):\s*(.*)$")
LINK = re.compile(r"\]\((?!https?:|#|mailto:)([^)\s]+)\)")
PATH = re.compile(r"""^\s*-?\s*path:\s*["']?([^"'\s]+)["']?\s*$""", re.M)
NO_LICENCE = re.compile(r"^(?:null|none|unknown|other)$", re.I)


def front_matter(card):
    m = FRONT.match(card or "")
    if not m:
        return None
    out = {}
    for line in re.split(r"\r?\n", m.group(1)):
        kv = KV.match(line)
        if kv:
            out[kv.group(1)] = kv.group(2).strip()
    return out


def referenced(card):
    text = card or ""
    links = [p[2:] if p.startswith("./") else p for p in LINK.findall(text)]
    paths = [p[2:] if p.startswith("./") else p for p in PATH.findall(text)]
    seen, out = set(), []
    for p in links + paths:
        if "*" in p or p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def run_on(inp):
    """One input through the replay's checks: ("answered", None) or ("handed_back", why). Mirrors agentWorkflowRunOn
    with writes false for the first workflow's node order: input_check, runner_verdict, licence_gate, then the write and
    fetch-back nodes, which a replay skips."""
    have = set(inp["files"])
    card = inp.get("card")
    fm = front_matter(card)
    if not card or "README.md" not in have:
        return "handed_back", "no README.md card in the folder"
    if fm is None:
        return "handed_back", "its card has no front matter"
    missing = [p for p in referenced(card) if p not in have]
    if missing:
        return "handed_back", "its card refers to files not in the folder: " + ", ".join(missing[:3])
    if inp.get("verdict") != "passed":
        return "handed_back", "its runner verdict is %s, not passed" % (inp.get("verdict") or "missing")
    licence = (fm.get("license") or "").replace('"', "").replace("'", "")
    if not licence or NO_LICENCE.match(licence):
        return "handed_back", "its card names no licence"
    return "answered", None


def compare(bundle, inputs):
    """REPRODUCED / DIFFERENT / UNABLE, and a short line on what differed."""
    expected = ((bundle or {}).get("replay") or {}).get("inputs") or []
    if not expected:
        return "UNABLE", "the bundle names no inputs"
    by_tool = {i["tool"]: i for i in inputs}
    differ = []
    for e in expected:
        inp = by_tool.get(e.get("tool"))
        if inp is None:
            return "UNABLE", "could not read %s" % e.get("tool")
        outcome, _ = run_on(inp)
        if outcome != e.get("outcome"):
            differ.append("%s: %s, the bundle says %s" % (e.get("tool"), outcome, e.get("outcome")))
    if differ:
        return "DIFFERENT", "; ".join(differ)[:200]
    return "REPRODUCED", "%d of %d inputs agree" % (len(expected), len(expected))


def get(url, accept="application/json"):
    req = urllib.request.Request(url, headers={"user-agent": "bee-self-test workflow-replay", "accept": accept})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def read_inputs(repo, bundle):
    tree = json.loads(get("https://api.github.com/repos/%s/%s/git/trees/main?recursive=1" % (ORG, repo)))
    paths = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob"]
    out = []
    for e in ((bundle.get("replay") or {}).get("inputs") or []):
        tool = e.get("tool") or ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", tool):
            continue
        prefix = "tools/%s/" % tool
        files = [p[len(prefix):] for p in paths if p.startswith(prefix)]
        try:
            card = get("https://raw.githubusercontent.com/%s/%s/main/tools/%s/README.md" % (ORG, repo, tool), "text/plain")
        except Exception:
            card = None
        verdict = None
        result = os.path.join("results", repo, tool + ".json")
        if os.path.exists(result):
            try:
                verdict = "passed" if json.load(open(result)).get("result") == "success" else "failed"
            except Exception:
                verdict = None
        out.append({"tool": tool, "files": files, "card": card, "verdict": verdict})
    return out


def fixtures(folder):
    n = 0
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        case = json.load(open(os.path.join(folder, name)))
        got, _ = compare(case["bundle"], case["inputs"])
        assert got == case["expect"], "%s: %s, expected %s" % (name, got, case["expect"])
        n += 1
    # The ported checks, one by one (each fails if agent-workflow.ts and this drift apart).
    card = "---\nlicense: mit\n---\n# x\n\nRows: [data.csv](data.csv)\n- path: ./extra/b.parquet\n"
    assert front_matter(card) == {"license": "mit"}; n += 1
    assert referenced(card) == ["data.csv", "extra/b.parquet"]; n += 1
    ok = {"files": ["README.md", "data.csv", "extra/b.parquet"], "card": card, "verdict": "passed"}
    assert run_on(ok) == ("answered", None); n += 1
    assert run_on({**ok, "files": ["README.md"]})[0] == "handed_back"; n += 1
    assert run_on({**ok, "verdict": "failed"})[1].startswith("its runner verdict is failed"); n += 1
    assert run_on({**ok, "card": card.replace("license: mit", "license: other")})[1] == "its card names no licence"; n += 1
    assert run_on({**ok, "card": "# no front matter\n"})[1] == "its card has no front matter"; n += 1
    print("workflow replay: %d cases pass" % n)


def main(argv):
    if argv[:1] == ["--fixtures"]:
        fixtures(argv[1])
        return 0
    url = argv[0]
    repo = argv[argv.index("--repo") + 1] if "--repo" in argv else ""
    out_path = argv[argv.index("--json") + 1] if "--json" in argv else None
    try:
        bundle = json.loads(get(url))
        result, observed = compare(bundle, read_inputs(repo, bundle))
    except Exception as e:
        result, observed = "UNABLE", "could not read: %s" % str(e)[:120]
    out = {"result": result, "observed": observed}
    if out_path:
        json.dump(out, open(out_path, "w"))
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
