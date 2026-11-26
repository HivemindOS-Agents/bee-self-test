#!/usr/bin/env python3
"""B-13r (merges HB-077): a rescore is written back into the bundle it re-ran, keyed on the bundle id, never on the tool.

rescore.yml records each peer's re-run as rescores/<repo>/<bundle id>.json. HivemindOS then writes it back into the
builder's repository: proofs/<bundle id>.json gains `repro` (the result) and `peer` ({agent, at, result, run}, the
record's own values). A tool is rescored once a bundle, and one tool has many bundles (1071's agent-dispatch has 9 in
rescores/ today), so two rescores of the same tool can land in one write-back pass. Keyed on the tool, the second
would overwrite the first and one bundle would stay without its peer for ever. That case is the fixture here: two
rescores of 547's fixprotocol-modifyliquidities-nonreentrant (bundles 73c79e7 and ea8496c, both REPRODUCED by 86 on
22 Nov 2026), written back in one pass. Keyed on the bundle id both land; keyed on the tool one does not, and the
check fails.

    python3 scripts/rescore_writeback.py --self-test                   # the fixtures only, no network
    python3 scripts/rescore_writeback.py RESCORES_DIR CLONE...         # CLONE: a clone of hivepunk-<n> with proofs/

Live, every rescore record older than the grace (2 hours: the write-back runs after the record, about an hour behind
it on 18 Nov, HB-016) must be in its bundle: `peer.run` is the record's run, `peer.agent` its peer and `repro` and
`peer.result` its result. A rescore whose bundle is not in the clone is listed (a bundle is never deleted, so it is
a problem too). Only rescores of the repositories given are read.

Exit 0: every rescore is written back. 1: one is not. 2: a record or a bundle could not be read, or nothing was given.
"""
import datetime
import glob
import json
import os
import sys

GRACE = datetime.timedelta(hours=2)
HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "fixtures", "rescore-writeback")
UTC = datetime.timezone.utc


def when(text):
    return datetime.datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def write_back(bundles, records):
    """The contract, as a reference: each record lands in the bundle its own `bundle` names. Returns new bundles."""
    out = {k: dict(v) for k, v in bundles.items()}
    for r in records:
        b = out.get(r["bundle"])
        if b is None:
            continue
        b["repro"] = r["result"]
        b["peer"] = {"agent": r["peer"], "at": r["at"], "result": r["result"], "run": r["run"]}
    return out


def problems(records, bundles, now=None, grace=GRACE):
    """What is not written back. records: rescore records; bundles: {bundle id: bundle}."""
    out = []
    for r in sorted(records, key=lambda r: r["bundle"]):
        if now is not None and when(r["at"]) > now - grace:
            continue
        b = bundles.get(r["bundle"])
        if b is None:
            out.append(f"{r['repo']} {r['bundle']}: its bundle is not in the repository")
            continue
        peer = b.get("peer") if isinstance(b.get("peer"), dict) else {}
        if peer.get("run") != r["run"]:
            said = f"names run {peer.get('run')}" if peer else "has no peer"
            out.append(f"{r['repo']} {r['bundle']}: rescored by #{r['peer']} at {r['at']} ({r['result']}), and its bundle {said}")
        elif str(peer.get("agent")) != str(r["peer"]) or peer.get("result") != r["result"] or b.get("repro") != r["result"]:
            out.append(f"{r['repo']} {r['bundle']}: its bundle's peer or repro differs from the rescore record")
    return out


def read_json(path):
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: {error}")
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a JSON object")
    return doc


def read_records(folder, repos):
    out = []
    for repo in repos:
        for path in sorted(glob.glob(os.path.join(folder, repo, "*.json"))):
            r = read_json(path)
            if not all(isinstance(r.get(k), str) and r[k] for k in ("repo", "bundle", "result", "run", "at", "peer")):
                raise ValueError(f"{path}: a rescore record with no repo, bundle, result, run, at or peer")
            out.append(r)
    return out


def read_bundles(clone):
    folder = os.path.join(clone, "proofs")
    if not os.path.isdir(folder):
        raise ValueError(f"{clone}: no proofs/ folder")
    return {os.path.basename(p)[:-5]: read_json(p) for p in sorted(glob.glob(os.path.join(folder, "*.json")))}


def self_test():
    bad = []
    records = read_records(os.path.join(FIXTURES, "rescores"), ["hivepunk-547"])
    if len(records) != 2 or len({r["bundle"].rsplit("-", 1)[0] for r in records}) != 1:
        bad.append("the fixture is two rescores of one tool")
    good = read_bundles(os.path.join(FIXTURES, "bundle-keyed", "hivepunk-547"))
    tool = read_bundles(os.path.join(FIXTURES, "tool-keyed", "hivepunk-547"))
    if problems(records, good):
        bad.append(f"keyed on the bundle id, both are written back: {problems(records, good)}")
    found = problems(records, tool)
    if len(found) != 1 or "73c79e7" not in found[0]:
        bad.append(f"keyed on the tool, the first of the pass is lost and must be named: {found}")
    # The reference write-back on a pass that starts with neither written back.
    pending = {k: {kk: vv for kk, vv in v.items() if kk not in ("peer", "repro")} for k, v in good.items()}
    if problems(records, write_back(pending, records)):
        bad.append("the reference write-back lands both records of one pass")
    by_tool = {}
    for r in records:
        by_tool[r["bundle"].rsplit("-", 1)[0]] = r  # the regression: a map keyed on the tool keeps only the last
    newest = list(by_tool.values())[0]
    if len(problems(records, write_back(pending, [newest]))) != 1:
        bad.append("a write-back keyed on the tool fails the check")
    if problems(records, {}, now=when("2026-11-22T06:50:00Z")) != [f"hivepunk-547 {records[0]['bundle']}: its bundle is not in the repository"]:
        bad.append("inside the grace a rescore is not yet due; past it a missing bundle is named")
    total = 6
    for line in bad:
        print("FAIL:", line)
    print(f"rescore write-back self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if len(argv) < 2:
        print(__doc__)
        return 2
    folder, clones = argv[0], argv[1:]
    try:
        bundles, repos = {}, []
        for clone in clones:
            repos.append(os.path.basename(os.path.normpath(clone)))
            bundles.update(read_bundles(clone))
        records = read_records(folder, repos)
    except ValueError as error:
        print(f"STOP unparseable_security_setting: {error}", file=sys.stderr)
        return 2
    if not records:
        print(f"STOP empty_security_setting: {folder}: no rescore record for {', '.join(repos)}", file=sys.stderr)
        return 2
    found = problems(records, bundles, now=datetime.datetime.now(UTC))
    print(json.dumps({"rescores": len(records), "bundles": len(bundles), "notWrittenBack": found}, indent=2))
    print(f"rescore write-back: {len(found)} of {len(records)} rescores not in their bundle", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
