#!/usr/bin/env python3
"""HB-063's rule map check: rule_map.json says which of an agent's rules HivemindOS enforces in code (coded), in part
(partly) or not at all (prose). This holds the published map to the published rules.

Keyless and read-only. Exit 0 only when the map is valid and matches AUTONOMY.md.

    python3 scripts/rule_map_check.py                       # the template's map and AUTONOMY.md in bee-scouts, live
    python3 scripts/rule_map_check.py MAP.json AUTONOMY.md  # two local files
    python3 scripts/rule_map_check.py --agents 547 632      # also: each agent's own copy equals the template's
    python3 scripts/rule_map_check.py --self-test           # the fixtures only

What is checked:
  1. Every entry has an id, the rule's text and a status of coded, partly or prose; ids are unique.
  2. A coded or partly entry names a check and says what it does; a prose entry names no check.
  3. AUTONOMY.md's numbered rules are R1..Rn in the map, each with the same text, none missing and none extra: a rule
     added to AUTONOMY.md with no entry fails here.
  4. Every line of AUTONOMY.md's "Checked before every call" list is a coded `preflight:<id>` entry with the same words,
     and every `preflight:<id>` entry in the map is a line of that list (HB-137): a line taken out of AUTONOMY.md, such
     as its deny line, fails here.
  5. The map's `counts` are its entries counted.

The map and AUTONOMY.md are security settings (HB-136, scripts/security_input.py): an empty one, one that does not parse
or has the wrong shape, AUTONOMY.md with no numbered rules, and a "Checked before every call" section that is missing
or lists nothing each STOP with empty_security_setting or unparseable_security_setting, exit 2, never a traceback.
Neither has a default.
"""
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_input as si  # noqa: E402

RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/{repo}/main/{path}"
STATUSES = ("coded", "partly", "prose")


def autonomy_rules(markdown):
    """The numbered rules under "## Rules", in order, and the "Checked before every call" list as {id: words}."""
    rules, checks, section = [], {}, None
    for line in markdown.splitlines():
        head = re.match(r"^##\s+(.*)$", line)
        if head:
            section = head.group(1).strip().lower()
            continue
        if section == "rules":
            m = re.match(r"^(\d+)\.\s+(.*)$", line)
            if m:
                rules.append((int(m.group(1)), m.group(2).strip()))
        elif section == "checked before every call":
            m = re.match(r"^-\s+([a-z0-9-]+):\s+(.*)$", line)
            if m:
                checks[m.group(1)] = m.group(2).strip()
    return rules, checks


def checked_section(markdown):
    """The "Checked before every call" section's lines, or None when AUTONOMY.md has no such section."""
    lines, section = None, None
    for line in markdown.splitlines():
        head = re.match(r"^##\s+(.*)$", line)
        if head:
            section = head.group(1).strip().lower()
            if section == "checked before every call" and lines is None:
                lines = []
            continue
        if section == "checked before every call":
            lines.append(line)
    return lines


def validate(rule_map, markdown, map_source="rule_map.json", md_source="AUTONOMY.md"):
    """HB-136: what makes the map or AUTONOMY.md unreadable as a security setting. Raises si.Stop."""
    if not isinstance(rule_map, dict):
        raise si.Stop(si.UNPARSEABLE, map_source, f"not an object but {type(rule_map).__name__}")
    entries = si.field(map_source, rule_map, "rules", list)
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise si.Stop(si.UNPARSEABLE, map_source, f"rules[{i}] is not an object but {type(entry).__name__}")
    si.check_text(md_source, markdown)
    rules, checks = autonomy_rules(markdown)
    if not rules:
        raise si.Stop(si.UNPARSEABLE, md_source, "no numbered rule under a \"## Rules\" heading")
    if checked_section(markdown) is None:
        raise si.Stop(si.EMPTY, md_source, "no \"Checked before every call\" section")
    if not checks:
        raise si.Stop(si.EMPTY, md_source, "its \"Checked before every call\" section lists nothing")


def problems(rule_map, markdown):
    out, seen = [], {}
    entries = rule_map.get("rules") if isinstance(rule_map, dict) else None
    if not isinstance(entries, list) or not entries:
        return ["the map has no rules"]
    for r in entries:
        rid = r.get("id")
        if not rid:
            out.append("an entry has no id")
            continue
        if rid in seen:
            out.append(f"{rid}: duplicate id")
        seen[rid] = r
        status = r.get("status")
        if status not in STATUSES:
            out.append(f"{rid}: bad status {status!r}")
        if not (r.get("text") or "").strip():
            out.append(f"{rid}: no text")
        if status in ("coded", "partly") and not r.get("check"):
            out.append(f"{rid}: a coded or partly rule names no check")
        if status in ("coded", "partly") and len(r.get("evidence") or "") < 20:
            out.append(f"{rid}: a coded or partly rule does not say what its check does")
        if status == "prose" and r.get("check"):
            out.append(f"{rid}: a prose rule names a check")
    rules, checks = autonomy_rules(markdown)
    if not rules:
        out.append("AUTONOMY.md has no numbered rules")
    for n, text in rules:
        entry = seen.get(f"R{n}")
        if entry is None:
            out.append(f"R{n}: in AUTONOMY.md and not in the map")
        elif (entry.get("text") or "").strip() != text:
            out.append(f"R{n}: its text is not AUTONOMY.md's")
    known = {n for n, _ in rules}
    for rid in seen:
        m = re.match(r"^R(\d+)$", rid)
        if m and int(m.group(1)) not in known:
            out.append(f"{rid}: in the map and not in AUTONOMY.md")
    for cid, words in checks.items():
        entry = seen.get(f"preflight:{cid}")
        if entry is None:
            out.append(f"preflight:{cid}: checked before every call and not in the map")
        elif entry.get("status") != "coded" or (entry.get("text") or "").strip() != words:
            out.append(f"preflight:{cid}: not coded, or its words are not AUTONOMY.md's")
    for rid in seen:
        if rid.startswith("preflight:") and rid.split(":", 1)[1] not in checks:
            out.append(f"{rid}: in the map and not in AUTONOMY.md's \"Checked before every call\"")
    counted = {s: sum(1 for r in entries if r.get("status") == s) for s in STATUSES}
    if rule_map.get("counts") != counted:
        out.append(f"counts say {rule_map.get('counts')} and the entries count {counted}")
    return out


def fetch(repo, path):
    with urllib.request.urlopen(urllib.request.Request(RAW.format(repo=repo, path=path), headers={"user-agent": "bee-self-test-rule-map"}), timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def fetched(source, repo, path):
    """A live file; one that could not be fetched is absent, and has no default."""
    try:
        return fetch(repo, path)
    except Exception as error:  # noqa: BLE001 - any failure to fetch is the same STOP
        raise si.Stop(si.EMPTY, source, f"absent: could not be fetched ({error})")


def summary(rule_map):
    rules = [r for r in rule_map.get("rules", []) if re.match(r"^R\d+$", r.get("id", ""))]
    by = {s: [int(r["id"][1:]) for r in rules if r.get("status") == s] for s in STATUSES}
    return {"entries": len(rule_map.get("rules", [])), "autonomyRules": len(rules), **{s: sorted(by[s]) for s in STATUSES}, "checked": rule_map.get("checked")}


def main(argv):
    if "--self-test" in argv:
        return self_test()
    agents = []
    if "--agents" in argv:
        at = argv.index("--agents")
        agents = [a for a in argv[at + 1:] if a.isdigit()]
        argv = argv[:at]
    try:
        if len(argv) >= 2:
            map_source, md_source = argv[0], argv[1]
            map_text, markdown = si.read_text(argv[0]), si.read_text(argv[1])
        else:
            map_source, md_source = "bee-scouts templates/rule_map.json", "bee-scouts templates/AUTONOMY.md"
            map_text, markdown = fetched(map_source, "bee-scouts", "templates/rule_map.json"), fetched(md_source, "bee-scouts", "templates/AUTONOMY.md")
        rule_map = si.parse_json(map_source, map_text, want=None)
        validate(rule_map, markdown, map_source, md_source)
    except si.Stop as stop:
        print(stop.line())
        print("HB-063 rule map: STOP")
        return si.EXIT_STOP
    found = problems(rule_map, markdown)
    for n in agents:
        try:
            if fetch(f"hivepunk-{n}", "rule_map.json") != map_text:
                found.append(f"hivepunk-{n}: its rule_map.json is not the template's")
        except Exception as error:
            found.append(f"hivepunk-{n}: its rule_map.json could not be read: {error}")
    print(json.dumps(summary(rule_map)))
    for p in found:
        print("PROBLEM", p)
    print("HB-063 rule map:", "PASS" if not found else f"FAIL: {len(found)} problem(s)")
    return 0 if not found else 1


def self_test():
    md = "# X's autonomy\n\n## Rules\n\nAlways.\n\n1. Only a clean public artifact counts.\n2. Finish before new.\n3. Every action carries a why.\n\n## Upgrades\n\n- 1. not a rule\n\n## Checked before every call\n\nIn code.\n\n- deny: A call on the never list is stopped.\n- repo-scope: Its own writes go only to tools/<tool>/.\n"
    assert autonomy_rules(md) == ([(1, "Only a clean public artifact counts."), (2, "Finish before new."), (3, "Every action carries a why.")],
                                  {"deny": "A call on the never list is stopped.", "repo-scope": "Its own writes go only to tools/<tool>/."})

    def good():
        rules = [
            {"id": "R1", "text": "Only a clean public artifact counts.", "status": "coded", "check": "beeFrozenState", "evidence": "A target counts only when its page answers with every file."},
            {"id": "R2", "text": "Finish before new.", "status": "partly", "check": "the finish gate", "evidence": "A plan for other work is refused while a repair is open."},
            {"id": "R3", "text": "Every action carries a why.", "status": "prose", "evidence": "A step with no why is not refused."},
            {"id": "preflight:deny", "text": "A call on the never list is stopped.", "status": "coded", "check": "agentPreflight", "evidence": "Checked in code before the call goes out."},
            {"id": "preflight:repo-scope", "text": "Its own writes go only to tools/<tool>/.", "status": "coded", "check": "agentPreflight", "evidence": "Checked in code before the call goes out."},
            {"id": "guard:sibling-folder", "text": "A new version is a commit to its own folder.", "status": "coded", "check": "agentOppSiblingOf", "evidence": "Refused before anything is written."},
        ]
        return {"v": 1, "checked": "2026-11-21", "counts": {"coded": 4, "partly": 1, "prose": 1}, "rules": rules}

    def broken(change, markdown=md):
        m = good()
        change(m)
        return problems(m, markdown)

    cases = [
        ("valid", lambda m: None, []),
        ("duplicate", lambda m: m["rules"].append(dict(m["rules"][0])), ["R1: duplicate id", "counts say {'coded': 4, 'partly': 1, 'prose': 1} and the entries count {'coded': 5, 'partly': 1, 'prose': 1}"]),
        ("coded with no check", lambda m: m["rules"][0].pop("check"), ["R1: a coded or partly rule names no check"]),
        ("coded with no evidence", lambda m: m["rules"][0].update(evidence="yes"), ["R1: a coded or partly rule does not say what its check does"]),
        ("prose with a check", lambda m: m["rules"][2].update(check="something"), ["R3: a prose rule names a check"]),
        ("bad status", lambda m: m["rules"][1].update(status="enforced"), ["R2: bad status 'enforced'", "counts say {'coded': 4, 'partly': 1, 'prose': 1} and the entries count {'coded': 4, 'partly': 0, 'prose': 1}"]),
        ("a rule's text changed", lambda m: m["rules"][1].update(text="Finish first."), ["R2: its text is not AUTONOMY.md's"]),
        ("a preflight check not coded", lambda m: m["rules"][3].update(status="partly"), ["preflight:deny: not coded, or its words are not AUTONOMY.md's", "counts say {'coded': 4, 'partly': 1, 'prose': 1} and the entries count {'coded': 3, 'partly': 2, 'prose': 1}"]),
    ]
    for name, change, want in cases:
        assert broken(change) == want, (name, broken(change))
    # A rule added to AUTONOMY.md with no entry, and an entry for a rule AUTONOMY.md no longer has.
    assert broken(lambda m: None, md.replace("3. Every action carries a why.\n", "3. Every action carries a why.\n4. A new rule.\n")) == ["R4: in AUTONOMY.md and not in the map"]
    assert broken(lambda m: None, md.replace("3. Every action carries a why.\n", "")) == ["R3: in the map and not in AUTONOMY.md"]
    assert broken(lambda m: None, md + "- text-unsafe: A post holding a secret is not sent.\n") == ["preflight:text-unsafe: checked before every call and not in the map"]
    assert problems({"rules": []}, md) == ["the map has no rules"]
    # HB-137: the other direction. A checked line taken out of AUTONOMY.md while the map keeps its entry.
    assert broken(lambda m: None, md.replace("- deny: A call on the never list is stopped.\n", "")) == ['preflight:deny: in the map and not in AUTONOMY.md\'s "Checked before every call"']
    # HB-136: what stops instead of reading as a pass or a traceback.
    stops = []
    for name, m, text in [("a list", [1], md), ("an entry not an object", {"rules": [1]}, md), ("no rules key", {"v": 1}, md),
                          ("empty AUTONOMY.md", good(), " ,\n"), ("no numbered rule", good(), "# x\n"),
                          ("no checked section", good(), md.split("## Checked")[0]), ("an empty checked section", good(), md.split("- deny")[0])]:
        try:
            validate(m, text)
            stops.append(f"{name}: no STOP")
        except si.Stop as stop:
            stops.append(stop.reason)
    assert stops == [si.UNPARSEABLE, si.UNPARSEABLE, si.EMPTY, si.EMPTY, si.UNPARSEABLE, si.EMPTY, si.EMPTY], stops
    validate(good(), md)
    assert summary(good()) == {"entries": 6, "autonomyRules": 3, "coded": [1], "partly": [2], "prose": [3], "checked": "2026-11-21"}
    print(f"self-test: {len(cases) + 9}/{len(cases) + 9} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
