#!/usr/bin/env python3
"""HB-060 and HB-059 checks (19 Nov 2026 dev update), keyless and read-only, report-only until HB-056's fixtures leave
their 7-day report-only window.

HB-060, on the five active agents' public OPPORTUNITIES.md:
  hall     the open Hall bounty is quoted as demand (under "- Asks:") on at most one agent; the others say "claimed by"
  staple   no item carries the Hall bounty as its ask unless the item is about the bounty or paid calls
  junk     no Candidate in its lane whose title is a report, phone spam, a bare domain or good-first-issue trivia
  sized    an in-lane Candidate with an outside ask is never a bare "Effort: not estimated": a count, or why not
  taken    an ask "taken from the registry" (an agent with none of its own to try takes one from another agent's list)
           quotes its ask or carries a valid `- Spotted:` record (25 Nov 2026 update, row 84, guard 241), is sized at 3
           work steps or fewer, is taken by one agent only, and is not also the Exploratory item of the agent it was
           taken from. A take is read while the taking item is Candidate, Picked, Building or Shipped (row 61, guard
           188: line 87 read Candidate takes only, so opp-1071-180's shipped take of opp-547-430 went unseen); an
           Expired take was given back and is not counted
  served   an item another agent took (Candidate, Picked, Building or Shipped) no longer reads pickable on its own
           agent's list (row 61: opp-547-430 is served by opp-1071-180)
  dupe     a pickable item (Candidate, Tier pickable or exploratory) whose ask URL or canonical key (its repository and
           normalised title, opportunity_records.py) matches a Shipped, Building, Picked or taken item on any agent
           (row 85, guard 242)
  junk     also read on an item's `- Labels:` line, when it has one (row 84: the rule reads labels as well as titles)

HB-059, on FROZEN.md (bee-scouts): every `Done when: <path> sha256 <hex>` pin still matches the agent's file at main, so
the host's opportunity linker wrote into no pinned file.

HB-059, the linker's skip itself (20 Nov 2026 update, Part 3), on each agent repository's history: the host's link
commits ("HivemindOS linked tools/<x>/ to opp-...") since the skip was released, 10:57:56 UTC 19 Nov 2026. None may
touch a file FROZEN.md pins or a file in the agent's frozen tool's folder. A link written before the release is listed
and not counted. The history is read from local clones, with no key (`git log`; a blobless clone is enough).

    python3 scripts/opportunities_hb060.py              # all checks, live
    python3 scripts/opportunities_hb060.py --linker CLONE_OF_hivepunk-547 CLONE_OF_hivepunk-632 ...
    python3 scripts/opportunities_hb060.py --self-test  # the fixtures only, no network

Exit 0 only when every check is clean.
"""
import hashlib
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import opportunity_records as rec  # noqa: E402

AGENTS = ["547", "632", "667", "1071", "86"]
RAW = "https://raw.githubusercontent.com/HivemindOS-Agents/hivepunk-{n}/main/{path}"
FROZEN = "https://raw.githubusercontent.com/HivemindOS-Agents/bee-scouts/main/FROZEN.md"
HALL = "https://api.hivemindos.app/v1/hall#bounty"
# When the host's linker began to keep out of frozen files (agents service d0f724c0, the 19 Nov return).
LINKER_SKIP_FROM = "2026-11-19T10:57:56Z"
LINK_SUBJECT = re.compile(r"^HivemindOS linked tools/([a-z0-9][a-z0-9-]*)/ to (opp-[\w-]+)")
# The host's own junk rule (hivemind-os core agent-opportunity.ts JUNK_TITLE), as titles read on the public files.
JUNK = re.compile(r"^(upload|delete|create|update|rename|add files?)\b|^[^a-z0-9]*report:|security alert|conversion to parquet|"
                  r"collaborator request|^\[bot\]|good[ -]first[ -]issue|hacktoberfest|kundservice|klantenservice|kundendienst|"
                  r"service client|customer (service|care|support)|helpline|☎|^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.I)
TAKEN = re.compile(r"Fit: taken from the registry \((opp-[\w-]+):")
HALL_NEED = re.compile(r"\b(hall|bount(y|ies)|paid[ -]calls?|payers?|x402)\b", re.I)
LABELS = re.compile(r"^- Labels?:\s*(.+)$", re.M | re.I)
# The statuses a take is read in (row 61): every one but a take given back (Expired) or never made.
TAKE_HELD = ("Candidate", "Picked", "Building", "Shipped")
# The statuses that hold an ask for row 85: a pickable item matching one of these anywhere is a duplicate.
HELD = ("Picked", "Building", "Shipped")
PICKABLE_TIERS = ("pickable", "exploratory")


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


def labels_of(block):
    m = LABELS.search(block)
    return [l.strip() for l in m.group(1).split(",") if l.strip()] if m else []


def check_agent(n, text):
    """Problems on one agent's file, whether it quotes the Hall bounty as demand, the items it took and holds
    ([(its id, the id taken)], Candidate to Shipped), and its Exploratory Candidates' ids."""
    problems, hall, takes, exploratory = [], False, [], []
    for oid, title, block in blocks(text):
        status = rec.status(block)
        candidate = status == "Candidate"
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
        elif candidate and in_lane and any(JUNK.search(label) for label in labels_of(block)):
            problems.append(f"junk: {oid} is listed in its lane (label: {', '.join(l for l in labels_of(block) if JUNK.search(l))[:60]})")
        quoted = re.search(r"^- Asks: \d+ quoted", block, re.M) is not None
        if candidate and in_lane and quoted and re.search(r"Effort: not estimated(?! \(| yet:)", block):
            problems.append(f"sized: {oid} says only 'Effort: not estimated'")
        if candidate and re.search(r"^- Tier: exploratory\b", block, re.M):
            exploratory.append(oid)
        took = TAKEN.search(block)
        if took and status in TAKE_HELD:
            takes.append((oid, took.group(1)))
            if not (quoted or rec.spotted(block)) or not re.search(r"Effort: [123] work steps", block):
                problems.append(f"taken: {oid} was taken from the registry without a quoted ask or spotted record sized at 3 steps or fewer")
    return problems, hall, takes, exploratory


def items_of(n, text):
    """Every item on one agent's file, as the cross-agent checks read it."""
    out = []
    for oid, title, block in blocks(text):
        took = TAKEN.search(block)
        out.append({"agent": n, "id": oid, "title": title, "status": rec.status(block), "tier": rec.tier(block),
                    "urls": set(rec.ask_urls(block)), "key": rec.canonical_key(title, block),
                    "took": took.group(1) if took else None})
    return out


def check_served(files, taken_by):
    """Rows 61 and 85 across every agent's file: (lines, failed). taken_by: {source id: [taking ids]}."""
    lines, failed = [], 0
    items = [it for n, text in files.items() for it in items_of(n, text)]
    by_id = {it["id"]: it for it in items}
    for p in items:
        if p["status"] != "Candidate" or p["tier"] not in PICKABLE_TIERS:
            continue
        served = [t for t in taken_by.get(p["id"], []) if t != p["id"]]
        for t in served:
            failed += 1
            lines.append(f"{p['agent']}: served: {p['id']} reads pickable but is served by {t} ({by_id[t]['status'] if t in by_id else 'taken'}, "
                         f"agent {by_id[t]['agent'] if t in by_id else '?'}); mark it served by {t}")
        for o in items:
            if o["id"] == p["id"] or o["id"] in served or p["took"] == o["id"]:
                continue
            taken = o["id"] in taken_by or (o["took"] is not None and o["status"] in TAKE_HELD)
            if o["status"] not in HELD and not taken:
                continue
            shared = sorted(p["urls"] & o["urls"])
            why = f"ask {shared[0]}" if shared else (f"key {o['key'][0]} \"{o['key'][1][:50]}\"" if p["key"] and p["key"] == o["key"] else None)
            if why:
                failed += 1
                lines.append(f"{p['agent']}: duplicate: {p['id']} reads pickable and matches {o['id']} "
                             f"({o['status']}{', taken' if taken and o['status'] not in HELD else ''}, agent {o['agent']}) on {why}")
    return lines, failed


def check_opportunities(files):
    """files: {agent: text}. (lines, failed)."""
    lines, failed, halls, taken_by, tried = [], 0, [], {}, set()
    for n, text in files.items():
        problems, hall, takes, exploratory = check_agent(n, text)
        if hall:
            halls.append(n)
        tried.update(exploratory)
        for oid, source in takes:
            taken_by.setdefault(source, []).append(oid)
        failed += len(problems)
        lines += [f"{n}: {p}" for p in problems] or [f"{n}: clean"]
    if len(halls) > 1:
        failed += 1
        lines.append(f"hall: the open Hall bounty is demand on {len(halls)} agents ({', '.join(halls)}); at most one")
    else:
        lines.append(f"hall: demand on {halls[0] if halls else 'no agent'}")
    for source, takers in sorted(taken_by.items()):
        if len(takers) > 1:
            failed += 1
            lines.append(f"taken: {source} is taken by {len(takers)} agents ({', '.join(takers)}); at most one")
        if source in tried:
            failed += 1
            lines.append(f"taken: {source} is taken by {takers[0]} and is still its own agent's exploratory item")
    lines.append(f"taken: {sum(len(t) for t in taken_by.values())} from the registry" + (f" ({', '.join(f'{t[0]} from {s}' for s, t in sorted(taken_by.items()))})" if taken_by else ""))
    served, fs = check_served(files, taken_by)
    lines += served or ["served: none (no pickable item is served by a take or matches a held or taken item on any agent)"]
    return lines, failed + fs


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


def frozen_folders(text):
    """{agent: its frozen tool's folder} from FROZEN.md's blocks (skipping the template)."""
    out, agent = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"## #(\d+)\s*$", line)
        if m:
            agent = m.group(1)
            continue
        if line.startswith("## "):
            agent = None
        t = re.match(r"- Tool: ([a-z0-9][a-z0-9-]*)\s*$", line)
        if agent and t:
            out[agent] = f"tools/{t.group(1)}/"
    return out


def link_commits(log):
    """The host's link commits in `git log --format='%x01%H%x09%cI%x09%s' --name-only` output: [(sha, time, subject, paths)]."""
    out = []
    for chunk in (log or "").split("\x01")[1:]:
        head, _, rest = chunk.partition("\n")
        parts = head.split("\t", 2)
        if len(parts) == 3 and LINK_SUBJECT.match(parts[2]):
            out.append((parts[0], parts[1], parts[2], [p for p in rest.splitlines() if p.strip()]))
    return out


def utc(stamp):
    """A commit time as UTC seconds text that sorts: 2026-11-19T10:57:56Z, whatever offset git printed."""
    import calendar, time
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(Z|[+-]\d\d:\d\d)$", stamp.strip())
    if not m:
        return ""
    at = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    if m.group(2) != "Z":
        sign = 1 if m.group(2)[0] == "+" else -1
        at -= sign * (int(m.group(2)[1:3]) * 3600 + int(m.group(2)[4:6]) * 60)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


def check_linker(frozen_text, logs, since=LINKER_SKIP_FROM):
    """logs: {agent: git log text}. (lines, failed): a link commit since the skip that touches a pinned file or a file in
    the agent's frozen folder is a fail; one before it is listed only."""
    lines, failed, counted = [], 0, 0
    pinned = {}
    for agent, path, _ in frozen_pins(frozen_text):
        pinned.setdefault(agent, set()).add(path)
    folders = frozen_folders(frozen_text)
    for agent in sorted(logs, key=lambda a: int(a) if a.isdigit() else 0):
        for sha, stamp, subject, paths in link_commits(logs[agent]):
            at = utc(stamp)
            inside = [p for p in paths if p in pinned.get(agent, ()) or (folders.get(agent) and p.startswith(folders[agent]))]
            if at >= since:
                counted += 1
                if inside:
                    failed += 1
                    lines.append(f"linker: #{agent} {sha[:7]} {at} wrote a link into {', '.join(inside)}")
            elif inside:
                lines.append(f"linker: #{agent} {sha[:7]} {at} wrote a link into {', '.join(inside)} before the skip (listed, not counted)")
    lines.append(f"linker: {counted} link commits since {since}, {failed} into a frozen folder or a pinned file")
    return lines, failed


def git_log(clone):
    try:
        return subprocess.run(["git", "-C", clone, "log", "--format=%x01%H%x09%cI%x09%s", "--name-only", "--grep=^HivemindOS linked tools/"],
                              capture_output=True, text=True, timeout=60, check=True).stdout
    except Exception:
        return None


def fetch(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"user-agent": "bee-self-test-opportunities-hb060"}), timeout=20) as r:
            return r.read()
    except Exception:
        return None


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--linker" in argv:
        logs = {}
        for clone in [a for a in argv if not a.startswith("--")]:
            m = re.search(r"hivepunk-(\d+)/?$", os.path.abspath(clone))
            log = git_log(clone) if m else None
            if log is None:
                print(f"linker: {clone} could not be read as a clone of hivepunk-<n>")
                return 1
            logs[m.group(1)] = log
        lines, failed = check_linker((fetch(FROZEN) or b"").decode("utf-8", "replace"), logs)
        for line in lines:
            print(line)
        print("HB-059 linker check:", "PASS" if not failed else f"FAIL ({failed} problems)")
        return 0 if not failed else 1
    files = {n: (fetch(RAW.format(n=n, path="OPPORTUNITIES.md")) or b"").decode("utf-8", "replace") for n in AGENTS}
    a, fa = check_opportunities(files)
    b, fb = check_frozen((fetch(FROZEN) or b"").decode("utf-8", "replace"), lambda agent, path: fetch(RAW.format(n=agent, path=path)))
    for line in a + b:
        print(line)
    print("HB-060/HB-059 check:", "PASS" if not (fa + fb) else f"FAIL ({fa + fb} problems)")
    return 0 if not (fa + fb) else 1


def item(oid, title, status="Candidate", lane=True, asks=None, effort="3 work steps", extra="", tier="watch (queue)", fit=None):
    ask_lines = "".join(f"  - \"{q}\" by someone, {u} (asked 2026-11-01)\n" for q, u in (asks or []))
    fit = fit or ('in its lane' if lane else 'outside its lane')
    return (f"## {oid} · {title}\n\nA need.\n\n- Status: {status} since 2026-11-19\n- Tier: {tier}\n"
            f"- Asks: {len(asks or [])} quoted\n{ask_lines}{extra}"
            f"- Fit: {fit} · Effort: {effort} · Paid path: none\n\n") if asks else \
           (f"## {oid} · {title}\n\nA need.\n\n- Status: {status} since 2026-11-19\n- Asks: none quoted yet\n{extra}"
            f"- Fit: {fit} · Effort: {effort} · Paid path: none\n\n")


def self_test():
    hall_ask = [("Open Hall bounty, 25000 credits", HALL)]
    real = [("Latest trading day is still 20261028", "https://huggingface.co/datasets/venvoo/x/discussions/9")]
    # A second, different ask on another repository: the source's own try below is not the ask it lent out (row 85
    # would read one ask URL on both as the same ask).
    other = [("The licence tag is missing", "https://huggingface.co/datasets/someone/y/discussions/2")]
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
    # The registry fill: 86 has no ask of its own and takes 547's second ask, which 547 keeps out of its own try.
    took = "taken from the registry (opp-547-14: it had no ask of its own to try)"
    source = head + item("opp-547-13", "licence tag", asks=other, effort="1 work steps", tier="exploratory") + \
        item("opp-547-14", "kinematics", asks=real, effort="1 work steps", extra="- Registry: taken by agent 86, which had no ask of its own to try\n")
    copy = lambda oid, **over: head + item(oid, "kinematics", **{"lane": False, "asks": real, "effort": "1 work steps", "tier": "exploratory", "fit": took, **over})
    ok(check_opportunities({"547": source, "86": copy("opp-86-36")})[1] == 0, "one take, the source keeps its own try")
    ok(any("still its own agent's exploratory" in line for line in check_opportunities({"547": source.replace("opp-547-13", "opp-547-99").replace("watch (queue)", "exploratory"), "86": copy("opp-86-36")})[0]), "taken and still tried by its source")
    ok(any("taken by 2 agents" in line for line in check_opportunities({"547": source, "86": copy("opp-86-36"), "667": copy("opp-667-30")})[0]), "one ask taken twice")
    ok(any(line.startswith("86: taken:") for line in check_opportunities({"547": source, "86": copy("opp-86-36", effort="5 work steps")})[0]), "a take over 3 steps")
    ok(check_opportunities({"547": source, "86": copy("opp-86-36", status="Expired")})[1] == 0, "a take given back is not counted")
    # HB-059: a pinned README unchanged passes; the same README with a link line written into it fails.
    readme = b"# agent-memory-lint-fixtures\n\nFixtures.\n"
    frozen = ("## #<n>\n\n- Done when: <path in its repository> sha256 <64 hex>\n\n## #547\n\n- Tool: agent-memory-lint-fixtures\n"
              f"- Done when: tools/agent-memory-lint-fixtures/README.md sha256 {hashlib.sha256(readme).hexdigest()}\n")
    ok(len(frozen_pins(frozen)) == 1, "the template block is skipped")
    ok(check_frozen(frozen, lambda a, p: readme)[1] == 0, "a pinned README unchanged")
    linked = readme.replace(b"\n\nFixtures", b"\n\nopportunity: opp-547-1\n\nFixtures")
    ok(check_frozen(frozen, lambda a, p: linked)[1] == 1, "a link line written into a pinned README is caught")
    ok(check_frozen(frozen, lambda a, p: None)[1] == 1, "an unreadable pinned file is a fail, said as such")
    # HB-059, the skip itself: the host's link commits since it was released, read from each repository's history.
    blocks_ = frozen + "- Done when: tools/other-tool/pinned.py sha256 " + "0" * 64 + "\n\n## #632\n\n- Tool: attribution-docs-check-fixtures\n"
    ok(frozen_folders(blocks_) == {"547": "tools/agent-memory-lint-fixtures/", "632": "tools/attribution-docs-check-fixtures/"}, "each agent's frozen folder, the template skipped")
    entry = lambda sha, stamp, subject, *paths: "\x01" + "\t".join([sha, stamp, subject]) + "\n\n" + "\n".join(paths) + "\n"
    link = lambda tool: f"HivemindOS linked tools/{tool}/ to opp-547-9"
    outside = entry("a" * 40, "2026-11-20T08:45:00Z", link("hf-publish-check"), "tools/hf-publish-check/README.md")
    ok(len(link_commits(outside + entry("b" * 40, "2026-11-20T09:00:00Z", "It updated its goal", "GOAL.md"))) == 1, "only the host's link commits are read")
    ok(check_linker(blocks_, {"547": outside}) == (["linker: 1 link commits since 2026-11-19T10:57:56Z, 0 into a frozen folder or a pinned file"], 0), "a link outside the frozen folder")
    in_folder = entry("c" * 40, "2026-11-20T10:00:00+00:00", link("agent-memory-lint-fixtures"), "tools/agent-memory-lint-fixtures/NOTES.md")
    ok(check_linker(blocks_, {"547": outside + in_folder})[1] == 1, "a link into a file in the frozen folder, pinned or not")
    pinned_elsewhere = entry("d" * 40, "2026-11-20T11:00:00Z", link("other-tool"), "tools/other-tool/pinned.py")
    ok(check_linker(blocks_, {"547": pinned_elsewhere})[1] == 1, "a link into a pinned file outside the frozen folder")
    early = entry("e" * 40, "2026-11-19T02:21:00+08:00", link("attribution-docs-check-fixtures"), "tools/attribution-docs-check-fixtures/README.md")
    before = check_linker(blocks_, {"632": early})
    ok(before[1] == 0 and "before the skip (listed, not counted)" in before[0][0] and "2026-11-18T18:21:00Z" in before[0][0], "a link before the skip is listed, not counted, in UTC")
    ok(check_linker(blocks_, {"632": early.replace("2026-11-19T02:21:00+08:00", "2026-11-19T10:57:56Z")})[1] == 1, "the release second itself counts")
    ok(check_linker(blocks_, {"86": in_folder})[1] == 0, "another agent's folder is not this agent's frozen folder")
    print(f"self-test: {n}/{n} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
