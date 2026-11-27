#!/usr/bin/env python3
"""Every SKILL.md's frontmatter is read as YAML, the way GitHub and an agent's skill loader read it (Based Elnen,
2026-11-12, living spec L46: 17 pinned-copy files across #547, #632, #86 and #1071 failed with "mapping values are not
allowed in this context"). A file passes when it opens with a --- block that parses to a mapping whose `name` and
`description` are non-empty strings.

  check_skill_files.py --fixtures DIR        the regression cases: DIR/broken/SKILL.md must fail, DIR/quoted/SKILL.md pass,
                                             DIR/no-skill-md (a skills/<slug>/ folder with no SKILL.md) must be bad, and
                                             a root holding nothing must stop
  check_skill_files.py ROOT [ROOT ...]       every ROOT/<repo>/skills/<slug>/SKILL.md; prints JSON, exits 1 on any bad file

Zero is not clean (HB-136, HB-138; scripts/security_input.py): a skills/<slug>/ folder with no SKILL.md is a bad file,
and a ROOT that is absent or holds no skill folder at all stops the run (STOP empty_security_setting, exit 2, nothing
on stdout), never "0 files, 0 bad". An agent repository with no skills/ folder is not one: it pins no skill.

R24 (dev update 2026-11-27 rows 131 and 132, guard 295, the TrojanPony fake-skill malware): a skill folder that ships a
native binary (.exe, .dll, .so, .dylib) is a bad file, and so is a SKILL.md that names no source pinned to a 40-hex
commit. A SKILL.md with no SHA-256 of its source is listed under "unhashed" and does not fail the run until
R24_SHA_ENFORCED_FROM (the host backfills the older notes first; then the check enforces). A star count or a marketplace
PASS in a file is never read as trust. That the bytes still match the recorded hash is the host's check, at every load
(the agents service's skill-learning.ts reads a skill only when its bytes are the pinned ones).

Only reads and parses text (yaml.safe_load): nothing in a repository is run."""
import json, os, pathlib, re, sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_input as si  # noqa: E402

FRONT = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.S)
BINARY_EXT = (".exe", ".dll", ".so", ".dylib")
# A source pinned to a commit: a GitHub blob, tree or raw link at a 40-hex commit, or a "Commit: <40-hex>" line.
PINNED = re.compile(r"(?:github\.com/[^/\s]+/[^/\s]+/(?:blob|tree)/|raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/|Commit:\s*)([0-9a-f]{40})\b")
HASHED = re.compile(r"SHA-256[^0-9a-f\n]{0,40}([0-9a-f]{64})\b", re.I)
R24_SHA_ENFORCED_FROM = "2026-11-30"

def r24_problem(folder: pathlib.Path, text: str) -> str | None:
    """A binary in the folder, or no pinned source. None when the folder passes R24's enforced half."""
    binaries = sorted(str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in BINARY_EXT)
    if binaries:
        return "R24: ships a native binary (" + ", ".join(binaries[:3]) + ")"
    if not PINNED.search(text):
        return "R24: names no source pinned to a 40-hex commit"
    return None

def r24_unhashed(text: str) -> bool:
    return not HASHED.search(text)

def sha_enforced(today: str | None = None) -> bool:
    import datetime
    return (today or datetime.date.today().isoformat()) >= R24_SHA_ENFORCED_FROM

def problem(text: str) -> str | None:
    match = FRONT.match(text)
    if not match:
        return "no --- frontmatter block at the top"
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError as error:
        return " ".join(str(error).split())[:200]
    if not isinstance(data, dict):
        return "frontmatter is not a mapping"
    for key in ("name", "description"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            return f"{key} is missing or not a string"
    return None

UNHASHED: list = []

def collect(roots: list[pathlib.Path]) -> tuple[int, list]:
    """(files read, bad files). Raises si.Stop for a root that is absent or holds no skill folder. Skills with no
    SHA-256 of their source go to UNHASHED (R24, report-only until R24_SHA_ENFORCED_FROM)."""
    files, bad = 0, []
    UNHASHED.clear()
    for root in roots:
        if not root.is_dir():
            raise si.Stop(si.EMPTY, root, "the scan root is absent")
        folders = sorted(p for p in root.glob("*/skills/*") if p.is_dir())
        if not folders:
            raise si.Stop(si.EMPTY, root, "the scan root holds no skills/<slug>/ folder: 0 files to read")
        for folder in folders:
            path = folder / "SKILL.md"
            if not path.is_file():
                bad.append({"repo": folder.parts[-3], "skill": folder.parts[-1], "problem": "no SKILL.md in its folder"})
                continue
            files += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            said = problem(text) or r24_problem(folder, text)
            if said:
                bad.append({"repo": path.parts[-4], "skill": path.parts[-2], "problem": said})
            elif r24_unhashed(text):
                UNHASHED.append({"repo": path.parts[-4], "skill": path.parts[-2]})
    return files, bad

def fixtures(folder: pathlib.Path) -> int:
    broken = problem(si.read_text(folder / "broken" / "SKILL.md"))
    quoted = problem(si.read_text(folder / "quoted" / "SKILL.md"))
    print(f"broken fixture: {broken or 'PASSED (wrong)'}")
    print(f"quoted fixture: {quoted or 'passed'}")
    files, orphan = collect([folder / "no-skill-md"])
    print(f"no-skill-md fixture: {orphan[0]['problem'] if orphan else 'PASSED (wrong)'}")
    try:
        collect([folder / "no-skill-md" / "hivepunk-0" / "skills"])
        empty = None
    except si.Stop as stop:
        empty = stop.reason
    print(f"a root with nothing to read: {empty or 'PASSED (wrong)'}")
    binary = r24_problem(folder / "binary", si.read_text(folder / "binary" / "SKILL.md"))
    print(f"binary fixture: {binary or 'PASSED (wrong)'}")
    unpinned = r24_problem(folder / "unpinned", si.read_text(folder / "unpinned" / "SKILL.md"))
    print(f"unpinned fixture: {unpinned or 'PASSED (wrong)'}")
    pinned = si.read_text(folder / "quoted" / "SKILL.md")
    ok_pin = r24_problem(folder / "quoted", pinned)
    print(f"pinned and hashed fixture: {ok_pin or ('passed' if not r24_unhashed(pinned) else 'UNHASHED (wrong)')}")
    starred = r24_problem(folder / "starred", si.read_text(folder / "starred" / "SKILL.md"))
    print(f"a PASS and stars are not a pin: {starred or 'PASSED (wrong)'}")
    dates = (not sha_enforced("2026-11-29"), sha_enforced(R24_SHA_ENFORCED_FROM))
    print(f"SHA-256 report-only before {R24_SHA_ENFORCED_FROM}, enforced from it: {'yes' if all(dates) else 'NO (wrong)'}")
    return 0 if broken and not quoted and len(orphan) == 1 and empty == si.EMPTY and binary and unpinned and not ok_pin and not r24_unhashed(pinned) and starred and all(dates) else 1

def scan(roots: list[pathlib.Path]) -> int:
    files, bad = collect(roots)
    enforced = sha_enforced()
    if enforced:
        bad = bad + [{**u, "problem": "R24: no SHA-256 of its source recorded"} for u in UNHASHED]
    print(json.dumps({"files": files, "bad": bad, "unhashed": UNHASHED, "sha256_enforced": enforced, "sha256_enforced_from": R24_SHA_ENFORCED_FROM}, indent=2))
    return 1 if bad else 0

if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--fixtures"]:
            sys.exit(fixtures(pathlib.Path(sys.argv[2])))
        if not sys.argv[1:]:
            raise si.Stop(si.EMPTY, "ROOT", "no scan root named")
        sys.exit(scan([pathlib.Path(arg) for arg in sys.argv[1:]]))
    except si.Stop as stop:
        print(stop.line(), file=sys.stderr)
        sys.exit(si.EXIT_STOP)
