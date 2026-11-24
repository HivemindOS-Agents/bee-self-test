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

Only reads and parses text (yaml.safe_load): nothing in a repository is run."""
import json, os, pathlib, re, sys
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_input as si  # noqa: E402

FRONT = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.S)

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

def collect(roots: list[pathlib.Path]) -> tuple[int, list]:
    """(files read, bad files). Raises si.Stop for a root that is absent or holds no skill folder."""
    files, bad = 0, []
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
            said = problem(path.read_text(encoding="utf-8", errors="replace"))
            if said:
                bad.append({"repo": path.parts[-4], "skill": path.parts[-2], "problem": said})
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
    return 0 if broken and not quoted and len(orphan) == 1 and empty == si.EMPTY else 1

def scan(roots: list[pathlib.Path]) -> int:
    files, bad = collect(roots)
    print(json.dumps({"files": files, "bad": bad}, indent=2))
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
