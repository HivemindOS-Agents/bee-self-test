#!/usr/bin/env python3
"""Every SKILL.md's frontmatter is read as YAML, the way GitHub and an agent's skill loader read it (Based Elnen,
2026-11-12, living spec L46: 17 pinned-copy files across #547, #632, #86 and #1071 failed with "mapping values are not
allowed in this context"). A file passes when it opens with a --- block that parses to a mapping whose `name` and
`description` are non-empty strings.

  check_skill_files.py --fixtures DIR        the regression case: DIR/broken/SKILL.md must fail, DIR/quoted/SKILL.md pass
  check_skill_files.py ROOT [ROOT ...]       every ROOT/<repo>/skills/<slug>/SKILL.md; prints JSON, exits 1 on any bad file

Only reads and parses text (yaml.safe_load): nothing in a repository is run."""
import json, pathlib, re, sys
import yaml

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

def fixtures(folder: pathlib.Path) -> int:
    broken = problem((folder / "broken" / "SKILL.md").read_text(encoding="utf-8"))
    quoted = problem((folder / "quoted" / "SKILL.md").read_text(encoding="utf-8"))
    print(f"broken fixture: {broken or 'PASSED (wrong)'}")
    print(f"quoted fixture: {quoted or 'passed'}")
    return 0 if broken and not quoted else 1

def scan(roots: list[pathlib.Path]) -> int:
    files, bad = 0, []
    for root in roots:
        for path in sorted(root.glob("*/skills/*/SKILL.md")):
            files += 1
            said = problem(path.read_text(encoding="utf-8", errors="replace"))
            if said:
                bad.append({"repo": path.parts[-4], "skill": path.parts[-2], "problem": said})
    print(json.dumps({"files": files, "bad": bad}, indent=2))
    return 1 if bad else 0

if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixtures"]:
        sys.exit(fixtures(pathlib.Path(sys.argv[2])))
    sys.exit(scan([pathlib.Path(arg) for arg in sys.argv[1:]]))
