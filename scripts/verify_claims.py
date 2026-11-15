#!/usr/bin/env python3
"""Re-runs one HivemindOS agent claim from its proof bundle and says whether it still holds (Based Elnen's proof and
trust pack, 2026-11-14, item 2). A bundle (proofs/<id>.json in the agent's repository) pins a tool's self-test to the
commit the runner tested and the file's sha256 there, and says what the run came to: passed or failed, and the check
count when it printed "Results: N/M checks passed".

  verify_claims.py BUNDLE [--json OUT]        BUNDLE is a path or an https URL on github.com/githubusercontent.com
  verify_claims.py --fixtures DIR             the regression cases: DIR/<case>/bundle.json run against DIR/<case>/root,
                                              which must come out as the case's name says

It fetches only the tool's folder at the pinned commit, checks the self-test file is the pinned one, runs it as the
runner does (no token, a clean environment, four minutes), and prints one of:

  REPRODUCED  the run came to the same result and the same count        exit 0
  DIFFERENT   it ran, and came to something else                        exit 1
  UNABLE      it could not be run as claimed (no commit, another file,  exit 2
              no interpreter, a timeout): never a pass

The tool's code is run. Run this where that is safe, as the runner does: a job with no permissions and no secrets."""
import hashlib, json, os, pathlib, re, shutil, subprocess, sys, tempfile, urllib.request

COUNT = re.compile(r"^Results: (\d{1,6})/(\d{1,6}) checks passed\s*$")
REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
PATH = re.compile(r"^tools/([a-z0-9][a-z0-9-]{1,47})/(self_test\.(?:py|mjs|sh))$")
URL = re.compile(r"^https://(?:github\.com|raw\.githubusercontent\.com)/[^\s\"<>]{1,300}$")
RUNS = {"self_test.py": ["python3", "self_test.py"], "self_test.mjs": ["node", "self_test.mjs"], "self_test.sh": ["bash", "self_test.sh"]}
TIMEOUT = 240

class Unable(Exception):
    pass

def load(where: str) -> dict:
    if where.startswith("https://"):
        if not URL.match(where):
            raise Unable("a bundle is read only from github.com or raw.githubusercontent.com")
        try:
            with urllib.request.urlopen(urllib.request.Request(where, headers={"user-agent": "bee-self-test-verify-claims"}), timeout=20) as answer:
                text = answer.read(200_000).decode("utf-8")
        except Exception as error:
            raise Unable(f"the bundle could not be read ({type(error).__name__})")
    else:
        text = pathlib.Path(where).read_text(encoding="utf-8")
    try:
        bundle = json.loads(text)
    except ValueError:
        raise Unable("the bundle is not JSON")
    if not isinstance(bundle, dict) or bundle.get("kind") != "claim-proof":
        raise Unable("not a claim-proof bundle")
    return bundle

def pinned(bundle: dict) -> tuple[str, str, str, str, str]:
    scorer = bundle.get("scorer") or {}
    repo, path, commit, sha256 = scorer.get("repo"), scorer.get("path"), scorer.get("commit"), scorer.get("sha256")
    if not (isinstance(repo, str) and REPO.match(repo)):
        raise Unable("the bundle names no repository")
    match = PATH.match(path) if isinstance(path, str) else None
    if not match:
        raise Unable("the bundle's scorer is not a tool's self-test file")
    if not (isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit)):
        raise Unable("the bundle pins no commit")
    if not (isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256)):
        raise Unable("the bundle pins no file hash")
    return repo, path, commit, sha256, match.group(1)

def expected(bundle: dict) -> tuple[str, int | None, int | None]:
    want = bundle.get("expected") or {}
    result = want.get("result")
    if result not in ("passed", "failed"):
        raise Unable("the bundle claims no result")
    passed, total = want.get("checksPassed"), want.get("checksTotal")
    if (passed is None) != (total is None) or (passed is not None and not (isinstance(passed, int) and isinstance(total, int))):
        raise Unable("the bundle's count is incomplete")
    return result, passed, total

def fetch(repo: str, commit: str, tool: str, into: pathlib.Path) -> pathlib.Path:
    git = ["git", "-c", "advice.detachedHead=false", "-C", str(into)]
    steps = [
        ["git", "init", "--quiet", str(into)],
        git + ["remote", "add", "origin", f"https://github.com/{repo}.git"],
        git + ["sparse-checkout", "set", f"tools/{tool}"],
        git + ["fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", commit],
        git + ["checkout", "--quiet", "FETCH_HEAD"],
    ]
    for step in steps:
        try:
            done = subprocess.run(step, capture_output=True, text=True, timeout=120, env={"PATH": os.environ.get("PATH", ""), "HOME": str(into), "GIT_TERMINAL_PROMPT": "0"})
        except subprocess.TimeoutExpired:
            raise Unable("fetching the commit timed out")
        if done.returncode != 0:
            raise Unable(f"{repo} at {commit[:7]} could not be fetched")
    return into

def run(root: pathlib.Path, path: str, sha256: str) -> tuple[str, int | None, int | None]:
    file = root / path
    if not file.is_file():
        raise Unable("the pinned self-test file is not at that commit")
    if hashlib.sha256(file.read_bytes()).hexdigest() != sha256:
        raise Unable("the self-test file at that commit is not the one the bundle pins")
    command = RUNS[file.name]
    if not shutil.which(command[0]):
        raise Unable(f"{command[0]} is not installed here")
    home = tempfile.mkdtemp(prefix="verify-claims-home-")
    # A clean environment: nothing of the caller's (no token, no CI variables) reaches the tool.
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        done = subprocess.run(command, cwd=file.parent, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Unable(f"the self-test ran past {TIMEOUT} s")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    lines = done.stdout.decode("utf-8", "replace").replace("\r", "").splitlines()
    passed = total = None
    for line in reversed(lines):
        match = COUNT.match(line.strip())
        if match and 0 < int(match.group(2)) and int(match.group(1)) <= int(match.group(2)):
            passed, total = int(match.group(1)), int(match.group(2))
            break
    return ("passed" if done.returncode == 0 else "failed"), passed, total

def said(result: str, passed: int | None, total: int | None) -> str:
    return f"{result}, {passed}/{total}" if total is not None else f"{result}, no count line"

def verify(bundle: dict, root: pathlib.Path | None = None) -> dict:
    out = {"v": 1, "kind": "claim-rescore-run", "bundle": bundle.get("id"), "claim": (bundle.get("claim") or {}).get("text"), "result": "UNABLE", "observed": ""}
    try:
        repo, path, commit, sha256, tool = pinned(bundle)
        out["scorerCommit"] = commit
        want = expected(bundle)
        if root is None:
            with tempfile.TemporaryDirectory(prefix="verify-claims-") as work:
                got = run(fetch(repo, commit, tool, pathlib.Path(work) / "repo"), path, sha256)
        else:
            got = run(root, path, sha256)
        out["observed"] = said(*got)
        out["result"] = "REPRODUCED" if got == want else "DIFFERENT"
    except Unable as why:
        out["observed"] = str(why)
    return out

CODES = {"REPRODUCED": 0, "DIFFERENT": 1, "UNABLE": 2}

def fixtures(folder: pathlib.Path) -> int:
    bad = 0
    for case in sorted(p for p in folder.iterdir() if p.is_dir()):
        want = case.name.upper()
        got = verify(load(str(case / "bundle.json")), case / "root")
        ok = got["result"] == want
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {case.name}: {got['result']} ({got['observed']})")
    return 1 if bad else 0

def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--fixtures":
        return fixtures(pathlib.Path(argv[1]))
    if not argv or argv[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    write = argv[argv.index("--json") + 1] if "--json" in argv and argv.index("--json") + 1 < len(argv) else None
    try:
        bundle = load(argv[0])
    except Unable as why:
        bundle, out = {}, {"v": 1, "kind": "claim-rescore-run", "bundle": None, "claim": None, "result": "UNABLE", "observed": str(why)}
    else:
        out = verify(bundle)
    out["exit"] = CODES[out["result"]]
    print(f"bundle   {out['bundle']}\nclaim    {out['claim']}\nobserved {out['observed']}\nresult   {out['result']}")
    if write:
        pathlib.Path(write).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out["exit"]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
