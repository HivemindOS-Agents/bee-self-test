#!/usr/bin/env python3
"""HB-067 G (22 Nov 2026 update, section 5 G): a build step's work note headed **Done** needs a real change.

Rules 3 and 6 say a note may not claim a file that its commit does not hold. A work note (work/*.md in an agent's
repository) for a build step ("spent ... on Build a small tool in its own repository") is headed **Done** only when:

  done-without-tool-commit   a commit in that step changed something under tools/. An empty commit is no change, and
                             neither is the host's SELFTEST_OUTPUT.md nor a commit the host made ("HivemindOS ...")
  done-without-folder        every tools/<name> the note names is a folder at the note's commit

A step's commits are the ones after the agent's previous work note and at most STEP_MINUTES before this one.

Shadow mode, report-only: it changes nothing. Keyless and read-only; nothing in an agent repository is run.

    python3 scripts/done_paths.py --self-test                  # fixtures/done-paths/, replayed into a temp git repo
    python3 scripts/done_paths.py [--since 2026-11-14] DIR...  # clones of hivepunk-<n> with history

Exit 0 when every Done build note holds, 1 when one does not, 2 when a clone could not be read.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import git_history  # noqa: E402

SINCE = "2026-11-14"
STEP_MINUTES = 30
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "done-paths")
DONE = re.compile(r"^\*\*Done\*\*\s*$", re.M)
BUILD = re.compile(r"\bspent \S+ on Build a small tool\b")
NAMED = re.compile(r"(?<![A-Za-z0-9_./-])tools/([A-Za-z0-9_-][A-Za-z0-9._-]*)")
NOT_A_CHANGE = ("SELFTEST_OUTPUT.md",)


def is_done_build(text):
    return bool(DONE.search(text or "")) and bool(BUILD.search(text or ""))


def named_folders(text):
    return sorted({n.rstrip(".") for n in NAMED.findall(text or "") if "." not in n.rstrip(".")})


def tool_change(commit):
    """The paths under tools/ a commit really changed, the host's own writes left out."""
    if commit["subject"].startswith("HivemindOS "):
        return []
    return [p for _, p in commit["files"] if p.startswith("tools/") and os.path.basename(p) not in NOT_A_CHANGE]


def check(commits, texts, folders_at):
    """commits: oldest first, {h, at, subject, files}; texts: {"<h>:<path>": note text}; folders_at(h) -> the set of
    tools/ folder names at commit h. Returns (done build notes, problems)."""
    notes, problems, previous = 0, [], None
    window = datetime.timedelta(minutes=STEP_MINUTES)
    for i, c in enumerate(commits):
        added = [p for st, p in c["files"] if st == "A" and p.startswith("work/") and p.endswith(".md")]
        for path in added:
            text = texts.get(f"{c['h']}:{path}")
            if text is not None and is_done_build(text):
                notes += 1
                step = [d for d in commits[:i + 1] if (previous is None or d["at"] > previous) and c["at"] - d["at"] <= window]
                title = text.splitlines()[0].lstrip("# ").strip()[:100] if text else ""
                where = {"note": path, "at": c["at"].strftime("%Y-%m-%dT%H:%M:%SZ"), "commit": c["h"][:12], "title": title}
                if not any(tool_change(d) for d in step):
                    problems.append({**where, "kind": "done-without-tool-commit"})
                have = folders_at(c["h"])
                for name in named_folders(text):
                    if name not in have:
                        problems.append({**where, "kind": "done-without-folder", "folder": f"tools/{name}"})
        if added:
            previous = c["at"]
    return notes, problems


def check_repo(repo, since=SINCE):
    git_history.prefetch(repo, since, ["work/"])
    commits = git_history.commits(repo, since)
    specs = [f"{c['h']}:{p}" for c in commits for st, p in c["files"] if st == "A" and p.startswith("work/") and p.endswith(".md")]
    texts = git_history.show_many(repo, specs)
    cache = {}

    def folders_at(h):
        if h not in cache:
            out = git_history.git(repo, "ls-tree", "-d", "--name-only", h, "tools/", check=False)
            cache[h] = {line.split("/", 1)[1] for line in out.splitlines() if "/" in line}
        return cache[h]
    return check(commits, {k: v for k, v in texts.items() if v is not None}, folders_at)


def summary(problems):
    out = {"done-without-tool-commit": 0, "done-without-folder": 0}
    for p in problems:
        out[p["kind"]] += 1
    out["notes"] = len({p["note"] for p in problems})
    return out


# ---------------------------------------------------------------------------------------------------------------- fixtures
def replay(history, into):
    """Write fixtures/done-paths/history.json into a new git repository: each step's files, then its commit (an
    empty one when it lists none), at its own time."""
    run = lambda *args, env=None: subprocess.run(["git", "-C", into, *args], check=True, capture_output=True, env={**os.environ, **(env or {})})
    run("init", "--quiet")
    for step in history:
        for path, text in step.get("write", {}).items():
            os.makedirs(os.path.dirname(os.path.join(into, path)), exist_ok=True)
            note = text if not text.startswith("@") else open(os.path.join(FIXTURES, text[1:]), encoding="utf-8").read()
            open(os.path.join(into, path), "w", encoding="utf-8").write(note)
            run("add", path)
        env = {"GIT_AUTHOR_DATE": step["at"], "GIT_COMMITTER_DATE": step["at"], "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        run("commit", "--quiet", "--allow-empty", "--no-gpg-sign", "-m", step["subject"], env=env)


def self_test():
    bad = []
    history = json.load(open(os.path.join(FIXTURES, "history.json"), encoding="utf-8"))
    tmp = tempfile.mkdtemp(prefix="done-paths-")
    try:
        replay(history["steps"], tmp)
        notes, problems = check_repo(tmp, "2026-11-01")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    got = sorted((p["note"].split("/")[-1], p["kind"], p.get("folder")) for p in problems)
    want = sorted((n, k, f) for n, k, f in history["want"])
    for case in history["cases"]:
        note = case["note"]
        g = sorted(x for x in got if x[0] == note)
        w = sorted(x for x in want if x[0] == note)
        if g != w:
            bad.append(f"{case['name']}: got {g}, want {w}")
    if notes != history["doneBuildNotes"]:
        bad.append(f"Done build notes: got {notes}, want {history['doneBuildNotes']}")
    total = len(history["cases"]) + 1
    for line in bad:
        print("FAIL", line)
    print(f"done paths self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    since, repos, it = SINCE, [], iter(argv)
    for a in it:
        if a == "--since":
            since = next(it)
        else:
            repos.append(a)
    if not repos:
        print(__doc__)
        return 2
    reports, unread = [], 0
    for repo in repos:
        n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
        try:
            notes, problems = check_repo(repo, since)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
            continue
        reports.append({"agent": n, "doneBuildNotes": notes, **summary(problems), "problems": problems})
    print(json.dumps({"since": since, "mode": "shadow", "agents": reports}, indent=2))
    for r in reports:
        print(f"hivepunk-{r['agent']}: {r['doneBuildNotes']} Done build notes, {r['notes']} fail: {r['done-without-tool-commit']} done-without-tool-commit, "
              f"{r['done-without-folder']} done-without-folder", file=sys.stderr)
    total = sum(len(r["problems"]) for r in reports)
    print(f"done paths: {sum(r['notes'] for r in reports)} of {sum(r['doneBuildNotes'] for r in reports)} Done build notes fail, {total} problems, in {len(reports)} agents", file=sys.stderr)
    return 2 if unread else 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
