#!/usr/bin/env python3
"""B-08r1 (25 Nov 2026 checklist, rank 57; the 15 Nov self-watchdog pack, S11 "Commit-time gates"): D1, D5 and D22.

HB-014's named-files preflight is merged into HB-068 and HB-075; its commit-time part is this, run in the self-test
runner before any tool code (self-test.yml, "Commit-time gates") and as a sweep in host-checks (changed tool folders
daily, every folder on Mondays). Everything is read from git at one commit; nothing in an agent repository is run.

  D1  missing_committed_file      A path the tool's own files name does not exist at that commit, resolved from the
                                  tool folder (or the repository root). Named by: a string literal in self_test.py that
                                  is a relative path the test does not write itself, a cell of a rules or index .csv
                                  in the folder (rules.csv, fixture-rows.csv; never a dataset's data.csv),
                                  and a `code span` in the folder's README.md or ARTIFACTS.md, each a relative path
                                  with a folder in it (fixtures/x.txt; a bare out.json is what a test writes, too
                                  often to name). The runner refuses to
                                  start on a D1 hit from self_test.py or a CSV, `missing in commit: <path>`, when the
                                  self-test makes no file of its own and the file's folder is in the commit; when it does (writes fixtures at run time, a temp
                                  folder), and for a README or ARTIFACTS line, the hit is reported, never a refusal.
  D5  undefined_name              pyflakes reports an undefined name in any .py under the tool folder, nested copies
                                  included. pyflakes parses; it never imports or runs the file.
  D22 claimed_file_not_committed  A work note (work/<date>-<time>-*.md) or a commit message in the 48 hours up to
                                  that commit says it built, added, created or wrote a file under tools/ (a tools/
                                  path, or a code file named beside its tools/<folder>), and the file
                                  is not at that commit and never was in the repository's history. A sentence that says
                                  the file was not committed does not count.

The replays the pack's "Done when" names (fixtures/commit-gates/ holds their files, so --self-test needs no network):
hivepunk-632 at f22b7fd fires D1 for fixtures/missing-why.txt and fixtures/unlabelled-claim.txt; hivepunk-547 at
a22aa8b fires D5 for `dedent`; hivepunk-1071 at cfd9bc1 fires D22 for tools/glb-pad-cases/release_card.py.

    python3 scripts/commit_gates.py --self-test
    python3 scripts/commit_gates.py REPO [--commit SHA] [--tool NAME] [--pregate] [--json OUT]
                                                   # REPO: a clone with full history (blobless is fine)
    python3 scripts/commit_gates.py --sweep [--all] REPO...   # each REPO at HEAD; changed folders in 24 h, or --all

Exit 0: nothing found. 1: a finding (with --pregate, only a D1 refusal). 2: a repository or pyflakes could not be
read, never a pass.
"""
import ast
import csv
import datetime
import io
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "fixtures", "commit-gates")
WINDOW = datetime.timedelta(hours=48)
PATHLIKE = re.compile(r"^(?!\.?/)(?!.*\.\.)(?![a-z]+:)[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*\.[A-Za-z0-9]{1,6}$")
CODE_SPAN = re.compile(r"`([^`\n]{1,200})`")
NOTE_NAME = re.compile(r"^work/(\d{4}-\d\d-\d\d)-(\d\d)(\d\d)-.*\.md$")
CLAIM = re.compile(r"\b(?:built|added|created|wrote)\b", re.I)
CLAIM_END = re.compile(r"[.;!?](?:\s|$)|\n|\bthat\b|\bwhich\b|\bwho\b")
NOT_COMMITTED = re.compile(r"\b(?:not|never|couldn'?t|could not|did not|didn'?t)\s+(?:been\s+|be\s+|yet\s+)?(?:committed|commit|in this commit|in the commit)\b", re.I)
FILE_TOKEN = re.compile(r"(?<![\w/.-])((?:tools/[A-Za-z0-9_.-]+/)?(?:(?![A-Za-z0-9_.-]*\.(?:py|md|csv|json|txt|sh|js|ts|mjs)/)[A-Za-z0-9_.-]+/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:py|mjs|js|ts|sh|csv|json|jsonl|md|txt|yaml|yml|toml))\b")
TOOL_DIR = re.compile(r"(?<![\w/.-])tools/([A-Za-z0-9_.-]+)")
CODE_EXT = (".py", ".mjs", ".js", ".ts", ".sh")
INDEX_CSV = re.compile(r"rules|index|cases|fixture|manifest", re.I)  # a rules or index CSV, not a dataset's data.csv
# A self-test that makes files of its own (fixtures written at run time, a temp folder) names paths it creates: those
# names are reported, never a refusal. Measured on 26 Nov 2026, every D1 hit on a tool whose latest run passed came
# from such a self-test (or a CSV beside one).
MAKES_FILES = {"write_text", "write_bytes", "mkdtemp", "mkstemp", "TemporaryDirectory", "NamedTemporaryFile", "makedirs",
               "mkdir", "copy", "copy2", "copyfile", "copytree", "move", "symlink", "touch", "writer", "dump"}
WRITE_CALLS = {"write_text", "write_bytes", "mkdir", "makedirs", "touch", "mkstemp", "mkdtemp"}


def git(repo, *args, data=False):
    out = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=True, timeout=180)
    return out.stdout if data else out.stdout.decode("utf-8", "replace")


class Tree:
    """One commit of a repository, read with git."""

    def __init__(self, repo, commit="HEAD"):
        self.repo, self.commit = repo, git(repo, "rev-parse", commit).strip()
        self.oids = {}
        for entry in git(repo, "ls-tree", "-r", "-z", self.commit).split("\0"):
            if "\t" in entry:
                meta, path = entry.split("\t", 1)
                if meta.split()[1] == "blob":
                    self.oids[path] = meta.split()[2]
        self.paths = set(self.oids)
        self.promisor = git(repo, "config", "--default", "false", "--get", "remote.origin.promisor").strip() == "true"
        self.dirs = {os.path.dirname(p) for p in self.paths}
        for p in list(self.dirs):
            while p:
                p = os.path.dirname(p)
                self.dirs.add(p)
        self.tools = sorted({p.split("/")[1] for p in self.paths if p.startswith("tools/") and p.count("/") >= 2})
        self.at = datetime.datetime.fromisoformat(git(repo, "show", "-s", "--format=%cI", self.commit).strip())

    def prefetch(self, paths):
        """A blobless clone fetches each blob on first read, one round trip a file; fetch the missing ones at once."""
        if not self.promisor:
            return
        oids = sorted({self.oids[p] for p in paths if p in self.oids})
        if not oids:
            return
        check = subprocess.run(["git", "-C", self.repo, "cat-file", "--batch-check"], input="\n".join(oids) + "\n", capture_output=True,
                               text=True, timeout=60, env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
        missing = [line.split()[0] for line in check.stdout.splitlines() if line.endswith(" missing")]
        for i in range(0, len(missing), 200):
            git(self.repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "origin", *missing[i:i + 200])

    def text(self, path):
        return git(self.repo, "cat-file", "blob", self.oids[path], data=True).decode("utf-8", "replace")

    def has(self, path):
        return path in self.paths or path in self.dirs

    def ever(self, path):
        """Whether the path was ever in any commit of the repository's history."""
        return bool(git(self.repo, "log", "--all", "--format=%H", "-1", "--", path).strip())


# ---------------------------------------------------------------------------------------------------------------- D1
def written_by(tree):
    """String constants a self-test writes or makes itself: open(x, 'w'), x.write_text(), os.makedirs(x)."""
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
        args = list(node.args)
        if name == "open" and len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str) and set(args[1].value) & set("wax"):
            targets = [args[0]]
        elif name in WRITE_CALLS:
            targets = args[:1] + ([node.func.value] if isinstance(node.func, ast.Attribute) else [])
        else:
            continue
        for t in targets:
            for sub in ast.walk(t):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    out.add(sub.value)
    return out


def makes_files(text):
    """Whether a self-test writes or creates any file itself."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
            if name in MAKES_FILES:
                return True
            if name == "open":
                mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str) and not set(mode.value) & set("wax+")):
                    if mode is not None:
                        return True
    return False


def self_test_names(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []  # L52 / the compile step owns a file that does not parse
    written = written_by(tree)
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and PATHLIKE.match(n.value) and "/" in n.value and n.value not in written]


def csv_names(text):
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return []
    return [cell.strip() for row in rows for cell in row if PATHLIKE.match(cell.strip()) and "/" in cell.strip()]


def d1(tree, tool):
    """[(path, source, refuses)] for the names in one tool folder that do not exist at the commit."""
    folder = f"tools/{tool}"
    found, seen = [], set()
    tree.prefetch([p for p in tree.paths if p.startswith(folder + "/") and (p.endswith((".py", ".csv")) or p.endswith(("/README.md", "/ARTIFACTS.md")))])

    def resolve(name):
        return [os.path.normpath(os.path.join(folder, name)), os.path.normpath(name)]

    def named(name, source, refuses):
        # Resolved from the tool folder or the repository root; a path a sibling tool holds (632's
        # publish-attribution-run-lines-package reads card-lint's fixtures/) is not missing either, unless the tool has
        # that first folder itself (632's run-record-lint-fixtures/fixtures/ lacks what run-record-lint-dataset holds).
        own = f"{folder}/{name.split('/')[0]}" in tree.dirs
        if any(tree.has(p) for p in resolve(name)) or (not own and any(tree.has(f"tools/{t}/{name}") for t in tree.tools)):
            return
        path = resolve(name)[0]
        # A refusal needs the file's own folder in the commit: a file missing from fixtures/ that holds its siblings
        # (632's), not a string that only looks like a path (547's stated-issues expects the text 'data/issues.csv').
        refuses = refuses and os.path.dirname(path) in tree.dirs
        if path not in seen:
            seen.add(path)
            found.append((path, source, refuses))

    test = f"{folder}/self_test.py"
    strict = test in tree.paths and not makes_files(tree.text(test))
    for path in sorted(p for p in tree.paths if p.startswith(folder + "/")):
        rel = path[len(folder) + 1:]
        if rel == "self_test.py":
            for name in self_test_names(tree.text(path)):
                named(name, rel, strict)
        elif rel.endswith(".csv") and "/" not in rel and INDEX_CSV.search(rel):
            for name in csv_names(tree.text(path)):
                named(name, rel, strict)
        elif rel in ("README.md", "ARTIFACTS.md"):
            for span in CODE_SPAN.findall(tree.text(path)):
                for word in span.split():
                    if PATHLIKE.match(word) and "/" in word:
                        named(word, rel, False)
    return found


# ---------------------------------------------------------------------------------------------------------------- D5
def undefined_names(text, name):
    """[(line, name)] pyflakes reports as undefined. Raises ImportError when pyflakes is missing."""
    from pyflakes import api, messages, reporter as rep
    found = []

    class Collect(rep.Reporter):
        def __init__(self):
            super().__init__(io.StringIO(), io.StringIO())

        def flake(self, message):
            if isinstance(message, messages.UndefinedName):
                found.append((message.lineno, message.message_args[0]))

    api.check(text, name, Collect())
    return found


def d5(tree, tool):
    folder = f"tools/{tool}/"
    out = []
    tree.prefetch([p for p in tree.paths if p.startswith(folder) and p.endswith(".py")])
    for path in sorted(p for p in tree.paths if p.startswith(folder) and p.endswith(".py")):
        for line, name in undefined_names(tree.text(path), path):
            out.append({"path": path, "line": line, "name": name})
    return out


# --------------------------------------------------------------------------------------------------------------- D22
def claims(text):
    """Files a note or a commit message says it built, added, created or wrote: tools/<folder>/<file> paths."""
    out = []
    folders = TOOL_DIR.findall(text)
    for m in CLAIM.finditer(text):
        start = m.end()
        end = CLAIM_END.search(text, start)
        window = text[start:end.start() if end else start + 160][:160]
        sentence_start = max(text.rfind(". ", 0, m.start()), text.rfind("\n", 0, m.start())) + 1
        sentence_end = text.find(". ", m.end())
        if NOT_COMMITTED.search(text[sentence_start:sentence_end if sentence_end > 0 else None]):
            continue
        local = TOOL_DIR.findall(window) or TOOL_DIR.findall(text[sentence_start:m.start()]) or folders[:1]
        for token in FILE_TOKEN.findall(window):
            if token.startswith("tools/"):
                path = token
            elif not token.endswith(CODE_EXT):
                continue  # a bare data.csv or README.md beside "built" is what the tool emits, not a file it committed
            elif local:
                path = f"tools/{local[-1]}/{token}"
            else:
                continue
            if path not in out:
                out.append(path)
    return out


def d22(tree, tool=None):
    """[(path, where)] claimed in the 48 hours up to the commit, not at the commit and never in history."""
    since = tree.at - WINDOW
    notes = []
    for path in sorted(tree.paths):
        m = NOTE_NAME.match(path)
        if not m:
            continue
        at = datetime.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}:{m.group(3)}:00+00:00")
        if since <= at <= tree.at + datetime.timedelta(minutes=5):
            notes.append(path)
    tree.prefetch(notes)
    sources = [(path, tree.text(path)) for path in notes]
    log = git(tree.repo, "log", f"--since={since.isoformat()}", "--format=%H%x00%B%x01", tree.commit)
    for entry in log.split("\x01"):
        if "\x00" in entry:
            sha, body = entry.strip().split("\x00", 1)
            sources.append((f"commit {sha[:7]}", body))
    out, seen = [], set()
    for where, text in sources:
        for path in claims(text):
            if tool and not path.startswith(f"tools/{tool}/"):
                continue
            if path in seen or tree.has(path) or tree.ever(path):
                continue
            seen.add(path)
            out.append((path, where))
    return out


# -------------------------------------------------------------------------------------------------------------- runs
def tool_folders(tree):
    return sorted({p.split("/")[1] for p in tree.paths if p.startswith("tools/") and p.count("/") >= 2})


def gates(tree, tools, tool_for_d22=None):
    report = {"commit": tree.commit, "d1": [], "d5": [], "d22": []}
    for tool in tools:
        report["d1"] += [{"path": p, "namedIn": f"tools/{tool}/{s}", "refuses": r} for p, s, r in d1(tree, tool)]
        report["d5"] += d5(tree, tool)
    report["d22"] = [{"path": p, "claimedIn": w} for p, w in d22(tree, tool_for_d22)]
    return report


def changed_tools(tree, hours=24):
    out = git(tree.repo, "log", f"--since={(tree.at - datetime.timedelta(hours=hours)).isoformat()}", "--name-only", "--format=", tree.commit, "--", "tools/")
    return sorted({p.split("/")[1] for p in out.split() if p.startswith("tools/") and p.count("/") >= 2} & set(tool_folders(tree)))


def lines(report, repo, out=sys.stdout):
    for f in report["d1"]:
        print(f"{repo}: D1 missing_committed_file: {f['path']} (named in {f['namedIn']}){'' if f['refuses'] else ', reported'}", file=out)
    for f in report["d5"]:
        print(f"{repo}: D5 undefined_name: {f['path']}:{f['line']}: {f['name']}", file=out)
    for f in report["d22"]:
        print(f"{repo}: D22 claimed_file_not_committed: {f['path']} (claimed in {f['claimedIn']})", file=out)


# --------------------------------------------------------------------------------------------------------- self-test
def build(root, name, commits):
    """A git repository from [(iso time, message, {path: text or None})]; returns its path."""
    repo = os.path.join(root, name)
    os.makedirs(repo)
    git(repo, "init", "--quiet")
    for at, message, files in commits:
        for path, text in files.items():
            full = os.path.join(repo, path)
            if text is None:
                os.remove(full)
                continue
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(text)
        git(repo, "add", "-A")
        subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "--allow-empty", "-m", message],
                       check=True, capture_output=True, env={**os.environ, "GIT_AUTHOR_DATE": at, "GIT_COMMITTER_DATE": at})
    return repo


def fixture(*parts):
    return open(os.path.join(FIXTURES, *parts), encoding="utf-8").read()


def self_test():
    bad, cases = [], 0
    root = tempfile.mkdtemp(prefix="commit-gates-")

    def want(label, ok, got):
        nonlocal cases
        cases += 1
        if not ok:
            bad.append(f"{label}: got {got}")

    # Replay 1: hivepunk-632 at f22b7fd (15 Nov 2026), tools/run-record-lint-fixtures as it was.
    t632 = "tools/run-record-lint-fixtures"
    files = {f"{t632}/{n}": fixture("632-f22b7fd", n) for n in ("self_test.py", "rules.csv", "README.md", "run_record_lint.py")}
    files[f"{t632}/fixtures/clean.txt"] = fixture("632-f22b7fd", "fixtures", "clean.txt")
    repo = build(root, "hivepunk-632", [("2026-11-15T04:58:44Z", "Work note: Fixed run-record-lint-fixtures", files)])
    tree = Tree(repo)
    got = d1(tree, "run-record-lint-fixtures")
    refusing = sorted(p for p, _, r in got if r)
    want("632 f22b7fd: D1 for both fixture paths, refusing", refusing == [f"{t632}/fixtures/missing-why.txt", f"{t632}/fixtures/unlabelled-claim.txt"], got)
    # Fixed: the two fixtures committed, nothing fires.
    # The real tree also holds run-record-lint-dataset/fixtures/missing-why.txt: a sibling's file does not stand in.
    sibling = {**files, "tools/run-record-lint-dataset/fixtures/missing-why.txt": "x\n", "tools/run-record-lint-dataset/fixtures/unlabelled-claim.txt": "y\n"}
    repo = build(root, "hivepunk-632-siblings", [("2026-11-15T04:58:44Z", "f22b7fd's tree", sibling)])
    got = sorted(p for p, _, r in d1(Tree(repo), "run-record-lint-fixtures") if r)
    want("632 f22b7fd beside its sibling tool's fixtures: still refused", got == refusing, got)
    repo = build(root, "hivepunk-632-fixed", [("2026-11-15T04:58:44Z", "fixed", {**files, f"{t632}/fixtures/missing-why.txt": "x\n", f"{t632}/fixtures/unlabelled-claim.txt": "y\n"})])
    got = d1(Tree(repo), "run-record-lint-fixtures")
    want("632 with its fixtures committed: no D1", not [g for g in got if g[2]], got)
    # A self-test that writes its own fixtures names paths it creates: reported, not a refusal.
    maker = "import os, tempfile\nd = tempfile.mkdtemp()\nFIX = 'data/a.csv'\n"
    repo = build(root, "maker", [("2026-11-26T00:00:00Z", "m", {"tools/maker/self_test.py": maker})])
    got = d1(Tree(repo), "maker")
    want("a self-test that makes its own files is reported, never refused", [(p, r) for p, _, r in got] == [("tools/maker/data/a.csv", False)], got)
    # A path-shaped value whose folder the tool never committed is a value, reported, not refused.
    repo = build(root, "values", [("2026-11-26T00:00:00Z", "v", {"tools/v/self_test.py": "CASES = [('#53', 'data/issues.csv', 'not shown')]\n"})])
    got = d1(Tree(repo), "v")
    want("547 stated-issues: a path-shaped value with no committed folder is not refused", [(p, r) for p, _, r in got] == [("tools/v/data/issues.csv", False)], got)
    # A path the self-test writes itself is not named.
    got = self_test_names("import os\nopen('out/report.json', 'w').write('x')\nos.makedirs('tmp/run')\np = 'fixtures/a.txt'\nq = 'data.csv'\n")
    want("a path the self-test writes, or a bare file name, is not a name", got == ["fixtures/a.txt"], got)

    # Replay 2: hivepunk-547 at a22aa8b (14 Nov 2026), generate_catalog.py with dedent used and never imported.
    t547 = "tools/agent-memory-lint-fixture-catalog"
    repo = build(root, "hivepunk-547", [("2026-11-14T09:14:32Z", "agent-memory-lint-fixture-catalog: generate_catalog.py",
                                         {f"{t547}/generate_catalog.py": fixture("547-a22aa8b", "generate_catalog.py"),
                                          f"{t547}/nested/copy/helper.py": "def f():\n    return undefined_thing\n"})])
    try:
        got = d5(Tree(repo), "agent-memory-lint-fixture-catalog")
    except ImportError as error:
        print(f"STOP: pyflakes is not installed ({error}); pip install pyflakes==3.2.0")
        return 2
    want("547 a22aa8b: D5 for dedent", any(g["name"] == "dedent" and g["path"].endswith("generate_catalog.py") for g in got), got)
    want("D5 reads nested copies", any(g["name"] == "undefined_thing" for g in got), got)
    fixed = fixture("547-a22aa8b", "generate_catalog.py").replace("import re\n", "import re\nfrom textwrap import dedent\n", 1)
    repo = build(root, "hivepunk-547-fixed", [("2026-11-14T09:14:32Z", "fixed", {f"{t547}/generate_catalog.py": fixed})])
    got = d5(Tree(repo), "agent-memory-lint-fixture-catalog")
    want("547 with dedent imported: no D5", got == [], got)

    # Replay 3: hivepunk-1071 at cfd9bc1 (15 Nov 2026): a Partial note claims release_card.py, never committed.
    note = "work/2026-11-15-0315-publish-the-dataset-glb-fixture-byte-layouts-on-hugging-face.md"
    repo = build(root, "hivepunk-1071", [
        ("2026-11-14T20:00:00Z", "glb-pad-cases: build_card.py", {"tools/glb-pad-cases/build_card.py": "print('card')\n"}),
        ("2026-11-15T03:15:47Z", "Work note, 2026-11-15 03:15 UTC (no tool file in this commit)", {note: fixture("1071-cfd9bc1", "note.md")})])
    tree = Tree(repo)
    got = d22(tree)
    want("1071 cfd9bc1: D22 for release_card.py, and only it", [p for p, _ in got] == ["tools/glb-pad-cases/release_card.py"], got)
    got = d22(tree, "glb-pad-cases")
    want("D22 scoped to the dispatched tool", [p for p, _ in got] == ["tools/glb-pad-cases/release_card.py"], got)
    got = claims("Built tools/glb-pad-cases/release_card.py but it was not committed: it ran out of room.")
    want("a note that says the file was not committed does not fire", got == [], got)
    got = claims("Added tools/x/new_check.py and wrote tools/x/fixtures/case1.json.")
    want("two claims in one note", got == ["tools/x/new_check.py", "tools/x/fixtures/case1.json"], got)
    got = claims("Wrote tools/agent-dispatch/README.md/self_test.py updates.")
    want("a slash-joined list names README.md, never a folder called README.md", got == ["tools/agent-dispatch/README.md"], got)
    got = claims("Built tools/glb-pad-cases: offline builder for the GLB padding-cases data.csv, README and card that writes not-opened.")
    want("1071's 14 Nov note: the data.csv it emits is not a claimed file", got == [], got)
    # A claimed file that exists at the commit, or existed once, does not fire.
    repo = build(root, "hivepunk-1071-later", [
        ("2026-11-15T03:00:00Z", "release_card.py", {"tools/glb-pad-cases/release_card.py": "x = 1\n"}),
        ("2026-11-15T03:10:00Z", "remove it", {"tools/glb-pad-cases/release_card.py": None}),
        ("2026-11-15T03:15:47Z", "note", {note: fixture("1071-cfd9bc1", "note.md")})])
    got = d22(Tree(repo))
    want("a file that once was in history does not fire D22", got == [], got)
    for line in bad:
        print("FAIL:", line)
    print(f"commit gates self-test: {cases - len(bad)} of {cases} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["--sweep"]:
        rest, every = argv[1:], False
        if rest[:1] == ["--all"]:
            every, rest = True, rest[1:]
        if not rest:
            print(__doc__)
            return 2
        reports, unread = [], 0
        for repo in rest:
            try:
                tree = Tree(repo)
                tools = tool_folders(tree) if every else changed_tools(tree)
                report = gates(tree, tools)
                reports.append({"repo": os.path.basename(os.path.normpath(repo)), "tools": len(tools), **report})
                lines(report, reports[-1]["repo"], sys.stderr)
            except ImportError as error:
                print(f"STOP: pyflakes is not installed ({error})", file=sys.stderr)
                return 2
            except (OSError, subprocess.SubprocessError) as error:
                unread += 1
                print(f"STOP empty_security_setting: {repo}: could not be read: {error}", file=sys.stderr)
        found = sum(len(r["d1"]) + len(r["d5"]) + len(r["d22"]) for r in reports)
        print(json.dumps(reports, indent=2))
        print(f"commit gates ({'every folder' if every else 'folders changed in 24 h'}): {found} findings in "
              f"{sum(r['tools'] for r in reports)} tool folders of {len(reports)} repositories", file=sys.stderr)
        return 2 if unread else 1 if found else 0
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    repo, rest = argv[0], argv[1:]
    commit, tool, pregate, out = "HEAD", None, False, None
    while rest:
        if rest[0] == "--commit" and len(rest) > 1:
            commit, rest = rest[1], rest[2:]
        elif rest[0] == "--tool" and len(rest) > 1:
            tool, rest = rest[1], rest[2:]
        elif rest[0] == "--json" and len(rest) > 1:
            out, rest = rest[1], rest[2:]
        elif rest[0] == "--pregate":
            pregate, rest = True, rest[1:]
        else:
            print(__doc__)
            return 2
    try:
        tree = Tree(repo, commit)
        report = gates(tree, [tool] if tool else tool_folders(tree), tool)
    except ImportError as error:
        print(f"STOP: pyflakes is not installed ({error})", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError) as error:
        print(f"STOP empty_security_setting: {repo}: could not be read: {error}", file=sys.stderr)
        return 2
    lines(report, os.path.basename(os.path.normpath(repo)))
    if out:
        with open(out, "w") as f:
            json.dump(report, f)
    refusals = [f["path"] for f in report["d1"] if f["refuses"]]
    if pregate:
        for path in refusals:
            print(f"missing in commit: {path}")
        return 1 if refusals else 0
    return 1 if report["d1"] or report["d5"] or report["d22"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
