"""Reading an agent repository's public history from a clone, for the host checks that need more than its last
commit (repeat_guard.py, done_paths.py, rule_lifecycle.py). Read-only; nothing in the repository is run.

The workflow clones each hivepunk-<n> with --filter=blob:none, so a file's text at an old commit is fetched when it is
read. prefetch() asks for every blob a read will need in one request instead of one request a file.
"""
import datetime
import os
import subprocess


def ts(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(datetime.timezone.utc)


def git(repo, *args, stdin=None, env=None, check=True):
    out = subprocess.run(["git", "-C", repo, *args], input=stdin, capture_output=True, text=True, timeout=600,
                         env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})})
    if check and out.returncode != 0:
        raise OSError(out.stderr.strip()[:200] or f"git {' '.join(args)} failed")
    return out.stdout


def commits(repo, since=None, paths=()):
    """Every commit on its first-parent line, oldest first: {h, at, subject, files: [(status, path)]}. An empty commit
    lists no files."""
    args = ["log", "--first-parent", "--reverse", "--no-renames", "--format=%x01%H%x09%cI%x09%s", "--name-status"]
    if since:
        args += ["--since", since]
    out, found = git(repo, *args, "--", *paths), []
    for line in out.splitlines():
        if line.startswith("\x01"):
            h, at, subject = (line[1:].split("\t", 2) + ["", ""])[:3]
            found.append({"h": h, "at": ts(at), "subject": subject, "files": []})
        elif line.strip() and found:
            status, _, path = line.partition("\t")
            found[-1]["files"].append((status[:1], path))
    return found


def is_shallow(repo):
    return git(repo, "rev-parse", "--is-shallow-repository", check=False).strip() == "true"


def prefetch(repo, since=None, paths=()):
    """Fetch, in one request, the blobs that the versions of `paths` since `since` need and the clone lacks."""
    args = ["log", "--raw", "--no-abbrev", "--no-renames", "--format="]
    if since:
        args += ["--since", since]
    oids = sorted({f.split()[3] for f in git(repo, *args, "--", *paths, check=False).splitlines() if f.startswith(":") and len(f.split()) > 4} - {"0" * 40})
    if not oids:
        return 0
    have = git(repo, "cat-file", "--batch-check", stdin="\n".join(oids) + "\n", env={"GIT_NO_LAZY_FETCH": "1"}, check=False)
    missing = [line.split()[0] for line in have.splitlines() if line.endswith(" missing")]
    if missing:
        git(repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--filter=blob:none", "--stdin", "origin",
            stdin="\n".join(missing) + "\n", check=False)
    return len(missing)


def show_many(repo, specs):
    """{spec: text or None} for specs like "<commit>:<path>", read in one git process."""
    specs = list(dict.fromkeys(specs))
    if not specs:
        return {}
    proc = subprocess.run(["git", "-C", repo, "cat-file", "--batch"], input=("\n".join(specs) + "\n").encode(), capture_output=True, timeout=600,
                          env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    data, at, out = proc.stdout, 0, {}
    for spec in specs:
        end = data.index(b"\n", at)
        head = data[at:end].decode("utf-8", "replace").split()
        at = end + 1
        if len(head) < 3 or head[-1] == "missing":
            out[spec] = None
            continue
        size = int(head[2])
        out[spec] = data[at:at + size].decode("utf-8", "replace")
        at += size + 1
    return out


def prefetch_head(repo, rev="HEAD"):
    """Fetch, in one request, the blobs of the tree at `rev` that the clone lacks."""
    oids = [line.split()[2] for line in git(repo, "ls-tree", "-r", rev, check=False).splitlines() if len(line.split()) >= 3 and line.split()[1] == "blob"]
    if not oids:
        return 0
    have = git(repo, "cat-file", "--batch-check", stdin="\n".join(oids) + "\n", env={"GIT_NO_LAZY_FETCH": "1"}, check=False)
    missing = [line.split()[0] for line in have.splitlines() if line.endswith(" missing")]
    if missing:
        git(repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--filter=blob:none", "--stdin", "origin",
            stdin="\n".join(missing) + "\n", check=False)
    return len(missing)
