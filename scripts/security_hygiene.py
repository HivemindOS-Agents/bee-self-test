#!/usr/bin/env python3
"""HB-071 B, C and D (22 Nov 2026 update 22b, section 16): the detectors the security review asked for, run daily.

  B  hivemindos.app's wallet pages can be framed and have no HSTS: `/`, an agent card and `/launchpad/` must each send
     Strict-Transport-Security (max-age at least a year), a Content-Security-Policy with frame-ancestors, and
     X-Frame-Options DENY or SAMEORIGIN; /.well-known/security.txt must be served with a Contact line.
  C  `main` is protected: each repository's rules for `main` hold non_fast_forward and deletion. Those two rules block
     a force-push and a delete only, so the HivemindOS app's and Actions' normal pushes keep working.
  D  no internal host or home path in an agent repository's current tree: `<name>.internal/`, `localhost:<port>`,
     `/Users/<name>/` or `/home/<name>/` (632's two work notes of 17 Nov 2026 carry the media studio's internal
     gateway host, b44fe92 and d99d7c0).

B and D are host work: the site's headers, and the text-unsafe check on every repository write. This only says
whether they have landed, and whether they stay landed. HB-071 E (every action pinned to a commit SHA) is
scripts/live_gate.py's lint, which is required.

    python3 scripts/security_hygiene.py --self-test                          # the fixtures only, no network
    python3 scripts/security_hygiene.py [--repos OWNER/REPO...] [--trees DIR...] [--no-site]
                                                                             # DIR: a checkout of hivepunk-<n>

GH_TOKEN, when set, is sent to the GitHub API only (its rate limit); the rules of a public repository are public.
Exit 0: all hold. 1: one does not. 2: something could not be read (never a pass).
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

UA = "HivemindOS-security-hygiene/0.1 (read-only; https://hivemindos.app)"
PAGES = ["https://hivemindos.app/", "https://hivemindos.app/agents/hivepunkz/1071", "https://hivemindos.app/launchpad/"]
SECURITY_TXT = "https://hivemindos.app/.well-known/security.txt"
YEAR = 31536000
INTERNAL = re.compile(r"[A-Za-z0-9-]+\.internal(?:/|:\d)|\blocalhost:\d{2,5}|/Users/[A-Za-z][\w.-]*/|/home/[A-Za-z][\w.-]*/")
SKIP_DIRS = {".git", "node_modules"}
MAX_FILE = 2 * 1024 * 1024


def header_problems(page, headers):
    """headers: lower-cased name -> value."""
    out = []
    hsts = headers.get("strict-transport-security", "")
    age = re.search(r"max-age=(\d+)", hsts)
    if not age or int(age.group(1)) < YEAR:
        out.append(f"B: {page} sends no Strict-Transport-Security of at least a year ({hsts or 'none'})")
    if "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        out.append(f"B: {page} sends no Content-Security-Policy frame-ancestors")
    if headers.get("x-frame-options", "").strip().upper() not in ("DENY", "SAMEORIGIN"):
        out.append(f"B: {page} sends no X-Frame-Options DENY or SAMEORIGIN")
    return out


def security_txt_problems(status, text):
    if status != 200 or not re.search(r"^\s*Contact:\s*\S", text or "", re.M | re.I):
        return [f"B: {SECURITY_TXT} is not served with a Contact line (HTTP {status})"]
    return []


def ruleset_problems(repo, rules):
    """rules: the list GET /repos/{repo}/rules/branches/main returns."""
    kinds = {r.get("type") for r in rules if isinstance(r, dict)}
    return [f"C: {repo} main has no {k} rule" for k in ("non_fast_forward", "deletion") if k not in kinds]


def internal_problems(name, files):
    """files: {path: text}."""
    out = []
    for path, text in sorted(files.items()):
        for n, line in enumerate(text.splitlines(), 1):
            m = INTERNAL.search(line)
            if m:
                out.append(f"D: {name}/{path}:{n} carries {m.group(0)!r}")
    return out


def tree_files(root):
    files = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            path = os.path.join(folder, n)
            try:
                if os.path.getsize(path) > MAX_FILE:
                    continue
                data = open(path, "rb").read()
            except OSError:
                continue
            if b"\0" in data[:8192]:
                continue
            files[os.path.relpath(path, root)] = data.decode("utf-8", "replace")
    return files


def fetch(url, token=None, method="GET"):
    headers = {"User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method=method), timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, ""
    except (OSError, ValueError):
        return None, {}, ""


def live(repos, trees, site=True):
    problems, unread = [], []
    if site:
        for page in PAGES:
            status, headers, _ = fetch(page)
            if status != 200:
                unread.append(f"{page} (HTTP {status})")
                continue
            problems += header_problems(page, headers)
        status, _, text = fetch(SECURITY_TXT)
        if status is None:
            unread.append(SECURITY_TXT)
        else:
            problems += security_txt_problems(status, text)
    token = os.environ.get("GH_TOKEN")
    for repo in repos:
        status, _, body = fetch(f"https://api.github.com/repos/{repo}/rules/branches/main", token)
        try:
            rules = json.loads(body) if status == 200 else None
        except ValueError:
            rules = None
        if not isinstance(rules, list):
            unread.append(f"{repo} rules (HTTP {status})")
            continue
        problems += ruleset_problems(repo, rules)
    for root in trees:
        files = tree_files(root)
        if not files:
            unread.append(f"{root} (no files: zero is not clean)")
            continue
        problems += internal_problems(os.path.basename(os.path.normpath(root)), files)
    print(json.dumps({"problems": problems, "unread": unread}, indent=2))
    for line in unread:
        print(f"STOP empty_security_setting: {line}: could not be read", file=sys.stderr)
    print(f"security hygiene: {len(problems)} problems, {len(unread)} unread", file=sys.stderr)
    return 2 if unread else 1 if problems else 0


def self_test():
    good_headers = {"strict-transport-security": "max-age=31536000; includeSubDomains",
                    "content-security-policy": "frame-ancestors 'none'", "x-frame-options": "DENY"}
    # What the three pages sent on 22 Nov 2026 (and still on 26 Nov): referrer-policy and x-content-type-options only.
    seen = {"referrer-policy": "strict-origin-when-cross-origin", "x-content-type-options": "nosniff"}
    cases = [
        ("B bad: the 22 Nov headers", len(header_problems("/", seen)), 3),
        ("B bad: HSTS of a day", len(header_problems("/", {**good_headers, "strict-transport-security": "max-age=86400"})), 1),
        ("B good", len(header_problems("/", good_headers)), 0),
        ("B bad: security.txt 404", len(security_txt_problems(404, "")), 1),
        ("B bad: security.txt with no Contact", len(security_txt_problems(200, "Expires: 2027-11-26T00:00:00Z\n")), 1),
        ("B good: security.txt", len(security_txt_problems(200, "Contact: mailto:security@hivemindos.app\n")), 0),
        ("C bad: no rules (22 Nov, all 8 repositories)", len(ruleset_problems("o/r", [])), 2),
        ("C bad: deletion only", len(ruleset_problems("o/r", [{"type": "deletion"}])), 1),
        ("C good", len(ruleset_problems("o/r", [{"type": "deletion"}, {"type": "non_fast_forward"}])), 0),
        ("D bad: 632's 17 Nov work note", len(internal_problems("hivepunk-632", {"work/2026-11-17-0944.md":
            '  "https://hivemindos-media-studio-gateway.internal/v1/outputs/mgen_849bcdc9-d67b-472f-be58-1341cb9f7714/0"\n'})), 1),
        ("D bad: a home path and a localhost port", len(internal_problems("x", {"a.md": "see /Users/someone/proj\n", "b.md": "http://localhost:8787/x\n"})), 2),
        ("D good: the public result link", len(internal_problems("x", {"a.md": "https://hivemindos.app/agents/hivepunkz/632\nan internal note\n"})), 0),
    ]
    bad = [f"{name}: {got} problems, want {want}" for name, got, want in cases if got != want]
    for line in bad:
        print("FAIL:", line)
    print(f"security hygiene self-test: {len(cases) - len(bad)} of {len(cases)} passed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    repos, trees, site, key = [], [], True, None
    for arg in argv:
        if arg in ("--repos", "--trees"):
            key = arg
        elif arg == "--no-site":
            site = False
        elif key == "--repos":
            repos.append(arg)
        elif key == "--trees":
            trees.append(arg)
        else:
            print(__doc__)
            return 2
    return live(repos, trees, site)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
