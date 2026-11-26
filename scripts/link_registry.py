#!/usr/bin/env python3
"""HB-067 C (22 Nov 2026 update, section 5 C): one registry of the hivemindos.app link shapes the host writes.

On 21 Nov 2026 every Hugging Face card footer linked https://hivemindos.app/agents/<n>, a route that had moved: 62
cards pointed at a 404 until a redirect went in on 22 Nov. link_registry.json lists the shapes the host may write
({n} an agent number, {address} a 0x address; a trailing slash, a query and a #fragment do not change a shape) and
what each answers: page (200 after any redirect), redirect (3xx, then 200: "redirect, allowed") or auth (401 or 403
with no token: "auth, allowed", as api.hivemindos.app/mcp is by design).

    python3 scripts/link_registry.py --self-test     # the fixtures only (fixtures/link-registry/), no network
    python3 scripts/link_registry.py DIR...          # clones of hivepunk-<n>: every hivemindos.app link in the tree
                                                     # at HEAD, mapped to its shape; one sample a shape is fetched
                                                     # once (HEAD, then GET; redirects followed; 10 s timeout)

Problems: an unregistered shape (with how many files use it and one example), and a dead shape (a registered or
unregistered shape whose sample does not answer what its kind says). Shadow mode, report-only; nothing is written.
Exit 0 when every link is a registered shape that answers, 1 when not, 2 when a clone could not be read.
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import git_history  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "link_registry.json")
FIXTURES = os.path.join(HERE, "..", "fixtures", "link-registry")
LINK = re.compile(r"https?://(?:[a-z0-9-]+\.)*hivemindos\.app(?:/[^\s\"'<>()\[\]{}`,|\\]*)?(?P<hole><[A-Za-z][A-Za-z _-]{0,20}>|\{[A-Za-z_]{1,20}\})?", re.I)
# A placeholder written straight after a link's last slash ("/bee/<number>", "/agents/hivepunkz/{n}") stands for one
# path segment: an agent number when it names one, else a slug. The link is that shape, never its parent.
NUMBER_HOLES = ("n", "number", "num", "id", "agent", "bee", "agent number", "agent id")
KINDS = ("page", "redirect", "auth")
TIMEOUT = 10
PARTS = {"{n}": r"\d+", "{address}": r"0x[0-9a-fA-F]{40}", "{slug}": r"[A-Za-z0-9._-]+"}


def clean(url):
    """A link as written, with its query, fragment, trailing punctuation and trailing slash taken off."""
    url = re.split(r"[?#]", url, maxsplit=1)[0].rstrip(".:;!*_~")
    scheme, _, rest = url.partition("://")
    host, _, path = rest.partition("/")
    path = "/" + path.rstrip("/") if path.strip("/") else ""
    return f"https://{host.lower()}{path}"


def shape_of(url):
    """The shape of a link no registered shape matches: numbers are {n} and 0x addresses {address}."""
    url = clean(url)
    scheme, _, rest = url.partition("://")
    host, _, path = rest.partition("/")
    segs = [("{address}" if re.fullmatch(PARTS["{address}"], s) else "{n}" if s.isdigit() else s) for s in path.split("/") if s]
    return f"https://{host}" + "".join("/" + s for s in segs)


def compile_shape(shape):
    pattern = re.escape(shape)
    for part, rx in PARTS.items():
        pattern = pattern.replace(re.escape(part), rx)
    return re.compile("^" + pattern + "$")


def matcher(registry):
    shapes = [(s, compile_shape(s["shape"])) for s in registry["shapes"]]

    def match(url):
        u = clean(url)
        return next((s for s, rx in shapes if rx.match(u)), None)
    return match


def registry_problems(registry):
    p, seen, match = [], set(), matcher(registry)
    for s in registry.get("shapes") or []:
        if s.get("kind") not in KINDS:
            p.append(f"{s.get('shape')}: bad kind {s.get('kind')!r}")
        if s.get("shape") in seen:
            p.append(f"{s.get('shape')}: listed twice")
        seen.add(s.get("shape"))
        if not s.get("sample") or match(s["sample"]) is not s:
            p.append(f"{s.get('shape')}: its sample is not that shape")
    return p


def answers(kind, status, redirected):
    """Whether a sample's answer is what its kind says. status: the final status; redirected: a redirect came first."""
    if kind == "auth":
        return status in (401, 403)
    if kind == "redirect":
        return status == 200
    return status == 200


def fetch(url):
    """(final status, redirected, final url, error) for one sample: HEAD, and GET when HEAD does not answer 200 (an API
    may answer HEAD with 401 or 404 and GET with 200)."""
    got = (None, False, url, "no answer")
    for method in ("HEAD", "GET"):
        request = urllib.request.Request(url, method=method, headers={"User-Agent": "bee-self-test-link-registry"})
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as r:
                got = (r.status, clean(r.geturl()) != clean(url), r.geturl(), None)
        except urllib.error.HTTPError as error:
            got = (error.code, clean(error.geturl() or url) != clean(url), error.geturl(), None)
        except (OSError, ValueError) as error:
            got = (None, False, url, str(error)[:120])
        if got[0] == 200:
            return got
    return got


def survey(links, registry, get=fetch):
    """links: [(file, url)]. Returns the shapes used, the unregistered ones and the dead ones."""
    match, used = matcher(registry), {}
    for file, url in links:
        s = match(url)
        key = s["shape"] if s else shape_of(url)
        row = used.setdefault(key, {"shape": key, "registered": bool(s), "kind": s["kind"] if s else "page", "sample": s["sample"] if s else clean(url), "files": set(), "links": 0, "example": url})
        row["files"].add(file)
        row["links"] += 1
    unregistered, dead = [], []
    for key, row in sorted(used.items()):
        status, redirected, final, error = get(row["sample"])
        row.update(status=status, redirected=redirected, final=final, error=error, files=len(row["files"]))
        if not row["registered"]:
            unregistered.append(row)
        if not answers(row["kind"], status, redirected):
            dead.append(row)
    return sorted(used.values(), key=lambda r: -r["links"]), unregistered, dead


def links_in(text):
    out = []
    for m in LINK.finditer(text or ""):
        url, hole = m.group(0), m.group("hole")
        if hole:
            url = url[: -len(hole)]
            if url.endswith("/"):
                url += "0" if hole[1:-1].strip().lower() in NUMBER_HOLES else "x"
        out.append(url)
    return out


def repo_links(repo):
    """(file, url) for every hivemindos.app link in the tree at HEAD (text files only)."""
    git_history.prefetch_head(repo)
    out = subprocess.run(["git", "-C", repo, "grep", "-I", "-o", "-E", "-i", r"https?://([a-z0-9-]+\.)*hivemindos\.app[^][[:space:]\"'<>(){}`,|\\]*(<[A-Za-z][A-Za-z _-]{0,20}>|\{[A-Za-z_]{1,20}\})?", "HEAD", "--", "."],
                         capture_output=True, text=True, timeout=600)
    if out.returncode not in (0, 1):
        raise OSError(out.stderr.strip()[:200])
    found = []
    for line in out.stdout.splitlines():
        _, file, url = line.split(":", 2) if line.startswith("HEAD:") else ("", *line.split(":", 1))
        found += [(file, u) for u in links_in(url)]
    return found


def self_test():
    bad = []
    registry = json.load(open(REGISTRY))
    if registry_problems(registry):
        bad.append(f"link_registry.json: {registry_problems(registry)}")
    match = matcher(registry)
    for name, url, want in [
        ("an agent's log", "https://hivemindos.app/bee/547", "https://hivemindos.app/bee/{n}"),
        ("the canonical page, with and without its slash", "https://hivemindos.app/agents/hivepunkz/1071/", "https://hivemindos.app/agents/hivepunkz/{n}"),
        ("the card footer's redirect", "https://hivemindos.app/agents/667.", "https://hivemindos.app/agents/{n}"),
        ("a fragment and a query", "https://api.hivemindos.app/v1/hall?week=2025-01-06#bounty", "https://api.hivemindos.app/v1/hall"),
        ("a coin page", "https://hivemindos.app/agents/base/0x1649cd37f4748807b4882fc48765ba0b2affa94a/4200", "https://hivemindos.app/agents/base/{address}/{n}"),
        ("the agents index is not an agent's page", "https://hivemindos.app/agents/hivepunkz/", None),
        ("a note page nobody registered", "https://hivemindos.app/notes/agent-memory-lint-fixtures/", None),
    ]:
        got = (match(url) or {}).get("shape")
        if got != want:
            bad.append(f"{name}: got {got}, want {want}")
    # Links as the files hold them: in a README line, in JSON with escaped newlines, and in a sentence's last word.
    text = open(os.path.join(FIXTURES, "card.md"), encoding="utf-8").read()
    if [clean(u) for u in links_in(text)] != ["https://hivemindos.app/agents/667", "https://hivemindos.app/bee/667", "https://hivemindos.app/notes/agent-memory-lint-fixtures", "https://api.hivemindos.app/mcp"]:
        bad.append(f"links in a card: got {links_in(text)}")
    # The survey: an unregistered shape is a problem; a page that 404s is dead; the redirect and the 401 are allowed.
    answer = {"https://hivemindos.app/agents/667": (200, True), "https://hivemindos.app/bee/547": (200, False), "https://hivemindos.app/notes/agent-memory-lint-fixtures": (404, False),
              "https://api.hivemindos.app/mcp": (401, False), "https://hivemindos.app/agents/547": (200, True)}
    get = lambda url: (*answer.get(clean(url), (404, False)), url, None)
    sample = registry
    used, unregistered, dead = survey([("card.md", u) for u in links_in(text)], sample, get)
    if [r["shape"] for r in unregistered] != ["https://hivemindos.app/notes/agent-memory-lint-fixtures"]:
        bad.append(f"the unregistered shape: got {[r['shape'] for r in unregistered]}")
    if [r["shape"] for r in dead] != ["https://hivemindos.app/notes/agent-memory-lint-fixtures"]:
        bad.append(f"the dead shape: got {[(r['shape'], r['status']) for r in dead]}")
    # The 21 Nov state: the footer's route answered 404, and a registry without its shape calls it unregistered.
    before = {"shapes": [s for s in registry["shapes"] if s["shape"] != "https://hivemindos.app/agents/{n}"]}
    get21 = lambda url: (404, False, url, None) if clean(url) == "https://hivemindos.app/agents/667" else get(url)
    used, unregistered, dead = survey([("card.md", "https://hivemindos.app/agents/667")], before, get21)
    if [(r["shape"], r["status"]) for r in unregistered] != [("https://hivemindos.app/agents/{n}", 404)] or len(dead) != 1:
        bad.append(f"21 Nov's footer: got {unregistered}, {dead}")
    if not answers("auth", 401, False) or answers("page", 401, False) or answers("redirect", 404, True):
        bad.append("what each kind answers")
    # A shape written out in prose with a placeholder (a scout's "the card at https://hivemindos.app/bee/<number>")
    # is that shape, never its parent: 632, 547 and 1071's scout notes read as the 404 /agents/hivepunkz and /bee.
    prose = "cards at https://hivemindos.app/agents/hivepunkz/<number> and https://hivemindos.app/bee/<n>, or {n}: https://hivemindos.app/bee/{n}."
    got = [(match(u) or {}).get("shape") for u in links_in(prose)]
    if got != ["https://hivemindos.app/agents/hivepunkz/{n}", "https://hivemindos.app/bee/{n}", "https://hivemindos.app/bee/{n}"]:
        bad.append(f"a shape with a placeholder: got {got} from {links_in(prose)}")
    if [shape_of(u) for u in links_in("see https://hivemindos.app/notes/<slug> here")] != ["https://hivemindos.app/notes/x"]:
        bad.append(f"an unregistered shape with a placeholder: got {[shape_of(u) for u in links_in('see https://hivemindos.app/notes/<slug> here')]}")
    total = 1 + 7 + 1 + 2 + 1 + 1 + 2
    for line in bad:
        print("FAIL", line)
    print(f"link registry self-test: {total - len(bad)} of {total} passed")
    return 1 if bad else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if not argv:
        print(__doc__)
        return 2
    registry = json.load(open(REGISTRY))
    links, unread, per = [], 0, {}
    for repo in argv:
        n = re.sub(r"^hivepunk-", "", os.path.basename(os.path.normpath(repo)))
        try:
            found = repo_links(repo)
        except (OSError, subprocess.SubprocessError) as error:
            unread += 1
            print(f"could not read {repo}: {error}", file=sys.stderr)
            continue
        per[n] = len(found)
        links += [(f"hivepunk-{n}/{file}", url) for file, url in found]
    used, unregistered, dead = survey(links, registry)
    print(json.dumps({"mode": "shadow", "links": per, "registryProblems": registry_problems(registry), "shapes": used,
                      "unregistered": [r["shape"] for r in unregistered], "dead": [{"shape": r["shape"], "status": r["status"], "error": r["error"]} for r in dead]}, indent=2, default=str))
    for r in unregistered:
        print(f"UNREGISTERED {r['shape']} ({r['links']} links in {r['files']} files, e.g. {r['example'][:90]}), sample answered {r['status']}", file=sys.stderr)
    for r in dead:
        print(f"DEAD {r['shape']}: {r['sample']} answered {r['status'] or r['error']}", file=sys.stderr)
    print(f"link registry: {len(links)} links in {len(per)} agents, {len(used)} shapes ({sum(1 for r in used if r['registered'])} registered), {len(unregistered)} unregistered, {len(dead)} dead", file=sys.stderr)
    return 2 if unread else 1 if unregistered or dead or registry_problems(registry) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
