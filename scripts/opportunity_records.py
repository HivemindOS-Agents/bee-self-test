#!/usr/bin/env python3
"""How the opportunity checks read one item of an agent's public OPPORTUNITIES.md: one place, imported by
opportunities_48h.py and opportunities_hb060.py.

  quoted(block)         its Asks line quotes at least one outside ask
  spotted(block)        it carries a valid `- Spotted:` record: a line with an address (http or https) and a commit
                        SHA (7 to 64 hex, at least one letter), as `<url>@<sha>`, `<url> @ <sha>`, `(commit <sha>)`,
                        `sha <sha>` or a /commit/, /blob/ or /tree/ address that names one (25 Nov 2026 update, rows
                        82 and 84, guard 241). The host does not write Spotted lines yet; when it does, they are read.
  status(block)         its Status word (Candidate, Picked, Building, Shipped, Expired, ...)
  tier(block)           its Tier word, or None
  ask_urls(block)       the addresses of its quoted asks, in order
  canonical_key(...)    (repository, normalised title): the same need on the same repository, whichever agent lists it
"""
import re

ASKS_NONE = re.compile(r"^- Asks:\s*none quoted yet", re.M | re.I)
ASKS_LINE = re.compile(r"^- Asks:\s*(.+)$", re.M)
SPOTTED_LINE = re.compile(r"^- Spotted:(.*)$", re.M | re.I)
URL = re.compile(r"https?://[^\s@)\]>\"']+", re.I)
HEX = re.compile(r"(?<![0-9a-z])[0-9a-f]{7,64}(?![0-9a-z])", re.I)
STATUS = re.compile(r"^- Status:\s*([A-Za-z]+)", re.M)
TIER = re.compile(r"^- Tier:\s*([a-z]+)", re.M | re.I)
ASK_URL = re.compile(r"^  - .* by [^,\n]+, (https?://\S+)", re.M)


def quoted(block):
    m = ASKS_LINE.search(block or "")
    return bool(m) and not ASKS_NONE.search(block or "")


def spotted(block):
    """The first valid Spotted record as (url, sha), or None."""
    for m in SPOTTED_LINE.finditer(block or ""):
        line = m.group(1)
        urls = URL.findall(line)
        if not urls:
            continue
        for sha in HEX.findall(line):
            if re.search(r"[a-f]", sha, re.I):
                return urls[0].rstrip(".,;"), sha.lower()
    return None


def status(block):
    m = STATUS.search(block or "")
    return m.group(1) if m else None


def tier(block):
    m = TIER.search(block or "")
    return m.group(1).lower() if m else None


def ask_urls(block):
    return [u.rstrip(".,;") for u in ASK_URL.findall(block or "")]


def repository(url):
    """github.com/<owner>/<repo>, huggingface.co/[datasets|spaces/]<owner>/<name>, else host plus its first two path
    parts: the repository an address belongs to, lowercased."""
    m = re.match(r"https?://(?:www\.)?([^/\s]+)/*([^?#\s]*)", url or "", re.I)
    if not m:
        return None
    host, parts = m.group(1).lower(), [p for p in m.group(2).split("/") if p]
    if host == "huggingface.co" and parts[:1] and parts[0] in ("datasets", "spaces"):
        parts = parts[:3]
    else:
        parts = parts[:2]
    return "/".join([host] + parts).lower()


def normal_title(title):
    return " ".join(re.sub(r"[^\w]+", " ", (title or "").lower()).split())


def canonical_key(title, block):
    """(repository of its first ask or spotted address, normalised title), or None with neither address."""
    urls = ask_urls(block)
    spot = spotted(block)
    url = urls[0] if urls else (spot[0] if spot else None)
    repo = repository(url) if url else None
    title = normal_title(title)
    return (repo, title) if repo and title else None
