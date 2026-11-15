#!/usr/bin/env python3
"""Re-checks every source of a HivemindOS agent's research receipt and says whether each is still what the agent read
(Based Elnen's proof and trust pack, 2026-11-14, item 1). A receipt (research/<date>-<slug>.json in the agent's
repository) written since 2026-11-15 says "sourceFormat": "record-v1": each page it read has a record with the url,
when it was read, the sha256 of the text it extracted, and a passage (`quote`); each FACT cites a record by `sourceId`
with the passage it rests on.

  verify_sources.py RECEIPT [--json OUT]      RECEIPT is a path or an https URL on github.com/githubusercontent.com
  verify_sources.py --fixtures DIR            the shared cases (DIR/cases.json), with no network

Each page is fetched once, and each passage is looked for in its words (lower case, entities and everything but a-z and
0-9 out; nav, header, footer, noscript, svg, form, scripts and styles stripped, as the agent's reader strips them), so
a page whose menu or date changed still matches while the passage is there:

  MATCH    the passage is still on the page
  CHANGED  the page answers, and the passage is no longer on it
  GONE     the page answered 404 or 410
  UNABLE   it could not be checked: the page could not be fetched or answered another error, an API answer (checked by
           its field, which this version does not do), or a source recorded before passages were. Never a pass.

Exit 0 only if every source and every cited passage is MATCH; 1 if any is CHANGED or GONE; 2 otherwise.

The agents service's copy of these rules is hivemind-os/src/shared/hive/core/agent-source-record.ts
(agentSourceWords, AGENT_SOURCE_STRIP, agentSourceRecheck, AGENT_SOURCE_CASES). fixtures/verify-sources/cases.json is
its cases; CASES_SHA256 below and the same hash in that file's test both change when the cases do."""
import hashlib, json, pathlib, re, sys, urllib.error, urllib.request

CASES_SHA256 = "c0604f0b8f97c2a445208b3e9302ea0aea5d2c51ccebf103639ace9cf10e6337"
URL = re.compile(r"^https://(?:github\.com|raw\.githubusercontent\.com)/[^\s\"<>]{1,300}$")
BLOB = re.compile(r"^https://github\.com/([^/]+/[^/]+)/blob/(.+)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CHROME = re.compile(r"<(nav|header|footer|noscript|svg|form)\b[\s\S]*?</\1\s*>", re.I)
BLOCKS = re.compile(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", re.I)
TAGS = re.compile(r"<[^>]+>")
PAGE_MAX = 2_000_000

class Unable(Exception):
    pass

def words(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", re.sub(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", " ", text.lower())).strip()

def html_words(html: str) -> str:
    # The same stripping, in the same order, as the agent's reader: chrome, then scripts and styles, then tags.
    return words(TAGS.sub(" ", BLOCKS.sub(" ", CHROME.sub(" ", html))))

def recheck(quote, fresh):
    """One passage against what was fetched now: (result, why). `fresh` is {"status", "body"} or None."""
    if not quote:
        return "UNABLE", "It holds no passage to look for (a source recorded before passages were)."
    if fresh is None:
        return "UNABLE", "The page could not be fetched."
    status = fresh["status"]
    if status in (404, 410):
        return "GONE", f"The page answered {status}."
    if status < 200 or status >= 300:
        return "UNABLE", f"The page answered {status}."
    if f" {words(quote)} " in f" {html_words(fresh['body'])} ":
        return "MATCH", "The passage is still on the page."
    return "CHANGED", "The passage is no longer on the page."

def fetch(url: str):
    if not url.startswith("https://"):
        return None
    request = urllib.request.Request(url, headers={"user-agent": "bee-self-test-verify-sources", "accept": "text/html,text/plain;q=0.9"})
    try:
        with urllib.request.urlopen(request, timeout=20) as answer:
            return {"status": answer.status, "body": answer.read(PAGE_MAX).decode("utf-8", "replace")}
    except urllib.error.HTTPError as error:
        return {"status": error.code, "body": ""}
    except Exception:
        return None

def load(where: str) -> dict:
    if where.startswith("https://"):
        if not URL.match(where):
            raise Unable("a receipt is read only from github.com or raw.githubusercontent.com")
        blob = BLOB.match(where)
        url = f"https://raw.githubusercontent.com/{blob.group(1)}/{blob.group(2)}" if blob else where
        fresh = fetch(url)
        if not fresh or fresh["status"] != 200:
            raise Unable("the receipt could not be read")
        text = fresh["body"]
    else:
        text = pathlib.Path(where).read_text(encoding="utf-8")
    try:
        receipt = json.loads(text)
    except ValueError:
        raise Unable("the receipt is not JSON")
    if not isinstance(receipt, dict) or receipt.get("kind") != "research-receipt" or not isinstance(receipt.get("sources"), list):
        raise Unable("not a research receipt")
    return receipt

def quote_ok(item: dict) -> bool:
    quote, digest = item.get("quote"), item.get("quoteSha256")
    return isinstance(quote, str) and isinstance(digest, str) and SHA256.match(digest) is not None \
        and hashlib.sha256(words(quote).encode("utf-8")).hexdigest() == digest

def verify(receipt: dict, get=fetch) -> list[dict]:
    rows, pages = [], {}
    records = {s.get("id"): s for s in receipt["sources"] if isinstance(s, dict) and isinstance(s.get("id"), str)}
    def page(url):
        if url not in pages:
            pages[url] = get(url)
        return pages[url]
    for source in receipt["sources"]:
        if not isinstance(source, dict):
            continue
        name, url = source.get("id") or "-", str(source.get("url") or "")
        if receipt.get("sourceFormat") != "record-v1" or source.get("type") is None:
            result, why = "UNABLE", "A legacy source: a title and a url, with no hash or passage."
        elif source.get("type") == "api":
            result, why = "UNABLE", "An API answer is re-checked by the field a claim cites, which this version does not do."
        elif source.get("type") != "url":
            result, why = "UNABLE", f"A {source.get('type')} source is not checked by this version."
        elif source.get("quote") is not None and not quote_ok(source):
            result, why = "UNABLE", "Its passage's hash does not match its words."
        else:
            result, why = recheck(source.get("quote"), page(url))
        rows.append({"what": "source", "id": name, "url": url, "result": result, "why": why})
    for claim in receipt.get("claims") or []:
        if not isinstance(claim, dict) or claim.get("label") != "FACT" or not claim.get("quote"):
            continue
        record = records.get(claim.get("sourceId"))
        if not record or record.get("type") != "url":
            result, why, url = "UNABLE", "It cites no page record of this receipt.", ""
        elif not quote_ok(claim):
            result, why, url = "UNABLE", "Its passage's hash does not match its words.", str(record.get("url"))
        else:
            url = str(record.get("url"))
            result, why = recheck(claim["quote"], page(url))
        rows.append({"what": "claim", "id": str(claim.get("id")), "url": url, "result": result, "why": why})
    return rows

def exit_code(rows: list[dict]) -> int:
    results = {r["result"] for r in rows}
    if results <= {"MATCH"} and rows:
        return 0
    return 1 if results & {"CHANGED", "GONE"} else 2

def fixtures(folder: str) -> int:
    raw = pathlib.Path(folder, "cases.json").read_text(encoding="utf-8")
    cases = json.loads(raw)
    compact = json.dumps(cases, separators=(",", ":"), ensure_ascii=False)
    if hashlib.sha256(compact.encode("utf-8")).hexdigest() != CASES_SHA256:
        print("cases.json is not the agents service's AGENT_SOURCE_CASES (its hash changed): copy them again and update CASES_SHA256")
        return 1
    failed = 0
    for case in cases:
        result, _ = recheck(case["quote"], case["fresh"])
        ok = result == case["result"]
        failed += not ok
        print(f"{'ok' if ok else 'FAILED'}  {case['name']}: {result}" + ("" if ok else f" (expected {case['result']})"))
    # The receipt fixture: one page that still holds its passage, one whose passage is gone, one gone, an API answer.
    receipt = json.loads(pathlib.Path(folder, "receipt.json").read_text(encoding="utf-8"))
    served = json.loads(pathlib.Path(folder, "pages.json").read_text(encoding="utf-8"))
    rows = verify(receipt, get=lambda url: served.get(url))
    expected = json.loads(pathlib.Path(folder, "expected.json").read_text(encoding="utf-8"))
    got = [[r["what"], r["id"], r["result"]] for r in rows]
    ok = got == expected and exit_code(rows) == 1
    failed += not ok
    print(f"{'ok' if ok else 'FAILED'}  receipt fixture: {got}")
    return 1 if failed else 0

def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--fixtures":
        return fixtures(argv[1])
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    out = argv[argv.index("--json") + 1] if "--json" in argv[1:-1] else None
    try:
        receipt = load(argv[0])
    except Unable as why:
        print(f"UNABLE  {why}")
        return 2
    rows = verify(receipt)
    for r in rows:
        print(f"{r['result']:<8} {r['what']:<6} {r['id']:<7} {r['url']}\n         {r['why']}")
    code = exit_code(rows)
    summary = {"v": 1, "kind": "source-recheck", "receipt": argv[0], "results": rows, "exit": code}
    if out:
        pathlib.Path(out).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return code

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
