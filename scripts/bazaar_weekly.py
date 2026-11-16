#!/usr/bin/env python3
"""Where HivemindOS ranks when an agent shops on the x402 Bazaar, and which of its listed URLs an independent index
already covers (HB-022 and the unpaid HB-033 sweep; block S5 of the Launch-readiness & Trust upgrade, HB-035).

  bazaar_weekly.py [--fixture F] [--out DIR] [--date YYYY-MM-DD]   run the searches and the sweep, write the reports
  bazaar_weekly.py --check-fixture [F]                             the fixture's shape only, no network

A run, all reads, nothing paid and no payment header ever sent:
  1. The listed-URL set: Bazaar's merchant listing for HivemindOS's payTo, kept to the two HivemindOS hosts, and one
     urlSubstring search per host to catch a HivemindOS URL listed under another payTo.
  2. The 20 fixed searches (GET .../discovery/search?query=&network=eip155:8453&limit=20; the parameter is `query`).
     Each records HivemindOS's best rank or `absent`, that resource, its 30-day payers and calls when Bazaar returns
     them (`not-read` when it does not), the #1 result's host and payers, `searchMethod` and the fetch time.
  3. Agents Trust Inspect for every listed URL and the fixture's unlisted control, with no payment header: 402 means
     indexed (the quoted amount, asset and payTo are kept), 404 ENDPOINT_NOT_INDEXED means not indexed, anything else
     after two retries is `not-read`. At most 20 requests in any 60 s, and Retry-After is waited out.

Reports: reports/bazaar-intent-rank/DATE.json + .md and reports/agents-trust-index/DATE.json + .md. Counts, never a
score; vendor scores are not read. Bazaar's payer counts include HivemindOS's own test purchases, so they are never
counted as outside use.

An incomplete run is never published as complete. A search or listing read that is not 200 after two retries stops the
rank board, and a sweep row left `not-read` marks the index board; either is then written as DATE.incomplete.json/.md
and the run exits 1. A complete run also exits 1 when an expected resource is no longer listed, when the control is
listed or indexed, or when a URL indexed last week is not indexed now (the board says which).

The fixture has a second copy in the HivemindOS monorepo, hivemind-cloud-services/workers/platform-api/bazaar/
bazaar-intents.json, whose test pins the same FIXTURE_SHA256; change both together. Python 3 standard library only."""
import argparse, base64, collections, datetime, glob, hashlib, json, os, pathlib, re, sys, time, urllib.error, urllib.parse, urllib.request

FIXTURE_SHA256 = "55e8df2ba83d75d47d8a4cf953dcf7e7f2315d07f6925acef215803461d8ccd6"
FIXTURE = "fixtures/bazaar-intents/bazaar-intents.json"
INTENTS = 20
EXPECTS = ("listed", "unlisted", "out_of_scope")
DATED_NOTE = re.compile(r"^\d{4}-\d{2}-\d{2}: \S")
RETRIES = 2
RETRY_WAIT = (5, 15)
RETRY_AFTER_MAX = 120
USER_AGENT = "bee-self-test-bazaar-weekly/1"
NOT_READ = "not-read"
PAYERS_NOTE = ("Bazaar's 30-day payers and calls are what Bazaar reports; they include HivemindOS's own test purchases, "
               "so they are never counted as outside use.")


class Incomplete(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def host(url):
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except (TypeError, ValueError):
        return ""


# ---- the fixture ----------------------------------------------------------------------------------------------------

def check_fixture(fx, raw=None):
    """Every problem with the fixture's shape, as a list of sentences; empty when it is sound."""
    bad = []
    if raw is not None and hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        bad.append(f"the fixture is not the pinned file (sha256 {hashlib.sha256(raw).hexdigest()})")
    hosts = fx.get("hiveHosts")
    if not isinstance(hosts, list) or not hosts:
        bad.append("hiveHosts is missing")
        hosts = []
    intents = fx.get("intents")
    if not isinstance(intents, list):
        return bad + ["intents is not a list"]
    if len(intents) != INTENTS:
        bad.append(f"{len(intents)} intents, not {INTENTS}")
    ids, queries = set(), set()
    for n, it in enumerate(intents, 1):
        name = it.get("id") or f"intent {n}"
        if not isinstance(it.get("id"), str) or not re.match(r"^[a-z0-9-]{2,40}$", it["id"]):
            bad.append(f"{name}: id must be 2-40 of a-z, 0-9 and -")
        if not isinstance(it.get("query"), str) or not 2 <= len(it["query"]) <= 400:
            bad.append(f"{name}: query must be 2-400 characters")
        if it.get("id") in ids:
            bad.append(f"{name}: id repeated")
        if isinstance(it.get("query"), str) and it["query"].lower() in queries:
            bad.append(f"{name}: query repeated")
        ids.add(it.get("id"))
        queries.add(str(it.get("query")).lower())
        expect = it.get("expect")
        if expect not in EXPECTS:
            bad.append(f"{name}: expect must be one of {', '.join(EXPECTS)}")
        resources = it.get("resources", [])
        if expect == "listed":
            if not resources or not all(isinstance(u, str) and u.startswith("https://") and host(u) in hosts for u in resources):
                bad.append(f"{name}: a listed intent names one or more https resources on hiveHosts")
        elif resources:
            bad.append(f"{name}: only a listed intent names resources")
        if expect == "out_of_scope" and not DATED_NOTE.match(str(it.get("note", ""))):
            bad.append(f"{name}: out_of_scope needs a dated note (YYYY-MM-DD: ...)")
    control = fx.get("control") or {}
    curl = control.get("url")
    if control.get("expect") != "unlisted" or not isinstance(curl, str) or host(curl) not in hosts:
        bad.append("control must be an unlisted https URL on a HivemindOS host")
    elif any(curl in it.get("resources", []) for it in intents):
        bad.append("the control is named as an expected resource")
    for key in ("search", "listed", "inspect"):
        if not isinstance(fx.get(key), dict) or not str(fx[key].get("url", "")).startswith("https://"):
            bad.append(f"{key}.url is missing")
    return bad


def load_fixture(path):
    raw = pathlib.Path(path).read_bytes()
    fx = json.loads(raw)
    bad = check_fixture(fx, raw)
    if bad:
        raise SystemExit("bad fixture:\n  " + "\n  ".join(bad))
    return fx, hashlib.sha256(raw).hexdigest()


# ---- HTTP -----------------------------------------------------------------------------------------------------------

def http_get(url, timeout=40):
    """(status, headers, body bytes). Never sends a payment header."""
    req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(4_000_000)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(4_000_000) if e.fp else b""
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, {}, str(e).encode()


def body_json(body):
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def retry_after(headers):
    try:
        return min(RETRY_AFTER_MAX, max(1, int(float(headers.get("retry-after", "")))))
    except ValueError:
        return None


def get_json_200(get, sleep, url):
    """The JSON of a 200, retried twice (waiting out Retry-After); Incomplete when it never comes."""
    last = None
    for attempt in range(RETRIES + 1):
        status, headers, body = get(url)
        data = body_json(body) if status == 200 else None
        if status == 200 and isinstance(data, dict):
            return data, attempt + 1
        last = f"HTTP {status}" if status else f"no answer ({body[:120].decode('utf-8', 'replace')})"
        if attempt < RETRIES:
            sleep(retry_after(headers) or RETRY_WAIT[attempt])
    raise Incomplete(f"{url}: {last} after {RETRIES} retries")


# ---- 1. the listed-URL set ------------------------------------------------------------------------------------------

def read_listed(fx, get, sleep):
    hosts = set(fx["hiveHosts"])
    listed = fx["listed"]
    found, offset = {}, 0
    for pay_to in listed["payTo"]:
        offset = 0
        while True:
            q = urllib.parse.urlencode({"payTo": pay_to, "limit": 100, "offset": offset})
            data, _ = get_json_200(get, sleep, f"{listed['url']}?{q}")
            page = data.get("resources") or data.get("items") or []
            for r in page:
                url = r.get("resource")
                if isinstance(url, str) and host(url) in hosts:
                    found[url] = r
            total = (data.get("pagination") or {}).get("total")
            offset += len(page)
            if not page or not isinstance(total, int) or offset >= total:
                break
    other = []
    for h in fx["hiveHosts"]:
        q = urllib.parse.urlencode({"urlSubstring": h, "network": fx["search"]["network"], "limit": 20})
        data, _ = get_json_200(get, sleep, f"{fx['search']['url']}?{q}")
        for r in data.get("resources") or []:
            url = r.get("resource")
            if isinstance(url, str) and host(url) in hosts and url not in found:
                other.append(url)
    return found, sorted(set(other))


# ---- 2. the searches ------------------------------------------------------------------------------------------------

def quality(r, key):
    v = (r.get("quality") or {}).get(key) if isinstance(r, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else NOT_READ


def parse_rank(data, hive_hosts, expected=()):
    """One search answer as a board row: HivemindOS's best rank (1-based) or `absent`, and what the answer said."""
    results = data.get("resources")
    if not isinstance(results, list):
        raise Incomplete("the search answer has no resources list")
    hive_hosts = {h.lower() for h in hive_hosts}
    hits = [(n, r) for n, r in enumerate(results, 1) if isinstance(r, dict) and host(r.get("resource")) in hive_hosts]
    best = hits[0] if hits else None
    top = results[0] if results and isinstance(results[0], dict) else None
    return {
        "bestRank": best[0] if best else "absent",
        "resource": best[1].get("resource") if best else None,
        "resourceIsExpected": (best[1].get("resource") in expected) if best else False,
        "expectedFound": sorted({r.get("resource") for _, r in hits if r.get("resource") in expected}),
        "l30DaysUniquePayers": quality(best[1], "l30DaysUniquePayers") if best else None,
        "l30DaysTotalCalls": quality(best[1], "l30DaysTotalCalls") if best else None,
        "hiveHits": [{"rank": n, "resource": r.get("resource")} for n, r in hits],
        "top": {"host": host(top.get("resource")), "resource": top.get("resource"),
                "l30DaysUniquePayers": quality(top, "l30DaysUniquePayers")} if top else None,
        "resultCount": len(results),
        "partialResults": data.get("partialResults") if isinstance(data.get("partialResults"), bool) else NOT_READ,
        "searchMethod": data.get("searchMethod") if isinstance(data.get("searchMethod"), str) else NOT_READ,
    }


def run_searches(fx, get, sleep, listed_urls):
    rows = []
    for it in fx["intents"]:
        q = urllib.parse.urlencode({"query": it["query"], "network": fx["search"]["network"], "limit": fx["search"]["limit"]})
        fetched_at = now()
        data, attempts = get_json_200(get, sleep, f"{fx['search']['url']}?{q}")
        expected = it.get("resources", [])
        row = {"id": it["id"], "query": it["query"], "expect": it["expect"], **parse_rank(data, fx["hiveHosts"], expected),
               "fetchedAt": fetched_at, "attempts": attempts, "flags": []}
        if it.get("note"):
            row["note"] = it["note"]
        gone = [u for u in expected if u not in listed_urls]
        if gone:
            row["flags"].append({"flag": "expected-resource-not-listed", "resources": gone})
        rows.append(row)
        sleep(0.5)
    return rows


# ---- 3. the Agents Trust sweep --------------------------------------------------------------------------------------

def parse_inspect(status, headers, body):
    """One unpaid Inspect answer: indexed (402, with the Base quote), not-indexed (404 ENDPOINT_NOT_INDEXED), or None
    when it says neither (the caller retries, then records `not-read`)."""
    data = body_json(body)
    if status == 402:
        offer = data if isinstance(data, dict) and data.get("accepts") else None
        if offer is None and headers.get("payment-required"):
            try:
                offer = json.loads(base64.b64decode(headers["payment-required"]))
            except (ValueError, TypeError):
                offer = None
        accepts = (offer or {}).get("accepts") or []
        base = next((a for a in accepts if isinstance(a, dict) and a.get("network") == "eip155:8453"), None)
        quote = {"network": "eip155:8453", "amount": base.get("amount"), "asset": base.get("asset"),
                 "payTo": base.get("payTo")} if base else NOT_READ
        return {"status": "indexed", "httpStatus": 402, "quote": quote}
    if status == 404 and isinstance(data, dict) and (data.get("error") or {}).get("code") == "ENDPOINT_NOT_INDEXED":
        return {"status": "not-indexed", "httpStatus": 404, "quote": None}
    return None


class Pace:
    """At most `per_minute` requests in any 60 s window (each counted as a cache miss, since a miss cannot be told
    from a hit before asking)."""

    def __init__(self, per_minute, clock, sleep):
        self.per_minute, self.clock, self.sleep, self.sent = per_minute, clock, sleep, collections.deque()

    def wait(self):
        while self.sent and self.clock() - self.sent[0] >= 60:
            self.sent.popleft()
        if len(self.sent) >= self.per_minute:
            self.sleep(60 - (self.clock() - self.sent[0]) + 0.5)
            return self.wait()
        self.sent.append(self.clock())


def inspect_one(fx, url, get, sleep, pace):
    q = urllib.parse.urlencode({"url": url, "view": fx["inspect"].get("view", "compact")})
    last, waits, attempt = None, 0, 0
    while attempt <= RETRIES:
        pace.wait()
        fetched_at = now()
        status, headers, body = get(f"{fx['inspect']['url']}?{q}")
        row = parse_inspect(status, headers, body)
        if row:
            return {"url": url, "host": host(url), **row, "fetchedAt": fetched_at, "requestId": headers.get("x-at-request-id")}
        data = body_json(body)
        code = (data.get("error") or {}).get("code") if isinstance(data, dict) and isinstance(data.get("error"), dict) else None
        last = f"HTTP {status}" + (f" {code}" if code else "") if status else "no answer"
        wait = retry_after(headers)
        if status == 429 and wait and waits < 5:
            waits += 1
            sleep(wait)
            continue
        attempt += 1
        if attempt <= RETRIES:
            sleep(wait or RETRY_WAIT[attempt - 1])
    return {"url": url, "host": host(url), "status": NOT_READ, "httpStatus": status, "quote": None,
            "reason": f"{last} after {RETRIES} retries", "fetchedAt": fetched_at, "requestId": headers.get("x-at-request-id")}


def previous_index(out_dir, date):
    """The newest complete index board before `date`, or None."""
    paths = sorted(p for p in glob.glob(os.path.join(out_dir, "reports", "agents-trust-index", "*.json"))
                   if re.match(r"^\d{4}-\d{2}-\d{2}\.json$", os.path.basename(p)) and os.path.basename(p)[:10] < date)
    for p in reversed(paths):
        try:
            data = load_json(p)
        except ValueError:
            continue
        if data.get("complete") is True:
            return data
    return None


# ---- the reports ----------------------------------------------------------------------------------------------------

def rank_counts(rows):
    return {
        "intents": len(rows),
        "hiveInTop20": sum(1 for r in rows if r["bestRank"] != "absent"),
        "absent": sum(1 for r in rows if r["bestRank"] == "absent"),
        "listedIntentsRanked": sum(1 for r in rows if r["expect"] == "listed" and r["bestRank"] != "absent"),
        "listedIntents": sum(1 for r in rows if r["expect"] == "listed"),
        "expectedResourceFound": sum(1 for r in rows if r["expectedFound"]),
        "outOfScope": sum(1 for r in rows if r["expect"] == "out_of_scope"),
        "expectedResourceNotListed": sum(1 for r in rows if any(f["flag"] == "expected-resource-not-listed" for f in r["flags"])),
    }


def index_counts(rows):
    c = collections.Counter(r["status"] for r in rows)
    return {"listed": len(rows), "indexed": c["indexed"], "notIndexed": c["not-indexed"], "notRead": c[NOT_READ]}


def cell(v):
    return "—" if v is None else str(v).replace("|", "\\|")


def rank_md(board):
    c = board["counts"]
    head = "# Bazaar intent rank, " + board["date"] + ("" if board["complete"] else " (INCOMPLETE: not a board)")
    lines = [head, ""]
    if not board["complete"]:
        lines += [f"This run stopped: {board['incompleteReason']}. Nothing below counts as this week's board.", ""]
    lines += [
        f"HivemindOS ranks in Bazaar's top {board['search']['limit']} for {c['hiveInTop20']} of {c['intents']} fixed searches "
        f"({c['listedIntentsRanked']} of {c['listedIntents']} intents it has a listing for); an expected resource came up in "
        f"{c['expectedResourceFound']}. {c['outOfScope']} intents are out of scope. Listed URLs: {board['listed']['count']}.",
        "", "Counts, not scores. " + PAYERS_NOTE, "",
        "| # | Intent | Query | Expect | Best rank | HivemindOS resource | Payers 30d | Calls 30d | #1 host | #1 payers | Method | Fetched (UTC) | Flags |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for n, r in enumerate(board["rows"], 1):
        top = r.get("top") or {}
        flags = ", ".join(f["flag"] for f in r["flags"]) or ""
        lines.append(f"| {n} | {r['id']} | {cell(r['query'])} | {r['expect']} | {r['bestRank']} | {cell(r['resource'])} | "
                     f"{cell(r['l30DaysUniquePayers'])} | {cell(r['l30DaysTotalCalls'])} | {cell(top.get('host'))} | "
                     f"{cell(top.get('l30DaysUniquePayers'))} | {r['searchMethod']} | {r['fetchedAt']} | {flags} |")
    notes = [f"- {r['id']}: {r['note']}" for r in board["rows"] if r.get("note")]
    if notes:
        lines += ["", "Notes:", *notes]
    if board["listed"].get("otherPayTo"):
        lines += ["", "Listed under another payTo: " + ", ".join(board["listed"]["otherPayTo"])]
    return "\n".join(lines) + "\n"


def index_md(board):
    c = board["counts"]
    head = "# Agents Trust index, " + board["date"] + ("" if board["complete"] else " (INCOMPLETE: not a board)")
    ctl = board["control"]
    lines = [head, "",
             f"Of {c['listed']} URLs HivemindOS has listed on the Bazaar, Agents Trust has indexed {c['indexed']}; "
             f"{c['notIndexed']} are not indexed and {c['notRead']} could not be read. Read with no payment header; nothing was paid.",
             "", f"Control (deliberately unlisted): {ctl['url']} answered {ctl['status']} ({'as expected' if ctl['ok'] else 'NOT as expected'}).",
             ""]
    if board["flags"]:
        lines += ["Flags:", *[f"- {f['flag']}: {f.get('url', '')}" for f in board["flags"]], ""]
    lines += ["| # | URL | Status | Quoted amount (atomic) | Asset | payTo | Fetched (UTC) |", "|---|---|---|---|---|---|---|"]
    for n, r in enumerate(board["rows"], 1):
        q = r["quote"] if isinstance(r["quote"], dict) else {}
        status = r["status"] + (f" ({r['reason']})" if r.get("reason") else "")
        lines.append(f"| {n} | {r['url']} | {cell(status)} | {cell(q.get('amount') if q else r['quote'])} | {cell(q.get('asset'))} | "
                     f"{cell(q.get('payTo'))} | {r['fetchedAt']} |")
    return "\n".join(lines) + "\n"


def write(out_dir, kind, date, board, md):
    folder = os.path.join(out_dir, "reports", kind)
    os.makedirs(folder, exist_ok=True)
    stem = date if board["complete"] else f"{date}.incomplete"
    with open(os.path.join(folder, stem + ".json"), "w") as f:
        json.dump(board, f, indent=2)
        f.write("\n")
    with open(os.path.join(folder, stem + ".md"), "w") as f:
        f.write(md)
    return os.path.join(folder, stem + ".json")


def run(fx, fixture_sha, out_dir, date, get=http_get, sleep=time.sleep, clock=time.monotonic, fixture_path=FIXTURE):
    started = now()
    base = {"date": date, "startedAt": started, "fixture": {"path": fixture_path, "sha256": fixture_sha, "intents": len(fx["intents"])},
            "hiveHosts": fx["hiveHosts"], "paid": False}
    problems = []
    listed, other, rows, incomplete = {}, [], [], None
    try:
        listed, other = read_listed(fx, get, sleep)
        rows = run_searches(fx, get, sleep, set(listed))
    except Incomplete as e:
        incomplete = str(e)
    rank = {"schema": "hive.bazaar-intent-rank.v1", **base, "complete": incomplete is None, "finishedAt": now(),
            "search": fx["search"], "listed": {"url": fx["listed"]["url"], "payTo": fx["listed"]["payTo"], "count": len(listed),
                                               "otherPayTo": other},
            "counts": rank_counts(rows), "rows": rows, "notes": [PAYERS_NOTE]}
    if incomplete:
        rank["incompleteReason"] = incomplete
        problems.append(f"rank board incomplete: {incomplete}")
    problems += [f"{r['id']}: expected resource no longer listed: {', '.join(f['resources'])}"
                 for r in rows for f in r["flags"] if f["flag"] == "expected-resource-not-listed"]
    written = [write(out_dir, "bazaar-intent-rank", date, rank, rank_md(rank))]

    if not listed:
        problems.append("index board not run: no listed-URL set was read")
        return problems, written
    pace = Pace(int(fx["inspect"].get("missesPerMinute", 20)), clock, sleep)
    sweep = [inspect_one(fx, u, get, sleep, pace) for u in sorted(listed)]
    control = inspect_one(fx, fx["control"]["url"], get, sleep, pace)
    control_ok = control["status"] == "not-indexed" and fx["control"]["url"] not in listed
    flags = []
    if not control_ok:
        flags.append({"flag": "control-not-as-expected", "url": fx["control"]["url"], "status": control["status"],
                      "listed": fx["control"]["url"] in listed})
    before = previous_index(out_dir, date)
    if before:
        was = {r["url"] for r in before.get("rows", []) if r.get("status") == "indexed"}
        flags += [{"flag": "was-indexed-now-not-indexed", "url": r["url"], "since": before.get("date")}
                  for r in sweep if r["status"] == "not-indexed" and r["url"] in was]
    not_read = [r["url"] for r in sweep if r["status"] == NOT_READ] + ([control["url"]] if control["status"] == NOT_READ else [])
    index = {"schema": "hive.agents-trust-index.v1", **base, "complete": not not_read, "finishedAt": now(),
             "inspect": {"url": fx["inspect"]["url"], "view": fx["inspect"].get("view", "compact"), "paymentHeader": False},
             "counts": index_counts(sweep), "control": {**control, "ok": control_ok}, "flags": flags, "rows": sweep,
             "previous": before.get("date") if before else None}
    if not_read:
        index["incompleteReason"] = f"{len(not_read)} URL(s) not read after {RETRIES} retries"
        problems.append(f"index board incomplete: {index['incompleteReason']}")
    problems += [f"{f['flag']}: {f['url']}" for f in flags]
    written.append(write(out_dir, "agents-trust-index", date, index, index_md(index)))
    return problems, written


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fixture", default=FIXTURE)
    p.add_argument("--out", default=".")
    p.add_argument("--date", default=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))
    p.add_argument("--check-fixture", nargs="?", const=True, default=False)
    a = p.parse_args(argv)
    if a.check_fixture:
        path = a.check_fixture if isinstance(a.check_fixture, str) else a.fixture
        fx, sha = load_fixture(path)
        print(f"fixture ok: {len(fx['intents'])} intents, control {fx['control']['url']}, sha256 {sha}")
        return 0
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", a.date):
        raise SystemExit("--date is YYYY-MM-DD")
    fx, sha = load_fixture(a.fixture)
    problems, written = run(fx, sha, a.out, a.date, fixture_path=a.fixture)
    for path in written:
        d = load_json(path)
        print(json.dumps({"report": path, "complete": d["complete"], "counts": d["counts"]}))
    for line in problems:
        print("FAIL " + line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
