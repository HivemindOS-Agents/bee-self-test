#!/usr/bin/env python3
"""Feed freshness by content, never by build stamp (25 Nov 2026 dev update, row 102, guard 263; it replaces 24 Nov
§26's rule, guard 26, which read `generatedAt`).

A feed is current only while its newest CONTENT timestamp is at most 48 hours old: the top-level `updatedAt`, or the
newest `updatedAt` or `startedAt` of any item in any top-level list. `generatedAt` and other build stamps are never
read as freshness: pwn.watch was rebuilt on 25 Nov (generatedAt 2026-11-25) while its updatedAt and newest of 960
incidents were still 2026-11-10T01:13:32Z, about 15 days old. A feed with no content timestamp at all is
`no_content_time`, a coverage limit, never current.

When a feed that was stale reads current again (it caught up), it is diffed against the 30-day backfill window: every
backfill entry dated in the last 30 days that no item of the feed matches (a shared CVE or GHSA id, the same address,
or every word of four or more letters of its title) is a gap, to be queued. A caught-up feed with no backfill to diff
against is itself a problem. Report-level: the live read never blocks an agent.

    python3 scripts/feed_freshness.py URL_OR_FILE... [--now ISO] [--state FILE] [--backfill FILE] [--name NAME]
    python3 scripts/feed_freshness.py --self-test

--state keeps each feed's last state between runs (a JSON object keyed by URL or file name, or --name); --backfill is
a JSON list of {title, date, source, ids?, url?}. A feed that is supplied but empty or does not parse stops with
empty_security_setting or unparseable_security_setting (exit 2, scripts/security_input.py). Exit 0 when every feed
is current and nothing caught up undiffed or with gaps, 1 otherwise.
"""
import datetime
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_input as si  # noqa: E402

MAX_AGE_HOURS = 48
BACKFILL_DAYS = 30
CONTENT_KEYS = ("updatedAt", "startedAt")
UA = "bee-self-test-feed-freshness (read-only; https://hivemindos.app)"


def parse_time(value):
    """An ISO 8601 time or date as an aware UTC datetime, or None."""
    if not isinstance(value, str):
        return None
    m = re.match(r"^(\d{4}-\d\d-\d\d)(?:[T ](\d\d:\d\d(?::\d\d)?)(\.\d+)?(Z|[+-]\d\d:?\d\d)?)?$", value.strip())
    if not m:
        return None
    clock = m.group(2) or "00:00:00"
    if len(clock) == 5:
        clock += ":00"
    zone = m.group(4) or "Z"
    zone = "+00:00" if zone == "Z" else (zone if ":" in zone else zone[:3] + ":" + zone[3:])
    try:
        return datetime.datetime.fromisoformat(f"{m.group(1)}T{clock}{zone}").astimezone(datetime.timezone.utc)
    except ValueError:
        return None


def iso(at):
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def content_times(feed):
    """Every content timestamp in the feed: its top-level updatedAt and each list item's updatedAt and startedAt."""
    out = []
    if isinstance(feed, dict):
        top = parse_time(feed.get("updatedAt"))
        if top:
            out.append(top)
        for value in feed.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        out += [t for t in (parse_time(item.get(k)) for k in CONTENT_KEYS) if t]
    return out


def freshness(feed, now, max_age_hours=MAX_AGE_HOURS):
    """{state: current | stale | no_content_time, newest, ageHours, generatedAt}. generatedAt is said, never used."""
    now = parse_time(now) if isinstance(now, str) else now
    times = content_times(feed)
    generated = feed.get("generatedAt") if isinstance(feed, dict) else None
    if not times:
        return {"state": "no_content_time", "newest": None, "ageHours": None, "generatedAt": generated}
    newest = max(times)
    age = (now - newest).total_seconds() / 3600
    return {"state": "current" if age <= max_age_hours else "stale", "newest": iso(newest), "ageHours": round(age, 1), "generatedAt": generated}


def is_current(feed, now):
    return freshness(feed, now)["state"] == "current"


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) >= 4}


def matches(entry, item):
    ids = {str(i).upper() for i in entry.get("ids") or []}
    text = json.dumps(item, ensure_ascii=False)
    if ids and any(i in text.upper() for i in ids):
        return True
    if entry.get("url") and entry["url"] in (item.get("url"), item.get("sourceUrl"), item.get("external_url")):
        return True
    words = _words(entry.get("title"))
    have = _words(" ".join(str(item.get(k) or "") for k in ("title", "slug", "product", "summary")))
    return bool(words) and words <= have


def items_of(feed):
    return [i for v in (feed.values() if isinstance(feed, dict) else []) if isinstance(v, list) for i in v if isinstance(i, dict)]


def catch_up(previous, feed, backfill, now, window_days=BACKFILL_DAYS):
    """previous: the feed's last state ({state}) or None. {caughtUp, diffed, gaps, problems}."""
    now_at = parse_time(now) if isinstance(now, str) else now
    caught = bool(previous) and previous.get("state") in ("stale", "no_content_time") and freshness(feed, now_at)["state"] == "current"
    out = {"caughtUp": caught, "diffed": False, "gaps": [], "problems": []}
    if not caught:
        return out
    if backfill is None:
        out["problems"].append(f"caught up, not diffed against the {window_days}-day backfill: no backfill was given")
        return out
    since = now_at - datetime.timedelta(days=window_days)
    items = items_of(feed)
    for entry in backfill:
        at = parse_time(entry.get("date"))
        if at is None or at < since:
            continue
        if not any(matches(entry, item) for item in items):
            out["gaps"].append(entry)
    out["diffed"] = True
    if out["gaps"]:
        out["problems"].append(f"caught up with {len(out['gaps'])} gap(s) in the {window_days}-day backfill: queue them")
    return out


def read_feed(source):
    if re.match(r"^https?://", source):
        try:
            with urllib.request.urlopen(urllib.request.Request(source, headers={"User-Agent": UA}), timeout=30) as r:
                text = r.read().decode("utf-8", "replace")
        except OSError as error:
            raise si.Stop(si.EMPTY, source, f"could not be read: {error}")
        return si.parse_json(source, text, want=dict)
    return si.read_json(source, want=dict)


def main(argv):
    if argv[:1] == ["--self-test"]:
        import unittest
        suite = unittest.defaultTestLoader.discover(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"), pattern="test_feed_freshness.py")
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    opts, sources, i = {}, [], 0
    while i < len(argv):
        if argv[i] in ("--now", "--state", "--backfill", "--name"):
            if i + 1 >= len(argv):
                print(si.Stop(si.EMPTY, argv[i], "supplied but empty").line(), file=sys.stderr)
                return si.EXIT_STOP
            opts[argv[i]] = argv[i + 1]
            i += 2
        else:
            sources.append(argv[i])
            i += 1
    if not sources:
        print(__doc__)
        return si.EXIT_STOP
    now = parse_time(opts.get("--now")) if opts.get("--now") else datetime.datetime.now(datetime.timezone.utc)
    try:
        state = si.read_json(opts["--state"], default={}, why="no earlier run") if opts.get("--state") else {}
        backfill = si.read_json(opts["--backfill"], want=list) if opts.get("--backfill") else None
    except si.Stop as stop:
        print(stop.line(), file=sys.stderr)
        return si.EXIT_STOP
    bad = stopped = 0
    for source in sources:
        name = opts.get("--name") if len(sources) == 1 and opts.get("--name") else os.path.basename(source) if not source.startswith("http") else source
        try:
            feed = read_feed(source)
        except si.Stop as stop:
            print(stop.line(), file=sys.stderr)
            stopped += 1
            continue
        got = freshness(feed, now)
        up = catch_up(state.get(name), feed, backfill, now)
        print(f"{name}: {got['state']} (newest content {got['newest'] or 'none'}, {got['ageHours']} h old; generatedAt {got['generatedAt'] or 'none'}, not read)")
        if up["caughtUp"]:
            print(f"{name}: caught up since the last run" + (f"; {len(up['gaps'])} gap(s) in the backfill window" if up["diffed"] else ""))
            for gap in up["gaps"]:
                print(f"  gap: {gap.get('date')} {gap.get('title')} ({gap.get('source', '?')})")
        for problem in up["problems"]:
            print(f"{name}: {problem}")
        bad += got["state"] != "current" or bool(up["problems"])
        state[name] = {"state": got["state"], "newest": got["newest"], "at": iso(now)}
    if opts.get("--state"):
        with open(opts["--state"], "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=1, sort_keys=True)
    if stopped:
        return si.EXIT_STOP
    print("feed freshness:", "PASS" if not bad else f"FAIL ({bad} feed(s) stale, without a content time, or caught up undiffed or with gaps)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
