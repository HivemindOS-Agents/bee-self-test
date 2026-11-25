#!/usr/bin/env python3
"""Guard 135 (24 Nov 2026 dev update, §45.7; 25 Nov row 41r3): x402 encoded paths.

For every keyless paid x402 operation in HivemindOS's openapi.json, an unpaid request with an encoded path variant
must never return 2xx. The variants encode the operation's last path separator as %2F, %2f, %5C, %5c and %252F
(double-encoded), next to the plain path: 6 requests an operation. Fixture class: x402 issue #3850, where the paywall
decoded the path and the router used the raw one, so a parameterised route was served without payment.

An operation is keyless and paid when its security is [] (no key) and it carries `x-payment-info` with an x402
protocol, or sits under /x402/ and lists a 402 answer. A templated path (/x402/{serviceId}/{operationId}) is covered
by its concrete listings and is counted, not probed.

The live read stays under the 40-requests-a-host daily ceiling (HB-083r2): at most 6 operations a run. Operations not
probed before go first, so a paid route the openapi.json adds is probed on the next run (--state keeps which were
probed); with none new, one operation a day is probed again, in turn. Requests carry no payment and no key, an empty
JSON body, and follow no redirect.

    python3 scripts/x402_encoded_paths.py --self-test        # the fixtures, no network
    python3 scripts/x402_encoded_paths.py [--openapi URL_OR_FILE] [--state FILE]

Exit 2 when any variant returned 2xx (a bypass) or the openapi.json stopped the run (empty, unparseable, or no keyless
paid operation), 1 when a request could not be read, 0 when every request was refused.
"""
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_input as si  # noqa: E402

OPENAPI = "https://api.hivemindos.app/openapi.json"
UA = "bee-self-test-x402-encoded-paths (unpaid, no key; guard 135; https://hivemindos.app)"
HOST_CAP = 40
ENCODINGS = ("%2F", "%2f", "%5C", "%5c", "%252F")


def paid_operations(openapi, source="openapi.json"):
    """[{method, path, templated}] for every keyless paid x402 operation, paths with the server's path prefix, sorted."""
    paths = si.field(source, openapi, "paths", dict)
    servers = openapi.get("servers") or [{"url": ""}]
    prefix = urllib.parse.urlsplit(servers[0].get("url", "")).path.rstrip("/")
    top = openapi.get("security")
    out = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            keyless = op.get("security", top) == []
            info = op.get("x-payment-info") or {}
            x402 = any("x402" in p for p in info.get("protocols") or [] if isinstance(p, dict))
            if keyless and (x402 or (path.startswith("/x402/") and "402" in (op.get("responses") or {}))):
                out.append({"method": method.lower(), "path": prefix + path, "templated": "{" in path})
    if not out:
        raise si.Stop(si.EMPTY, source, "no keyless paid x402 operation: nothing to check is not a pass")
    return sorted(out, key=lambda o: (o["templated"], o["path"], o["method"]))


def variants(path):
    """The plain path and its encoded variants, the last separator encoded each way."""
    head, _, tail = path.rpartition("/")
    return [path] + [f"{head}{enc}{tail}" for enc in ENCODINGS]


def key(op):
    return f"{op['method']} {op['path']}"


def pick(ops, seen, cap_requests=HOST_CAP, day=None):
    """The operations this run probes: those not probed before first, up to the cap; with none new, one in turn."""
    concrete = [o for o in ops if not o["templated"]]
    room = max(1, cap_requests // (len(ENCODINGS) + 1))
    new = [o for o in concrete if key(o) not in seen]
    if new:
        return new[:room]
    if not concrete:
        return []
    day = datetime.datetime.now(datetime.timezone.utc).timetuple().tm_yday if day is None else day
    return [concrete[day % len(concrete)]]


def probe(ops, base, send):
    """send(method, url) -> HTTP status or None. {requests, bypass, notRead, answers}."""
    report = {"requests": 0, "bypass": [], "notRead": [], "answers": {}}
    for op in ops:
        for path in variants(op["path"]):
            status = send(op["method"], base.rstrip("/") + path)
            report["requests"] += 1
            report["answers"][f"{op['method']} {path}"] = status
            if status is None:
                report["notRead"].append({"method": op["method"], "path": path})
            elif 200 <= status < 300:
                report["bypass"].append({"method": op["method"], "path": path, "status": status})
    return report


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send_live(method, url):
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, data=b"{}" if method != "get" else None, method=method.upper(),
                                     headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        with opener.open(request, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as error:
        return error.code
    except (OSError, ValueError):
        return None


def run(openapi, base, send, state_path=None, day=None, source="openapi.json"):
    ops = paid_operations(openapi, source)
    state = si.read_json(state_path, default={}, why="no earlier run") if state_path else {}
    seen = set(state.get("probed") or [])
    picked = pick(ops, seen, day=day)
    report = probe(picked, base, send)
    for op in picked:
        if not any(n["path"] in variants(op["path"]) and n["method"] == op["method"] for n in report["notRead"]):
            seen.add(key(op))
    templated = [o for o in ops if o["templated"]]
    concrete = [o for o in ops if not o["templated"]]
    print(f"guard 135: {len(concrete)} keyless paid x402 operations ({len(templated)} templated, covered by their listings); "
          f"{len(picked)} probed this run, {report['requests']} unpaid requests; {len(seen & {key(o) for o in concrete})} of {len(concrete)} probed so far")
    for answer, status in sorted(report["answers"].items()):
        print(f"  {status if status is not None else 'NOT_READ'} {answer}")
    for b in report["bypass"]:
        print(f"BYPASS {b['method'].upper()} {b['path']} answered {b['status']} with no payment")
    if state_path:
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump({"probed": sorted(seen)}, handle, indent=1)
    if report["bypass"]:
        return 2
    return 1 if report["notRead"] else 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        import unittest
        suite = unittest.defaultTestLoader.discover(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"), pattern="test_x402_encoded_paths.py")
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    opts = dict(zip(argv[::2], argv[1::2]))
    source = opts.get("--openapi", OPENAPI)
    try:
        if re.match(r"^https?://", source):
            try:
                with urllib.request.urlopen(urllib.request.Request(source, headers={"User-Agent": UA}), timeout=30) as r:
                    text = r.read().decode("utf-8", "replace")
            except OSError as error:
                raise si.Stop(si.EMPTY, source, f"could not be read: {error}")
            openapi = si.parse_json(source, text)
        else:
            openapi = si.read_json(source)
        servers = openapi.get("servers") or [{"url": "https://api.hivemindos.app"}]
        parts = urllib.parse.urlsplit(servers[0]["url"])
        return run(openapi, f"{parts.scheme}://{parts.netloc}", send_live, opts.get("--state"), source=source)
    except si.Stop as stop:
        print(stop.line(), file=sys.stderr)
        return si.EXIT_STOP


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
