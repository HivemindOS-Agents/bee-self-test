#!/usr/bin/env python3
"""B-59 / HB-021: a signed Twigpine mirror of the agent repositories. GitHub stays canonical; Twigpine is a second,
checkable copy of `main` that keeps running during a GitHub pause.

  twigpine_mirror.py --self-test                     Ed25519, did:key and certificate checks on fixtures, no network
  twigpine_mirror.py --check-fixture [F]             the mirror list's shape: one did:key per repository, none shared
  twigpine_mirror.py gate [--out FILE]               read-only owner-only push gate, per repository
  twigpine_mirror.py check [--out DIR] [--expect-live]
                                                     read-only: GitHub `main` against the latest Twigpine certificate,
                                                     each certificate's signature checked against the pinned node DID
  twigpine_mirror.py push --repo NAME [--out DIR]    push GitHub `main` to Twigpine and write its receipt
  twigpine_mirror.py bootstrap --repo NAME [--yes]   once per repository: register, create, protect `main`
  twigpine_mirror.py keys [--fixture F]              make the missing per-repository did:key seeds in PassBook

What Twigpine is (read 28 Nov 2026): a git network whose identities are Ed25519 `did:key` keypairs. A push is an
RFC 9421 HTTP-signed `git-receive-pack`; the node then signs a ref certificate (repo_id, ref, old, new, pusher, node,
ts) with its own key. There are no accounts or plans; registering an identity and creating a repository pass an
iCaptcha challenge that `gl` solves.

The owner-only gate. Node v0.8.0 (18 Nov 2026) made TWIGPINE_ENFORCE_OWNER_PUSH default to true, but an operator can
turn it off and no public endpoint says which way it is set. A protected branch, though, is refused to every pusher
that is not the repository owner, whatever that setting and whatever UCAN delegation is presented
(crates/twigpine-node/src/api/repos.rs, git_receive_pack, at v0.8.1), and the protected list is public
(GET /api/v1/repos/<did>/<repo>/branches/protected). So the gate does not trust the operator: a repository passes only
when its `main` is protected, and `push` refuses to run when it is not. No Hive-run node is needed.

Keys. One Ed25519 seed per repository, never shared, never written to a file but the 0600 identity PEM that a push
lives with for its own run and then overwrites. Its master copy is in PassBook (TWIGPINE_SEED_<REPO>); the workflow
gets each one from the `twigpine-mirror` environment, one secret per matrix leg. `push` refuses a seed whose did:key
is not the one this repository's list names, so a swapped secret cannot push another repository.

Receipts. Each push writes hive.twigpine-mirror-receipt.v1: the GitHub SHA, the certificate's id, old/new SHA,
pusher, node, time and signature, whether the signature checked, and links to the certificate and explorer page. The
workflow records it as results/<repo>/twigpine-mirror.json (the latest) and appends it to
results/<repo>/twigpine-mirror.jsonl. Nothing is ever committed to an agent repository's `main` (a receipt there would
change the SHA it certifies).

Inert until switched on: `push` and `bootstrap` refuse to run unless TWIGPINE_MIRROR=on.

Exit 0: all hold. 1: one does not. 2: something could not be read, or a refusal (never a pass). Python 3 standard
library only.
"""
import argparse, base64, datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.error, \
    urllib.parse, urllib.request

FIXTURE = "fixtures/twigpine-mirror/mirrors.json"
RECEIPT_SCHEMA = "hive.twigpine-mirror-receipt.v1"
GATE_SCHEMA = "hive.twigpine-mirror-gate.v1"
CHECK_SCHEMA = "hive.twigpine-mirror-check.v1"
USER_AGENT = "bee-self-test-twigpine-mirror/1 (read-only reads; https://hivemindos.app)"
NOT_READ = "not-read"
OWNER_PUSH_DEFAULT_SINCE = (0, 8, 0)
SWITCH = "TWIGPINE_MIRROR"
NAME = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
SEED_NAME = re.compile(r"^TWIGPINE_SEED_[A-Z0-9_]+$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
EXIT_OK, EXIT_FAIL, EXIT_STOP = 0, 1, 2


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- Ed25519 (RFC 8032 section 6, verification and public-key derivation only) ----------------------------------------

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(pt):
    zinv = _inv(pt[2])
    x, y = pt[0] * zinv % _P, pt[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_public(seed):
    """The 32-byte public key of a 32-byte Ed25519 seed."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, _G))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


# ---- did:key (multibase base58btc, multicodec ed25519-pub 0xed 0x01) ---------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB = b"\xed\x01"


def b58encode(data):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text):
    n = 0
    for ch in text:
        i = _B58.find(ch)
        if i < 0:
            raise ValueError("not base58btc")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def did_from_public(public):
    return "did:key:z" + b58encode(_ED25519_PUB + public)


def public_from_did(did):
    """The Ed25519 public key a did:key names; ValueError for anything else."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] != _ED25519_PUB or len(raw) != 34:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]


def owner_key(did):
    """The bare z6Mk... form Twigpine uses in remote URLs and explorer paths."""
    return did[len("did:key:"):]


def seed_pem(seed):
    """PKCS#8 v1 PEM of an Ed25519 seed (RFC 8410), the format `gl identity new` writes and the helper reads."""
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    b64 = base64.b64encode(der).decode()
    return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n"


def decode_seed(text):
    text = (text or "").strip()
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(raw) != 32:
        raise ValueError("a seed is 32 bytes")
    return raw


# ---- ref certificates ---------------------------------------------------------------------------------------------------

def cert_payload(cert):
    """The exact bytes a v0.8 node signs: v1_signing_payload in crates/twigpine-node/src/cert.rs, a serde_json Value
    serialized with sorted keys and no whitespace."""
    return json.dumps({"repo_id": cert["repo_id"], "ref": cert["ref_name"], "old": cert["old_sha"],
                       "new": cert["new_sha"], "pusher": cert["pusher_did"], "node": cert["node_did"],
                       "ts": cert["issued_at"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify_cert(cert, node_did):
    """Why a certificate does not hold, as a sentence; None when it does. The node DID is the pinned one, never the
    certificate's own claim (gl 0.8 asks for --expect-node for the same reason)."""
    if not isinstance(cert, dict):
        return "the certificate is not an object"
    for key in ("repo_id", "ref_name", "old_sha", "new_sha", "pusher_did", "node_did", "issued_at", "signature"):
        if not isinstance(cert.get(key), str):
            return f"the certificate has no {key}"
    if cert.get("version") != 1:
        return f"certificate version {cert.get('version')!r} is not 1, the only one this reader checks"
    if cert["node_did"] != node_did:
        return f"the certificate names node {cert['node_did']}, not the pinned {node_did}"
    try:
        sig = base64.urlsafe_b64decode(cert["signature"] + "=" * (-len(cert["signature"]) % 4))
        key = public_from_did(node_did)
    except ValueError as e:
        return f"unreadable signature or node DID ({e})"
    if not ed25519_verify(key, cert_payload(cert), sig):
        return "the node's signature does not verify"
    return None


def latest_main_cert(certs, branch):
    ref = f"refs/heads/{branch}"
    rows = [c for c in certs if isinstance(c, dict) and c.get("ref_name") == ref and isinstance(c.get("issued_at"), str)]
    return max(rows, key=lambda c: c["issued_at"]) if rows else None


# ---- the mirror list ---------------------------------------------------------------------------------------------------

def check_fixture(fx):
    """Every problem with the mirror list, as sentences; empty when it is sound."""
    bad = []
    if not isinstance(fx, dict):
        return ["the mirror list is not an object"]
    node = fx.get("node")
    if not isinstance(node, str) or not node.startswith("https://"):
        bad.append("node is not an https URL")
    try:
        public_from_did(fx.get("nodeDid"))
    except ValueError:
        bad.append("nodeDid is not an Ed25519 did:key")
    if not isinstance(fx.get("githubOrg"), str) or not NAME.match(fx.get("githubOrg") or ""):
        bad.append("githubOrg is missing")
    if fx.get("branch") != "main":
        bad.append("branch is not main: only main is mirrored")
    repos = fx.get("repos")
    if not isinstance(repos, list) or not repos:
        return bad + ["repos is empty"]
    seen_did, seen_name, seen_seed = set(), set(), set()
    for i, r in enumerate(repos):
        where = f"repos[{i}]"
        if not isinstance(r, dict):
            bad.append(f"{where} is not an object")
            continue
        for key in ("github", "twigpine"):
            if not isinstance(r.get(key), str) or not NAME.match(r[key]):
                bad.append(f"{where}.{key} is not a repository name")
        if not isinstance(r.get("seedName"), str) or not SEED_NAME.match(r["seedName"]):
            bad.append(f"{where}.seedName is not TWIGPINE_SEED_<REPO>")
        did = r.get("did")
        if did is not None:
            try:
                public_from_did(did)
            except ValueError:
                bad.append(f"{where}.did is not an Ed25519 did:key")
        if did is not None and did in seen_did:
            bad.append(f"{where}.did is shared with another repository")
        if did == fx.get("nodeDid"):
            bad.append(f"{where}.did is the node's DID")
        if r.get("github") in seen_name:
            bad.append(f"{where}.github is listed twice")
        if r.get("seedName") in seen_seed:
            bad.append(f"{where}.seedName is shared with another repository")
        seen_did.add(did)
        seen_name.add(r.get("github"))
        seen_seed.add(r.get("seedName"))
    return bad


def load_fixture(path):
    with open(path, "rb") as f:
        raw = f.read()
    if not raw.strip():
        raise Stop(f"{path} is empty")
    try:
        fx = json.loads(raw)
    except ValueError as e:
        raise Stop(f"{path} does not parse ({e})")
    bad = check_fixture(fx)
    if bad:
        raise Stop(f"{path}: " + "; ".join(bad))
    return fx


class Stop(Exception):
    pass


# ---- reads --------------------------------------------------------------------------------------------------------------

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        return None, str(e).encode()


def get_json(get, url):
    """(status, parsed body or None); the status is None when nothing answered."""
    for attempt in range(3):
        status, body = get(url)
        if status is not None and status < 500:
            try:
                return status, json.loads(body) if status == 200 else None
            except ValueError:
                return status, None
        if attempt < 2:
            time.sleep(2 * (attempt + 1))
    return status, None


def version_tuple(text):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def repo_api(fx, r):
    return f"{fx['node'].rstrip('/')}/api/v1/repos/{r['did']}/{r['twigpine']}"


def explorer_url(fx, r):
    return f"{fx.get('explorer', 'https://explorer.twigpine.com').rstrip('/')}/repos/{owner_key(r['did'])}/{r['twigpine']}"


def read_node(fx, get):
    status, doc = get_json(get, fx["node"].rstrip("/") + "/")
    if status != 200 or not isinstance(doc, dict):
        return {"read": False, "status": status}
    v = version_tuple(doc.get("version"))
    return {"read": True, "did": doc.get("did"), "version": doc.get("version"),
            "didMatchesPin": doc.get("did") == fx["nodeDid"],
            "ownerPushDefaultOn": bool(v and v >= OWNER_PUSH_DEFAULT_SINCE),
            # Not on /, /health, /ready or /api/v1/stats: an operator can set it either way and nobody can read it.
            "operatorOwnerPushSetting": NOT_READ}


def gate_repo(fx, r, get):
    """The owner-only push state of one repository on the node: not-bootstrapped, unprotected, protected or not-read."""
    row = {"repo": r["github"], "twigpine": r["twigpine"], "did": r.get("did")}
    if not r.get("did"):
        return {**row, "state": "no-key", "why": "no did:key made for this repository yet (twigpine_mirror.py keys)"}
    status, doc = get_json(get, repo_api(fx, r))
    if status == 404:
        return {**row, "state": "not-bootstrapped", "why": "the repository is not on the node yet"}
    if status != 200 or not isinstance(doc, dict):
        return {**row, "state": NOT_READ, "why": f"repository read answered {status}"}
    if doc.get("owner_did") != r["did"]:
        return {**row, "state": "wrong-owner", "why": f"the node says its owner is {doc.get('owner_did')}"}
    status, prot = get_json(get, repo_api(fx, r) + "/branches/protected")
    if status != 200 or not isinstance(prot, dict) or not isinstance(prot.get("protected_branches"), list):
        return {**row, "state": NOT_READ, "why": f"protected-branch read answered {status}"}
    names = {p if isinstance(p, str) else (p or {}).get("branch") or (p or {}).get("name") for p in prot["protected_branches"]}
    if fx["branch"] not in names:
        return {**row, "state": "unprotected", "why": f"{fx['branch']} is not protected, so any signed DID may push to it "
                                                     "when the operator has turned owner-only push off"}
    return {**row, "state": "protected", "why": f"{fx['branch']} is protected: the node refuses every non-owner push"}


def gate(fx, get=http_get):
    node = read_node(fx, get)
    rows = [gate_repo(fx, r, get) for r in fx["repos"]]
    return {"schema": GATE_SCHEMA, "at": now(), "node": fx["node"], "nodeState": node, "repos": rows,
            "passes": [r["repo"] for r in rows if r["state"] == "protected" and node.get("didMatchesPin")]}


def github_main(fx, r, run=subprocess.run):
    """GitHub's `main` SHA, read with git ls-remote (no token: the repositories are public)."""
    url = f"https://github.com/{fx['githubOrg']}/{r['github']}.git"
    p = run(["git", "ls-remote", "--", url, f"refs/heads/{fx['branch']}"], capture_output=True, text=True, timeout=60,
            env=child_env())
    if p.returncode != 0:
        return None
    m = re.match(r"^([0-9a-f]{40})\s", p.stdout)
    return m.group(1) if m else None


def check_repo(fx, r, g, get, sha):
    row = {"repo": r["github"], "gate": g["state"], "githubSha": sha or NOT_READ}
    if g["state"] in ("no-key", "not-bootstrapped"):
        return {**row, "state": g["state"]}
    if g["state"] == NOT_READ or sha is None:
        return {**row, "state": NOT_READ}
    status, doc = get_json(get, repo_api(fx, r) + "/certs?limit=100")
    certs = doc.get("certificates") if isinstance(doc, dict) else None
    if status != 200 or not isinstance(certs, list):
        return {**row, "state": NOT_READ, "why": f"certificate read answered {status}"}
    cert = latest_main_cert(certs, fx["branch"])
    if cert is None:
        return {**row, "state": "no-certificate"}
    why = verify_cert(cert, fx["nodeDid"])
    if why:
        return {**row, "state": "bad-certificate", "certId": cert.get("id"), "why": why}
    if cert["pusher_did"] != r["did"]:
        return {**row, "state": "foreign-pusher", "certId": cert["id"], "why": f"pushed by {cert['pusher_did']}"}
    row.update({"certId": cert["id"], "twigpineSha": cert["new_sha"], "issuedAt": cert["issued_at"]})
    if g["state"] != "protected":
        return {**row, "state": g["state"]}
    return {**row, "state": "in-sync" if cert["new_sha"] == sha else "behind"}


def check(fx, get=http_get, ls_remote=None):
    ls_remote = ls_remote or (lambda r: github_main(fx, r))
    g = gate(fx, get)
    rows = [check_repo(fx, r, gr, get, ls_remote(r)) for r, gr in zip(fx["repos"], g["repos"])]
    return {"schema": CHECK_SCHEMA, "at": now(), "gate": g, "repos": rows}


def check_exit(report, expect_live):
    states = [r["state"] for r in report["repos"]]
    if not report["gate"]["nodeState"].get("read") or NOT_READ in states:
        return EXIT_STOP
    if report["gate"]["nodeState"].get("didMatchesPin") is False:
        return EXIT_FAIL
    if any(s in ("bad-certificate", "foreign-pusher", "wrong-owner") for s in states):
        return EXIT_FAIL
    if expect_live and any(s != "in-sync" for s in states):
        return EXIT_FAIL
    return EXIT_OK


# ---- push and bootstrap (inert unless TWIGPINE_MIRROR=on) ---------------------------------------------------------------

def child_env(extra=None):
    """The environment a child process gets: no seed, no old GITLAWB_ names that could point it at another key."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TWIGPINE_SEED", "GITLAWB_", "TWIGPINE_KEY"))}
    env.update({"GIT_TERMINAL_PROMPT": "0", "TWIGPINE_LOG": "warn"})
    env.update(extra or {})
    return env


def switched_on():
    return os.environ.get(SWITCH) == "on"


def find_repo(fx, name):
    for r in fx["repos"]:
        if r["github"] == name:
            return r
    raise Stop(f"{name} is not in the mirror list")


def load_seed(r, env_name=None):
    """The repository's own seed from its own variable (its seedName, or the one variable a workflow leg was given),
    checked against the did:key the list names."""
    env_name = env_name or r["seedName"]
    text = os.environ.get(env_name, "")
    if not text.strip():
        raise Stop(f"{env_name} is not set")
    try:
        seed = decode_seed(text)
    except ValueError as e:
        raise Stop(f"{env_name} does not parse ({e})")
    if did_from_public(ed25519_public(seed)) != r.get("did"):
        raise Stop(f"{r['seedName']} is not the key of {r['github']}: its did:key differs from the list's")
    return seed


class Identity:
    """A 0600 identity PEM in a private temporary folder for one run; overwritten and removed on exit."""

    def __init__(self, seed):
        self.seed = seed

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="twigpine-id-")
        os.chmod(self.dir, 0o700)
        self.pem = os.path.join(self.dir, "identity.pem")
        fd = os.open(self.pem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(seed_pem(self.seed))
        return self

    def __exit__(self, *exc):
        try:
            size = os.path.getsize(self.pem)
            with open(self.pem, "r+b") as f:
                f.write(b"\0" * size)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def run_quiet(cmd, env, cwd=None, timeout=300):
    """Run a command; its output is returned for the error message with anything key-shaped removed."""
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    out = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[redacted]",
                 (p.stdout + p.stderr)[-2000:])
    return p.returncode, out


def wait_for_cert(fx, r, sha, get, sleep=time.sleep, tries=12):
    for _ in range(tries):
        status, doc = get_json(get, repo_api(fx, r) + "/certs?limit=100")
        certs = doc.get("certificates") if isinstance(doc, dict) else None
        if isinstance(certs, list):
            for c in sorted((c for c in certs if isinstance(c, dict)), key=lambda c: c.get("issued_at") or "", reverse=True):
                if c.get("ref_name") == f"refs/heads/{fx['branch']}" and c.get("new_sha") == sha:
                    return c
        sleep(5)
    return None


def receipt(fx, r, sha, cert, run_url):
    why = verify_cert(cert, fx["nodeDid"])
    return {"schema": RECEIPT_SCHEMA, "at": now(), "repo": r["github"],
            "github": {"repo": f"{fx['githubOrg']}/{r['github']}", "ref": f"refs/heads/{fx['branch']}", "sha": sha},
            "twigpine": {"node": fx["node"], "owner": r["did"], "repo": r["twigpine"], "certId": cert["id"],
                         "oldSha": cert["old_sha"], "newSha": cert["new_sha"], "pusherDid": cert["pusher_did"],
                         "nodeDid": cert["node_did"], "issuedAt": cert["issued_at"], "signature": cert["signature"],
                         "version": cert.get("version"),
                         "certUrl": f"{repo_api(fx, r)}/certs/{cert['id']}", "explorerUrl": explorer_url(fx, r)},
            "verified": why is None and cert["pusher_did"] == r["did"] and cert["new_sha"] == sha,
            "why": why, "run": run_url or NOT_READ}


def push(fx, name, get=http_get, run_url=None, seed_env=None):
    if not switched_on():
        raise Stop(f"{SWITCH} is not on: the mirror is inert")
    r = find_repo(fx, name)
    g = gate_repo(fx, r, get)
    if g["state"] != "protected":
        raise Stop(f"{name}: owner-only gate is {g['state']} ({g.get('why')}); nothing pushed")
    node = read_node(fx, get)
    if not node.get("didMatchesPin"):
        raise Stop(f"the node at {fx['node']} does not answer with the pinned DID; nothing pushed")
    seed = load_seed(r, seed_env)
    work = tempfile.mkdtemp(prefix="twigpine-push-")
    try:
        bare = os.path.join(work, "repo.git")
        env = child_env()
        code, out = run_quiet(["git", "init", "--quiet", "--bare", bare], env)
        source = f"https://github.com/{fx['githubOrg']}/{r['github']}.git"
        ref = f"refs/heads/{fx['branch']}"
        code, out = run_quiet(["git", "-C", bare, "fetch", "--quiet", "--no-tags", "--", source, f"{ref}:{ref}"], env)
        if code:
            raise Stop(f"{name}: fetching GitHub {fx['branch']} failed: {out}")
        code, out = run_quiet(["git", "-C", bare, "rev-parse", ref], env)
        sha = out.strip().splitlines()[-1] if code == 0 else ""
        if not SHA1.match(sha):
            raise Stop(f"{name}: no SHA for GitHub {fx['branch']}")
        with Identity(seed) as ident:
            env = child_env({"TWIGPINE_KEY": ident.pem, "TWIGPINE_NODE": fx["node"], "HOME": ident.dir})
            # The helper must read this PEM as the list's did:key, or the push would go out as someone else.
            code, out = run_quiet(["gl", "identity", "show", "--dir", ident.dir], env)
            if code or r["did"] not in out:
                raise Stop(f"{name}: gl does not read the identity as {r['did']}: {out}")
            remote = f"gitlawb://{owner_key(r['did'])}/{r['twigpine']}"
            # No `+` and no --force: git refuses anything but a fast-forward of the mirror's main.
            code, out = run_quiet(["git", "-C", bare, "push", "--quiet", "--", remote, f"{sha}:{ref}"], env)
        if code:
            raise Stop(f"{name}: the push to Twigpine was refused: {out}")
        cert = wait_for_cert(fx, r, sha, get)
        if cert is None:
            raise Stop(f"{name}: pushed {sha}, but no certificate for it appeared")
        return receipt(fx, r, sha, cert, run_url)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def bootstrap_plan(fx, r):
    """The one-time owner steps, in order. Each is idempotent on the node."""
    return [
        ["gl", "register", "--node", fx["node"], "--dir", "{dir}"],
        ["gl", "repo", "create", r["twigpine"], "--description",
         f"Signed mirror of github.com/{fx['githubOrg']}/{r['github']} (GitHub is canonical)", "--node", fx["node"],
         "--dir", "{dir}"],
        ["gl", "protect", "set", fx["branch"], "--repo", r["twigpine"], "--node", fx["node"], "--dir", "{dir}"],
    ]


def bootstrap(fx, name, yes, seed_env=None):
    r = find_repo(fx, name)
    plan = bootstrap_plan(fx, r)
    if not yes or not switched_on():
        return {"repo": name, "did": r.get("did"), "ran": False, "plan": [" ".join(c) for c in plan],
                "why": f"dry run: pass --yes with {SWITCH}=on to run it"}
    seed = load_seed(r, seed_env)
    done = []
    with Identity(seed) as ident:
        env = child_env({"TWIGPINE_KEY": ident.pem, "TWIGPINE_NODE": fx["node"], "HOME": ident.dir})
        code, out = run_quiet(["gl", "identity", "show", "--dir", ident.dir], env)
        if code or r["did"] not in out:
            raise Stop(f"{name}: gl does not read the identity as {r['did']}: {out}")
        for cmd in plan:
            cmd = [ident.dir if part == "{dir}" else part for part in cmd]
            code, out = run_quiet(cmd, env)
            already = code != 0 and re.search(r"already (exists|registered)|409", out, re.I)
            if code and not already:
                raise Stop(f"{name}: `{' '.join(cmd[:3])}` failed: {out}")
            done.append(" ".join(cmd[:3]))
    return {"repo": name, "did": r["did"], "ran": True, "steps": done}


# ---- keys ---------------------------------------------------------------------------------------------------------------

def make_keys(fx, path, passbook="passbook"):
    """A new seed for each repository with no did:key yet: the seed goes to PassBook on stdin (--if-absent, so an
    existing key is never replaced), and only the did:key is written to the list. Nothing secret is printed."""
    made = []
    for r in fx["repos"]:
        if r.get("did"):
            continue
        # A name PassBook already holds with no DID in the list would keep its old seed under --if-absent, and the DID
        # written here would then not be that seed's: stop instead.
        held = subprocess.run([passbook, "check", r["seedName"]], capture_output=True, text=True, timeout=60)
        if held.returncode == 0 or "missing" not in held.stdout:
            raise Stop(f"PassBook already holds {r['seedName']} (or could not say): set its did in the list by hand")
        seed = os.urandom(32)
        line = f"{r['seedName']}={base64.urlsafe_b64encode(seed).decode().rstrip('=')}\n"
        p = subprocess.run([passbook, "add", "--stdin", "--if-absent", "--app", "bee-self-test-twigpine-mirror"],
                           input=line, capture_output=True, text=True, timeout=60)
        del line
        if p.returncode != 0:
            raise Stop(f"PassBook did not take {r['seedName']} (exit {p.returncode})")
        r["did"] = did_from_public(ed25519_public(seed))
        made.append({"repo": r["github"], "did": r["did"], "seedName": r["seedName"]})
    with open(path, "w") as f:
        json.dump(fx, f, indent=2)
        f.write("\n")
    return made


# ---- self-test ----------------------------------------------------------------------------------------------------------

def self_test(fixture_dir="fixtures/twigpine-mirror"):
    bad = []
    # RFC 8032 section 7.1, test 1.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
                        "d25bf5f0595bbe24655141438e7a100b")
    if ed25519_public(seed) != pub:
        bad.append("RFC 8032 test 1: the public key is wrong")
    if not ed25519_verify(pub, b"", sig):
        bad.append("RFC 8032 test 1: the signature does not verify")
    if ed25519_verify(pub, b"x", sig):
        bad.append("RFC 8032 test 1: a signature verified over the wrong message")
    did = did_from_public(pub)
    if public_from_did(did) != pub or not did.startswith("did:key:z6Mk"):
        bad.append("did:key round trip failed")
    with open(os.path.join(fixture_dir, "live-cert.json")) as f:
        live = json.load(f)
    if verify_cert(live["cert"], live["nodeDid"]) is not None:
        bad.append("the recorded live certificate does not verify: " + str(verify_cert(live["cert"], live["nodeDid"])))
    tampered = dict(live["cert"], new_sha="0" * 40)
    if verify_cert(tampered, live["nodeDid"]) is None:
        bad.append("a certificate with a changed new_sha verified")
    if verify_cert(live["cert"], did) is None:
        bad.append("a certificate verified against a node DID that did not sign it")
    return bad


def write_json(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fixture", default=FIXTURE)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--check-fixture", nargs="?", const=True, default=False)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("gate")
    s.add_argument("--out")
    s = sub.add_parser("check")
    s.add_argument("--out")
    s.add_argument("--expect-live", action="store_true")
    s = sub.add_parser("push")
    s.add_argument("--repo", required=True)
    s.add_argument("--out")
    s.add_argument("--seed-env", help="the variable holding this repository's seed (default: its seedName)")
    s = sub.add_parser("bootstrap")
    s.add_argument("--repo", required=True)
    s.add_argument("--yes", action="store_true")
    s.add_argument("--seed-env")
    sub.add_parser("keys")
    a = p.parse_args(argv)
    try:
        if a.self_test:
            bad = self_test()
            print("\n".join(bad) or "self-test: ok")
            return EXIT_FAIL if bad else EXIT_OK
        if a.check_fixture:
            path = a.check_fixture if isinstance(a.check_fixture, str) else a.fixture
            fx = load_fixture(path)
            missing = [r["github"] for r in fx["repos"] if not r.get("did")]
            print(f"{path}: {len(fx['repos'])} repositories, no did:key shared" +
                  (f"; no key yet for {', '.join(missing)}" if missing else "; each has its own"))
            return EXIT_OK
        fx = load_fixture(a.fixture)
        if a.cmd == "gate":
            report = gate(fx)
            if a.out:
                write_json(a.out, report)
            print(json.dumps(report, indent=2))
            return EXIT_STOP if not report["nodeState"].get("read") else EXIT_OK
        if a.cmd == "check":
            report = check(fx)
            if a.out:
                write_json(os.path.join(a.out, "twigpine-mirror-check.json"), report)
            print(json.dumps(report, indent=2))
            return check_exit(report, a.expect_live)
        if a.cmd == "push":
            run_url = None
            if os.environ.get("GITHUB_RUN_ID"):
                run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY')}" \
                          f"/actions/runs/{os.environ['GITHUB_RUN_ID']}"
            rec = push(fx, a.repo, run_url=run_url, seed_env=a.seed_env)
            if a.out:
                write_json(os.path.join(a.out, a.repo, "twigpine-mirror.json"), rec)
            print(json.dumps(rec, indent=2))
            return EXIT_OK if rec["verified"] else EXIT_FAIL
        if a.cmd == "bootstrap":
            print(json.dumps(bootstrap(fx, a.repo, a.yes, a.seed_env), indent=2))
            return EXIT_OK
        if a.cmd == "keys":
            made = make_keys(fx, a.fixture)
            print(json.dumps({"made": made}, indent=2))
            return EXIT_OK
        p.print_help()
        return EXIT_STOP
    except Stop as e:
        print(f"STOP {e}", file=sys.stderr)
        return EXIT_STOP


if __name__ == "__main__":
    sys.exit(main())
