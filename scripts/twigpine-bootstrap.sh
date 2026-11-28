#!/bin/bash
# B-59: the one-time Twigpine bootstrap of every repository in fixtures/twigpine-mirror/mirrors.json, run by the owner
# in his own terminal (iCaptcha guards `gl register` and `gl repo create`; a CAPTCHA is his to answer, not an agent's).
# For each repository: register its did:key, create the repository, protect `main`. Steps the node already has are
# skipped, so after a stop run it again. Each seed reaches only its own run, through passbook run; nothing is printed.
# usage, from the bee-self-test checkout: bash scripts/twigpine-bootstrap.sh [repo ...]   (default: every repository)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=0.8.1
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PKG=gl-darwin-arm64;; Linux-x86_64) PKG=gl-linux-x64;; *) echo "no pinned Twigpine CLI for $(uname -sm)"; exit 2;;
esac
if ! gl --version 2>/dev/null | grep -q "$VERSION"; then
  CLI=$(mktemp -d)
  npm install --silent --no-save --ignore-scripts --prefix "$CLI" "@gitlawb/$PKG@$VERSION"
  chmod 0755 "$CLI/node_modules/@gitlawb/$PKG/gl" "$CLI/node_modules/@gitlawb/$PKG/git-remote-gitlawb"
  export PATH="$CLI/node_modules/@gitlawb/$PKG:$PATH"
  gl --version | grep -q "$VERSION"
fi
REPOS=("$@")
[ ${#REPOS[@]} -gt 0 ] || REPOS=($(python3 -I -c 'import json;print(" ".join(r["github"] for r in json.load(open("fixtures/twigpine-mirror/mirrors.json"))["repos"]))'))
for repo in "${REPOS[@]}"; do
  seed=$(python3 -I -c 'import json,sys;print(next(r["seedName"] for r in json.load(open("fixtures/twigpine-mirror/mirrors.json"))["repos"] if r["github"]==sys.argv[1]))' "$repo")
  echo; echo "=== $repo"
  passbook run --reason "B-59 Twigpine bootstrap of $repo (owner at the terminal)" --only "$seed" -- \
    env TWIGPINE_MIRROR=on python3 -I scripts/twigpine_mirror.py bootstrap --repo "$repo" --yes --attended
done
echo; python3 -I scripts/twigpine_mirror.py gate | python3 -I -c 'import json,sys;[print(r["repo"], r["state"]) for r in json.load(sys.stdin)["repos"]]'
