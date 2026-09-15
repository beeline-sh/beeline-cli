#!/usr/bin/env bash
# End-to-end smoke test: server + CLI share + CLI get on one machine.
# Expects beeline-server checked out next to beeline-cli.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # parent of beeline-cli and beeline-server
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

echo "== build"
(cd "$ROOT/beeline-server" && go build -o "$TMP/beeline-server" ./cmd/beeline-server)
(cd "$ROOT/beeline-cli" && go build -o "$TMP/beeline" ./cmd/beeline)

echo "== server"
"$TMP/beeline-server" -addr 127.0.0.1:18080 -db "$TMP/s.db" -origins '*' &
for i in $(seq 1 30); do curl -fs http://127.0.0.1:18080/healthz >/dev/null && break; sleep 0.2; done
curl -fs http://127.0.0.1:18080/v1/info; echo

export BEELINE_SERVER=http://127.0.0.1:18080
export XDG_RUNTIME_DIR="$TMP/run"; mkdir -p "$XDG_RUNTIME_DIR"
export HOME="$TMP/home"; mkdir -p "$HOME"

echo "== payload (64 MiB random)"
head -c $((64*1024*1024)) /dev/urandom > "$TMP/payload.bin"
SUM=$(sha256sum "$TMP/payload.bin" | cut -d' ' -f1)

echo "== share"
OUT=$("$TMP/beeline" share "$TMP/payload.bin")
echo "$OUT"
LINK=$(echo "$OUT" | grep -oE 'https?://[^ ]+#[A-Za-z0-9_-]+' | head -1)
[ -n "$LINK" ] || { echo "no link in output"; exit 1; }

echo "== ls"
"$TMP/beeline" ls

echo "== get"
mkdir -p "$TMP/dl"
time "$TMP/beeline" get "$LINK" -o "$TMP/dl"
GOT=$(sha256sum "$TMP/dl/payload.bin" | cut -d' ' -f1)
[ "$SUM" = "$GOT" ] && echo "OK: checksums match" || { echo "FAIL: checksum mismatch"; exit 1; }

echo "== revoke"
ID=$(echo "$LINK" | sed -E 's#.*/([a-z2-9]{6})\#.*#\1#')
"$TMP/beeline" revoke "$ID"
curl -s -o /dev/null -w "GET /v1/shares/$ID -> %{http_code} (expect 410)\n" "http://127.0.0.1:18080/v1/shares/$ID"
