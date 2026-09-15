#!/bin/sh
# Beeline CLI installer, served at https://beeline.sh/install
#
#   curl -fsSL https://beeline.sh/install | sh
#   BEELINE_VERSION=v0.2.0 ...  pin a release
#   BEELINE_BIN=~/bin ...       install somewhere else
#
# Downloads the release archive for this OS/arch from GitHub Releases and
# installs the single `beeline` binary. Linux and macOS; Windows users take
# the .zip from the releases page.
set -eu

REPO="beeline-sh/beeline-cli"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
	linux|darwin) ;;
	*) echo "beeline: unsupported OS '$os' (use the release archive by hand)" >&2; exit 1 ;;
esac
arch=$(uname -m)
case "$arch" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) echo "beeline: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

ver="${BEELINE_VERSION:-}"
if [ -z "$ver" ]; then
	ver=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
	[ -n "$ver" ] || { echo "beeline: could not determine the latest release" >&2; exit 1; }
fi
num=${ver#v}
url="https://github.com/$REPO/releases/download/$ver/beeline_${num}_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "downloading beeline $ver ($os/$arch)"
curl -fsSL "$url" | tar -xz -C "$tmp"

dest="${BEELINE_BIN:-}"
if [ -z "$dest" ]; then
	if [ -w /usr/local/bin ]; then dest=/usr/local/bin; else dest="$HOME/.local/bin"; fi
fi
mkdir -p "$dest"
install -m 755 "$tmp/beeline" "$dest/beeline"
echo "installed $dest/beeline"
case ":$PATH:" in
	*":$dest:"*) ;;
	*) echo "add $dest to your PATH" ;;
esac
"$dest/beeline" version
