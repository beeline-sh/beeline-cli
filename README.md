# beeline-cli

The `beeline` binary: a background daemon that serves shares over QUIC,
WebTransport and WebRTC, the command line in front of it, and an MCP server.
Implements `../beeline-protocol/PROTOCOL.md` v1.

```
$ beeline share film.mkv
  film.mkv   4.2 GB
  https://beeline.sh/m3xq8a#Hd7pKw2nRt5sVb1xZt4gPm
  serving in the background · beeline ls to see it · expires in 7d

$ beeline get https://beeline.sh/m3xq8a#Hd7pKw2nRt5sVb1xZt4gPm -o ~/Downloads
  film.mkv   4.2 GB   direct/quic
  ██████████████████████░░   91%   118 MB/s   00:04 left
  ✓ saved to /home/me/Downloads/film.mkv   sha256 root 9f3c1a20e4b1...
```

## Commands

| command | what |
|---|---|
| `beeline share <path\|-> [--name N] [--expires 24h\|7d\|0] [--max-downloads N] [--relay auto\|never] [--wait]` | Register the path and print the link. `-` spools stdin to `~/.beeline/spool` first (v1 needs a size). Starts the daemon if it is not running. `--wait` keeps the terminal attached, shows receivers live, and revokes the share on ctrl-c. |
| `beeline get <link> [-o DIR]` | Receive in-process. Resumes from `<dest>.beeline-part` if present. |
| `beeline ls` | Active shares, peers, transport, progress, speed. |
| `beeline revoke <id>` / `beeline revoke all` | Stop serving now. |
| `beeline daemon` | Run the daemon in the foreground. |
| `beeline daemon stop` / `restart` / `status` | Control the background daemon. Shares are persisted in `~/.beeline/shares.json` and come back after a restart. `status` includes the router port mapping. |
| `beeline update` | Install the latest release over this binary (checksum verified) and restart the daemon. `BEELINE_VERSION=vX.Y.Z` pins a release. |
| `beeline mcp` | MCP server over stdio (tools `share_file`, `share_text`, `receive`, `list_shares`, `revoke`). |

Config: `BEELINE_SERVER` (default `https://beeline.sh`), `BEELINE_PORT` (UDP,
default 41820, falls back to a random port), `BEELINE_RELAY`, `BEELINE_SOCKET`;
or `~/.config/beeline/config.json` with `server`, `port`, `relay`, `socket`.
Daemon socket: `$XDG_RUNTIME_DIR/beeline.sock` (else `~/.beeline/beeline.sock`).
Daemon log: `~/.beeline/daemon.log`. `share`, `get`, `ls` and `revoke` check
for a newer release at most once a day and print a one-line hint;
`BEELINE_NO_UPDATE_CHECK=1` turns that off.

The daemon asks the router (UPnP IGD or NAT-PMP/PCP) to forward its UDP
port, so browsers behind the internet can reach it over WebTransport even
when the NAT is port-restricted; `beeline daemon status` shows the result.
Without a cooperative router, forward the UDP port by hand or the browser
side falls back to WebRTC. `BEELINE_NO_PORTMAP=1` disables the request.

MCP registration (Claude Code `.mcp.json`):

```json
{ "mcpServers": { "beeline": { "command": "beeline", "args": ["mcp"] } } }
```

## Layout

```
cmd/beeline/         subcommands
internal/link        link parsing, key schedule (HKDF), sealed payloads (AES-GCM), proofs
internal/signal      WebSocket signaling client + payload types (hello, manifest, sdp, ice, bye)
internal/api         server HTTP API (create/delete share, info)
internal/wire        §7 frame codec, DATA splitting for WebRTC
internal/manifest    layout + chunk math, Source (chunk reader, hash cache), Sink (writer, sidecar resume)
internal/transport   Endpoint (one UDP socket: QUIC listen/dial, STUN, hole punch), cert, WebTransport server, WebRTC, race
internal/host        Share lifecycle: register, signaling loop, hello→manifest, serve REQ/HASH-REQ/DONE, download cap, expiry
internal/peer        Receive: hello, manifest, race, 64-in-flight scheduler, 256-chunk hash windows, resume, root check
internal/daemon      unix-socket HTTP API (§8), SSE /events, receive jobs, auto-start
internal/mcp         hand-rolled MCP stdio server on top of the daemon API
internal/config, ui  settings; sizes/rates/bars
```

## Build

```sh
go build ./cmd/beeline
```

Go 1.24 or newer. Releases are built by `.github/workflows/release.yml` on
every `v*` tag and published at https://github.com/beeline-sh/beeline-cli/releases;
`scripts/install.sh` (served at https://beeline.sh/install) picks the right
archive for the current OS and architecture.

One UDP socket carries everything: quic-go's `Transport` listens for `h3`
(WebTransport) and `beeline/1` (raw QUIC) and dispatches by negotiated ALPN;
STUN and hole-punch datagrams go through the same socket, so the address
advertised to peers is the one they can reach. The WebTransport certificate
is ECDSA P-256 with 13-day validity (`transport/cert.go`), rotated by the
daemon a day before expiry.

Every incoming QUIC/WebTransport stream must start with a valid `AUTH`
frame derived from the link key before anything is served; a source
address that fails ten times within a minute is refused for a minute.

## Not yet

- No relay of any kind: when both networks block direct connections the
  transfer fails and says so.
- Receivers exchanging chunks with each other (swarm).
- PCP/NAT-PMP/UPnP port mapping.
- Streaming stdin with unknown size (spooled instead).
- Windows: the daemon is not detached automatically (`beeline daemon` in its
  own window or as a service), and `beeline update` prints instructions
  instead of replacing the running binary.
