package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/daemon"
	"go.beeline.sh/cli/internal/host"
	"go.beeline.sh/cli/internal/ui"
)

const waitHint = "  waiting for a peer  ·  ctrl-c stops the share  ·  d keeps it running in the background"

// waitShare keeps the terminal on a share: it follows the daemon's event
// stream and redraws one line per connected receiver. ctrl-c revokes the
// share; `d` (or ctrl-b) detaches and leaves the daemon serving it. The
// daemon serves in the background either way; this is only the attached view.
func waitShare(ctx context.Context, cfg config.Config, dc *daemon.Client, id string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Raw mode so single keys arrive without enter. Output then needs \r\n.
	keys := make(chan byte, 4)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		if old, err := term.MakeRaw(fd); err == nil {
			defer term.Restore(fd, old)
			go func() {
				buf := make([]byte, 1)
				for {
					n, err := os.Stdin.Read(buf)
					if err != nil || n == 0 {
						return
					}
					keys <- buf[0]
				}
			}()
		}
	}
	out := func(format string, a ...any) { fmt.Fprintf(os.Stderr, strings.ReplaceAll(format, "\n", "\r\n"), a...) }

	snapshots := make(chan []host.Info, 4)
	errc := make(chan error, 1)
	go func() { errc <- followEvents(ctx, cfg.Socket, snapshots) }()

	out("%s\n", waitHint)
	drawn := 1
	delivered := 0
	for {
		select {
		case <-ctx.Done():
			clear(&drawn)
			return revokeOnExit(dc, id, out)
		case k := <-keys:
			switch k {
			case 0x03: // ctrl-c
				clear(&drawn)
				return revokeOnExit(dc, id, out)
			case 'd', 'D', 0x02: // ctrl-b
				clear(&drawn)
				out("\r\033[K  detached, still serving in the background  ·  beeline ls  ·  beeline revoke %s\n", id)
				return nil
			}
		case err := <-errc:
			if ctx.Err() != nil {
				clear(&drawn)
				return revokeOnExit(dc, id, out)
			}
			clear(&drawn)
			if err != nil {
				return err
			}
			out("\r\033[K  lost the daemon; the share may still be running (beeline ls)\n")
			return nil
		case shares := <-snapshots:
			var cur *host.Info
			for i := range shares {
				if shares[i].ID == id {
					cur = &shares[i]
				}
			}
			if cur == nil {
				clear(&drawn)
				out("\r\033[K  share %s is over (revoked, expired or downloads used up)\n", id)
				return nil
			}
			delivered = len(cur.Downloads)
			lines := make([]string, 0, len(cur.Peers)+1)
			switch {
			case len(cur.Peers) == 0 && delivered == 0:
				lines = append(lines, waitHint)
			case len(cur.Peers) == 0:
				lines = append(lines, fmt.Sprintf("  delivered %d  ·  waiting for the next peer  ·  ctrl-c stops  ·  d detaches", delivered))
			default:
				for _, p := range cur.Peers {
					lines = append(lines, fmt.Sprintf("  %s  %-14s %s  %3.0f%%   %s", p.Peer, transportLabel(p.Transport), ui.Bar(p.Progress, 20), p.Progress*100, ui.Rate(p.BPS)))
				}
			}
			if n := len(cur.Downloads); n > 0 {
				from := 0
				if n > 5 {
					from = n - 5
				}
				for _, d := range cur.Downloads[from:] {
					bps := 0.0
					if d.Seconds > 0 {
						bps = float64(d.Bytes) / d.Seconds
					}
					lines = append(lines, fmt.Sprintf("  ✓ %s in %s  %s  %s  %s", ui.Size(d.Bytes), ui.Secs(d.Seconds), ui.Rate(bps), transportLabel(d.Transport), ui.Ago(d.FinishedAt)))
				}
			}
			clear(&drawn)
			for _, l := range lines {
				out("\r\033[K%s\n", l)
			}
			drawn = len(lines)
		}
	}
}

// followEvents streams the daemon's share snapshots until ctx ends.
func followEvents(ctx context.Context, socket string, snapshots chan<- []host.Info) error {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://beeline/events", nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var shares []host.Info
		if err := json.Unmarshal([]byte(line[6:]), &shares); err != nil {
			continue
		}
		select {
		case snapshots <- shares:
		case <-ctx.Done():
			return nil
		}
	}
	return sc.Err()
}

// clear moves the cursor back over the lines drawn last time.
func clear(drawn *int) {
	if *drawn > 0 {
		fmt.Fprintf(os.Stderr, "\r\033[%dA", *drawn)
	}
	*drawn = 0
}

func revokeOnExit(dc *daemon.Client, id string, out func(string, ...any)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dc.Revoke(ctx, id); err != nil {
		return fmt.Errorf("revoke %s: %w", id, err)
	}
	out("\r\033[K  revoked %s\n", id)
	return nil
}
