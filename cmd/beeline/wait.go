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

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/daemon"
	"go.beeline.sh/cli/internal/host"
	"go.beeline.sh/cli/internal/ui"
)

// waitShare keeps the terminal on a share: it follows the daemon's event
// stream and redraws one line per connected receiver until ctrl-c, which
// revokes the share. The daemon keeps serving in the background either way;
// this is only the attached view.
func waitShare(ctx context.Context, cfg config.Config, dc *daemon.Client, id string) error {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", cfg.Socket)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://beeline/events", nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return revokeOnExit(dc, id)
		}
		return err
	}
	defer res.Body.Close()

	fmt.Fprintln(os.Stderr, "  waiting for a peer  ·  ctrl-c to stop")
	drawn := 1
	delivered := 0
	best := map[string]float64{} // peer -> highest progress seen, to count deliveries
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
		var cur *host.Info
		for i := range shares {
			if shares[i].ID == id {
				cur = &shares[i]
			}
		}
		if cur == nil {
			clear(&drawn)
			fmt.Fprintf(os.Stderr, "\r\033[K  share %s is over (revoked, expired or downloads used up)\n", id)
			return nil
		}
		seen := map[string]bool{}
		for _, p := range cur.Peers {
			seen[p.Peer] = true
			if p.Progress > best[p.Peer] {
				best[p.Peer] = p.Progress
			}
		}
		for peer, prog := range best {
			if !seen[peer] {
				if prog >= 0.999 {
					delivered++
				}
				delete(best, peer)
			}
		}
		lines := make([]string, 0, len(cur.Peers)+1)
		switch {
		case len(cur.Peers) == 0 && delivered == 0:
			lines = append(lines, "  waiting for a peer  ·  ctrl-c to stop")
		case len(cur.Peers) == 0:
			lines = append(lines, fmt.Sprintf("  delivered %d  ·  waiting for the next peer  ·  ctrl-c to stop", delivered))
		default:
			for _, p := range cur.Peers {
				lines = append(lines, fmt.Sprintf("  %s  %-14s %s  %3.0f%%   %s", p.Peer, transportLabel(p.Transport), ui.Bar(p.Progress, 20), p.Progress*100, ui.Rate(p.BPS)))
			}
			if delivered > 0 {
				lines = append(lines, fmt.Sprintf("  delivered %d so far", delivered))
			}
		}
		clear(&drawn)
		for _, l := range lines {
			fmt.Fprintf(os.Stderr, "\r\033[K%s\n", l)
		}
		drawn = len(lines)
	}
	if ctx.Err() != nil {
		clear(&drawn)
		return revokeOnExit(dc, id)
	}
	return sc.Err()
}

// clear moves the cursor back over the lines drawn last time.
func clear(drawn *int) {
	if *drawn > 0 {
		fmt.Fprintf(os.Stderr, "\r\033[%dA", *drawn) // \r: the shell echoes ^C and moves the cursor
	}
	*drawn = 0
}

func revokeOnExit(dc *daemon.Client, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dc.Revoke(ctx, id); err != nil {
		return fmt.Errorf("revoke %s: %w", id, err)
	}
	fmt.Fprintf(os.Stderr, "\r\033[K  revoked %s\n", id)
	return nil
}
