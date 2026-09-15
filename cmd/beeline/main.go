// Command beeline shares and receives files device to device.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/daemon"
	"go.beeline.sh/cli/internal/host"
	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/mcp"
	"go.beeline.sh/cli/internal/peer"
	"go.beeline.sh/cli/internal/ui"
	"go.beeline.sh/cli/internal/update"
)

const usageText = `beeline - files go straight from your device to theirs

usage:
  beeline share <path|-> [--name N] [--expires 24h|7d|0] [--max-downloads N] [--relay auto|never] [--wait]
  beeline get <link> [-o DIR]
  beeline ls
  beeline revoke <id>|all
  beeline daemon [stop|restart|status]
  beeline update
  beeline mcp
  beeline version

environment:
  BEELINE_SERVER            introduction server (default https://beeline.sh)
  BEELINE_PORT              UDP port for the daemon (default 41820)
  BEELINE_RELAY             auto | never
  BEELINE_VERSION           pin the update command to a release (vX.Y.Z)
  BEELINE_NO_UPDATE_CHECK   1 disables the daily check for a newer version
  BEELINE_NO_PORTMAP        1 disables UPnP/NAT-PMP port mapping on the router
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Everyday commands look for a newer release in the background and
	// mention it after their own output.
	latest := func() string { return "" }
	switch os.Args[1] {
	case "share", "get", "ls", "revoke":
		latest = update.Check(ctx, 1500*time.Millisecond)
	}

	var err error
	switch os.Args[1] {
	case "share":
		err = cmdShare(ctx, cfg, os.Args[2:])
	case "get":
		err = cmdGet(ctx, cfg, os.Args[2:])
	case "ls":
		err = cmdLs(ctx, cfg)
	case "revoke":
		err = cmdRevoke(ctx, cfg, os.Args[2:])
	case "daemon":
		err = cmdDaemon(ctx, cfg, os.Args[2:])
	case "update":
		err = cmdUpdate(ctx, cfg)
	case "mcp":
		err = mcp.Run(ctx, cfg)
	case "version":
		fmt.Println("beeline", config.Version)
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "beeline: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "beeline:", err)
		os.Exit(1)
	}
	if tag := latest(); tag != "" && update.Newer(config.Version, tag) {
		fmt.Fprintf(os.Stderr, "  beeline %s is available, run: beeline update\n", strings.TrimPrefix(tag, "v"))
	}
}

func cmdDaemon(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return daemon.Run(ctx, cfg)
	}
	dc := daemon.Dial(cfg.Socket)
	switch args[0] {
	case "status":
		st, err := dc.Status(ctx)
		if err != nil {
			fmt.Println("  not running")
			return nil
		}
		fmt.Printf("  beeline %s · pid %d · up %s · %d share(s)", st.Version, st.PID, shortDur(time.Duration(st.UptimeS)*time.Second), st.Shares)
		if st.Restoring {
			fmt.Print(" · re-hosting")
		}
		fmt.Println()
		if st.PortMapping.External != "" {
			fmt.Printf("  port mapping: %s %s\n", st.PortMapping.Kind, st.PortMapping.External)
		} else {
			fmt.Printf("  port mapping: none (forward UDP %d to this machine for browser transfers)\n", st.Port)
		}
		return nil
	case "stop":
		was, err := daemon.Stop(ctx, cfg)
		if err != nil {
			return err
		}
		if !was {
			fmt.Println("  not running")
			return nil
		}
		fmt.Println("  stopped · shares are kept and come back with the next daemon")
		return nil
	case "restart":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return restartDaemon(ctx, cfg, exe)
	default:
		return fmt.Errorf("usage: beeline daemon [stop|restart|status]")
	}
}

// restartDaemon stops the running daemon (if any) and starts exe, then
// reports how many shares came back from ~/.beeline/shares.json.
func restartDaemon(ctx context.Context, cfg config.Config, exe string) error {
	if _, err := daemon.Stop(ctx, cfg); err != nil {
		return err
	}
	dc, err := daemon.Start(ctx, cfg, exe)
	if err != nil {
		return err
	}
	st, err := dc.WaitRestored(ctx, 20*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("  daemon restarted, %d share(s) re-hosted\n", st.Shares)
	return nil
}

func cmdUpdate(ctx context.Context, cfg config.Config) error {
	var rel update.Release
	var err error
	pinned := os.Getenv("BEELINE_VERSION")
	if pinned != "" {
		rel, err = update.Latest(ctx, 10*time.Second)
		if err != nil {
			return err
		}
		if rel.Tag != pinned {
			// Not the latest: build the asset list from the release URL pattern.
			rel = update.Release{Tag: pinned, Assets: map[string]string{}}
			base := "https://github.com/beeline-sh/beeline-cli/releases/download/" + pinned + "/"
			rel.Assets[update.AssetName(pinned)] = base + update.AssetName(pinned)
			rel.Assets["checksums.txt"] = base + "checksums.txt"
		}
	} else {
		rel, err = update.Latest(ctx, 10*time.Second)
		if err != nil {
			return fmt.Errorf("checking for updates: %w", err)
		}
		if !update.Newer(config.Version, rel.Tag) {
			fmt.Printf("  beeline %s is the latest\n", config.Version)
			return nil
		}
	}
	fmt.Printf("  downloading beeline %s...\n", strings.TrimPrefix(rel.Tag, "v"))
	exe, err := update.Apply(ctx, rel)
	if err != nil {
		return err
	}
	fmt.Printf("  updated to %s\n", strings.TrimPrefix(rel.Tag, "v"))
	if _, err := daemon.Dial(cfg.Socket).Status(ctx); err == nil {
		return restartDaemon(ctx, cfg, exe)
	}
	return nil
}

func cmdShare(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	name := fs.String("name", "", "display name")
	expires := fs.String("expires", "7d", "lifetime (24h, 7d, 0 = until revoked)")
	maxDl := fs.Int("max-downloads", 0, "stop after N completed downloads")
	relay := fs.String("relay", cfg.Relay, "auto | never")
	wait := fs.Bool("wait", false, "stay attached: show receivers live; ctrl-c revokes, d detaches")
	if err := parseArgs(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: beeline share <path|->")
	}
	path := fs.Arg(0)
	if path == "-" {
		if *name == "" {
			*name = "stdin"
		}
		p, err := spoolStdin(*name)
		if err != nil {
			return err
		}
		path = p
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return err
	}
	d, err := ui.Duration(*expires)
	if err != nil {
		return err
	}
	dc, err := daemon.Ensure(ctx, cfg)
	if err != nil {
		return err
	}
	info, err := dc.Share(ctx, daemon.ShareRequest{Path: abs, Name: *name, ExpiresIn: int64(d.Seconds()), MaxDownloads: *maxDl, Relay: *relay})
	if err != nil {
		return err
	}
	fmt.Printf("  %s   %s\n", info.Name, ui.Size(info.Size))
	if info.Files > 1 {
		fmt.Printf("  %d files\n", info.Files)
	}
	fmt.Printf("  %s\n", info.Link)
	var notes []string
	if !*wait {
		notes = append(notes, "serving in the background · beeline ls to see it")
	}
	if info.ExpiresAt > 0 {
		notes = append(notes, "expires in "+shortDur(time.Until(time.Unix(info.ExpiresAt, 0))))
	}
	if info.DownloadsLeft > 0 {
		notes = append(notes, fmt.Sprintf("up to %d downloads", info.DownloadsLeft))
	}
	if len(notes) > 0 {
		fmt.Printf("  %s\n", strings.Join(notes, " · "))
	}
	if *wait {
		return waitShare(ctx, cfg, dc, info.ID)
	}
	return nil
}

// spoolStdin copies stdin to ~/.beeline/spool so it has a size and can be re-read.
func spoolStdin(name string) (string, error) {
	dir := filepath.Join(config.DataDir(), "spool")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(name)))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, os.Stdin); err != nil {
		f.Close()
		return "", err
	}
	return p, f.Close()
}

func cmdGet(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	out := fs.String("o", ".", "destination directory")
	if err := parseArgs(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: beeline get <link> [-o DIR]")
	}
	l, err := link.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	var lastLine string
	var header bool
	var started time.Time
	render := func(p peer.Progress) {
		switch p.State {
		case "connecting":
			lastLine = "  connecting..."
		case "waiting-host":
			lastLine = "  waiting for the other side to come online..."
		case "transferring":
			if !header {
				fmt.Fprintf(os.Stderr, "\r\033[K  %s   %s   %s\n", p.Name, ui.Size(p.Size), transportLabel(p.Transport))
				header = true
				started = time.Now()
			}
			frac := 1.0
			if p.Size > 0 {
				frac = float64(p.Received) / float64(p.Size)
			}
			lastLine = fmt.Sprintf("  %s  %3.0f%%   %s   %s left", ui.Bar(frac, 24), frac*100, ui.Rate(p.BPS), ui.ETA(p.Size-p.Received, p.BPS))
		default:
			return
		}
		fmt.Fprintf(os.Stderr, "\r\033[K%s", lastLine)
	}
	p, err := peer.Receive(ctx, cfg, l, *out, render)
	fmt.Fprint(os.Stderr, "\r\033[K")
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	if started.IsZero() {
		elapsed = 0
	}
	if sec := elapsed.Seconds(); sec > 0 && p.Size > 0 {
		fmt.Printf("  ✓ saved to %s   in %s (%s)   sha256 root %s...\n", p.Path, ui.Secs(sec), ui.Rate(float64(p.Size)/sec), p.Root[:12])
	} else {
		fmt.Printf("  ✓ saved to %s   sha256 root %s...\n", p.Path, p.Root[:12])
	}
	return nil
}

func cmdLs(ctx context.Context, cfg config.Config) error {
	dc := daemon.Dial(cfg.Socket)
	shares, err := dc.Shares(ctx)
	if err != nil {
		if _, serr := dc.Status(ctx); serr != nil {
			fmt.Println("  no daemon running · nothing shared")
			return nil
		}
		return err
	}
	if len(shares) == 0 {
		fmt.Println("  nothing shared")
		return nil
	}
	for _, s := range shares {
		fmt.Printf("  %s  %-28s %9s   %s\n", s.ID, trunc(s.Name, 28), ui.Size(s.Size), peersLabel(s))
		for _, p := range s.Peers {
			fmt.Printf("          %s  %3.0f%%   %s   %s\n", ui.Bar(p.Progress, 16), p.Progress*100, ui.Rate(p.BPS), transportLabel(p.Transport))
		}
		printDownloads(s.Downloads, 5)
	}
	return nil
}

// printDownloads lists the last n finished transfers of a share.
func printDownloads(ds []host.Download, n int) {
	if len(ds) == 0 {
		return
	}
	start := 0
	if len(ds) > n {
		start = len(ds) - n
	}
	for _, d := range ds[start:] {
		bps := 0.0
		if d.Seconds > 0 {
			bps = float64(d.Bytes) / d.Seconds
		}
		fmt.Printf("          ✓ %s in %s  %s  %s  %s\n", ui.Size(d.Bytes), ui.Secs(d.Seconds), ui.Rate(bps), transportLabel(d.Transport), ui.Ago(d.FinishedAt))
	}
	if start > 0 {
		fmt.Printf("          (+%d earlier)\n", start)
	}
}

func cmdRevoke(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: beeline revoke <id>|all")
	}
	dc := daemon.Dial(cfg.Socket)
	if args[0] != "all" {
		if err := dc.Revoke(ctx, args[0]); err != nil {
			return err
		}
		fmt.Printf("  revoked %s\n", args[0])
		return nil
	}
	shares, err := dc.Shares(ctx)
	if err != nil {
		return err
	}
	if len(shares) == 0 {
		fmt.Println("  nothing shared")
		return nil
	}
	for _, s := range shares {
		if err := dc.Revoke(ctx, s.ID); err != nil {
			return fmt.Errorf("revoke %s: %w", s.ID, err)
		}
		fmt.Printf("  revoked %s  %s\n", s.ID, s.Name)
	}
	return nil
}

func peersLabel(s host.Info) string {
	n := len(s.Peers)
	var b strings.Builder
	switch n {
	case 0:
		b.WriteString("waiting")
	case 1:
		b.WriteString("1 peer")
	default:
		fmt.Fprintf(&b, "%d peers", n)
	}
	if n := len(s.Downloads); n == 1 {
		b.WriteString(" · 1 delivered")
	} else if n > 1 {
		fmt.Fprintf(&b, " · %d delivered", n)
	}
	if s.ExpiresAt > 0 {
		fmt.Fprintf(&b, " · %s left", shortDur(time.Until(time.Unix(s.ExpiresAt, 0))))
	}
	if s.DownloadsLeft > 0 {
		fmt.Fprintf(&b, " · %d downloads left", s.DownloadsLeft)
	}
	return b.String()
}

func transportLabel(kind string) string {
	switch kind {
	case "quic":
		return "direct/quic"
	case "webtransport":
		return "direct/wt"
	case "webrtc":
		return "webrtc"
	}
	return kind
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "..."
}

func shortDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// parseArgs lets flags appear after positional arguments
// (`beeline get <link> -o DIR`), which the standard flag package refuses.
func parseArgs(fs *flag.FlagSet, args []string) error {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") {
				if f := fs.Lookup(name); f != nil {
					if bv, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bv.IsBoolFlag() {
						if i+1 < len(args) {
							i++
							flags = append(flags, args[i])
						}
					}
				}
			}
			continue
		}
		pos = append(pos, a)
	}
	return fs.Parse(append(flags, pos...))
}
