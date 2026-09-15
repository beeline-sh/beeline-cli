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
)

const usageText = `beeline - files go straight from your device to theirs

usage:
  beeline share <path|-> [--name N] [--expires 24h|7d|0] [--max-downloads N] [--relay auto|never]
  beeline get <link> [-o DIR]
  beeline ls
  beeline revoke <id>|all
  beeline daemon
  beeline mcp
  beeline version

environment:
  BEELINE_SERVER   introduction server (default https://beeline.sh)
  BEELINE_PORT     UDP port for the daemon (default 41820)
  BEELINE_RELAY    auto | never
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
		err = daemon.Run(ctx, cfg)
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
}

func cmdShare(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	name := fs.String("name", "", "display name")
	expires := fs.String("expires", "7d", "lifetime (24h, 7d, 0 = until revoked)")
	maxDl := fs.Int("max-downloads", 0, "stop after N completed downloads")
	relay := fs.String("relay", cfg.Relay, "auto | never")
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
	notes = append(notes, "serving in the background · beeline ls to see it")
	if info.ExpiresAt > 0 {
		notes = append(notes, "expires in "+shortDur(time.Until(time.Unix(info.ExpiresAt, 0))))
	}
	if info.DownloadsLeft > 0 {
		notes = append(notes, fmt.Sprintf("up to %d downloads", info.DownloadsLeft))
	}
	fmt.Printf("  %s\n", strings.Join(notes, " · "))
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
	fmt.Printf("  ✓ saved to %s   sha256 root %s...\n", p.Path, p.Root[:12])
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
	}
	return nil
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
