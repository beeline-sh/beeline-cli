// Package mcp exposes the daemon as an MCP server over stdio (newline-delimited
// JSON-RPC 2.0). It implements initialize, ping, tools/list and tools/call by
// hand: the surface is small enough that a dependency buys nothing.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/daemon"
	"go.beeline.sh/cli/internal/ui"
)

const protocolVersion = "2025-06-18"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

var tools = []tool{
	{Name: "share_file", Description: "Share a file or folder from this machine. Returns a beeline link the recipient opens in a browser or with `beeline get`. The daemon keeps serving after this call returns.",
		InputSchema: obj(map[string]any{
			"path":          str("Absolute or relative path to a file or folder"),
			"name":          str("Display name (default: base name)"),
			"expires":       str("Lifetime such as 24h, 7d; 0 = until revoked (default 7d)"),
			"max_downloads": num("Stop serving after this many completed downloads (default unlimited)"),
		}, "path")},
	{Name: "share_text", Description: "Share a piece of text as a file, for output too large for the chat.",
		InputSchema: obj(map[string]any{
			"text":    str("The content to share"),
			"name":    str("File name (default: share.txt)"),
			"expires": str("Lifetime such as 24h, 7d (default 7d)"),
		}, "text")},
	{Name: "receive", Description: "Download a beeline link into a directory. Blocks until the transfer finishes and returns the saved path and root hash.",
		InputSchema: obj(map[string]any{
			"link": str("The full beeline link including the part after #"),
			"dest": str("Destination directory (default: current directory)"),
		}, "link")},
	{Name: "list_shares", Description: "List active shares with connected peers, progress and speed.", InputSchema: obj(map[string]any{})},
	{Name: "revoke", Description: "Stop serving a share immediately.", InputSchema: obj(map[string]any{"id": str("The 6-character share id")}, "id")},
}

// Run serves MCP on stdin/stdout until EOF.
func Run(ctx context.Context, cfg config.Config) error {
	s := &server{cfg: cfg, out: os.Stdout}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var wg sync.WaitGroup
	defer wg.Wait() // finish in-flight calls before exiting on EOF
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.reply(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // notification
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, req)
		}()
	}
	return sc.Err()
}

type server struct {
	cfg config.Config
	out io.Writer
	wmu sync.Mutex
	dc  *daemon.Client
}

func (s *server) reply(r response) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.out.Write(append(b, '\n'))
}

func (s *server) client(ctx context.Context) (*daemon.Client, error) {
	if s.dc != nil {
		return s.dc, nil
	}
	c, err := daemon.Ensure(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	s.dc = c
	return c, nil
}

func (s *server) handle(ctx context.Context, req request) {
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "beeline", "version": config.Version},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{-32602, "invalid params"}
			break
		}
		text, err := s.call(ctx, p.Name, p.Args)
		if err != nil {
			resp.Result = callResult{Content: []content{{Type: "text", Text: err.Error()}}, IsError: true}
		} else {
			resp.Result = callResult{Content: []content{{Type: "text", Text: text}}}
		}
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	s.reply(resp)
}

func (s *server) call(ctx context.Context, name string, raw json.RawMessage) (string, error) {
	var a struct {
		Path         string `json:"path"`
		Name         string `json:"name"`
		Expires      string `json:"expires"`
		MaxDownloads int    `json:"max_downloads"`
		Text         string `json:"text"`
		Link         string `json:"link"`
		Dest         string `json:"dest"`
		ID           string `json:"id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return "", fmt.Errorf("bad arguments: %w", err)
		}
	}
	dc, err := s.client(ctx)
	if err != nil {
		return "", err
	}
	switch name {
	case "share_file":
		return s.share(ctx, dc, a.Path, a.Name, a.Expires, a.MaxDownloads)
	case "share_text":
		if a.Name == "" {
			a.Name = "share.txt"
		}
		dir := filepath.Join(config.DataDir(), "spool")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		p := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(a.Name)))
		if err := os.WriteFile(p, []byte(a.Text), 0o600); err != nil {
			return "", err
		}
		return s.share(ctx, dc, p, a.Name, a.Expires, a.MaxDownloads)
	case "receive":
		job, err := dc.Receive(ctx, daemon.ReceiveRequest{Link: a.Link, Dest: a.Dest})
		if err != nil {
			return "", err
		}
		for {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			p, err := dc.ReceiveStatus(ctx, job)
			if err != nil {
				return "", err
			}
			switch p.State {
			case "done":
				return fmt.Sprintf("saved %s (%s) to %s\nsha256 root %s\ntransport %s", p.Name, ui.Size(p.Size), p.Path, p.Root, p.Transport), nil
			case "error":
				return "", fmt.Errorf("receive failed: %s", p.Error)
			}
		}
	case "list_shares":
		shares, err := dc.Shares(ctx)
		if err != nil {
			return "", err
		}
		if len(shares) == 0 {
			return "no active shares", nil
		}
		b, _ := json.MarshalIndent(shares, "", "  ")
		return string(b), nil
	case "revoke":
		if err := dc.Revoke(ctx, a.ID); err != nil {
			return "", err
		}
		return "revoked " + a.ID, nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

func (s *server) share(ctx context.Context, dc *daemon.Client, path, name, expires string, max int) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	d, err := ui.Duration(expires)
	if err != nil {
		return "", err
	}
	info, err := dc.Share(ctx, daemon.ShareRequest{Path: abs, Name: name, ExpiresIn: int64(d.Seconds()), MaxDownloads: max})
	if err != nil {
		return "", err
	}
	exp := "until revoked"
	if info.ExpiresAt > 0 {
		exp = "expires " + time.Unix(info.ExpiresAt, 0).Format(time.RFC3339)
	}
	return fmt.Sprintf("%s  %s\n%s\n%s · id %s", info.Name, ui.Size(info.Size), info.Link, exp, info.ID), nil
}
