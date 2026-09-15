package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/host"
	"go.beeline.sh/cli/internal/peer"
)

// Client talks to the daemon over its unix socket.
type Client struct {
	http *http.Client
}

// Dial returns a client for socket. Nothing is connected until the first call.
func Dial(socket string) *Client {
	return &Client{http: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 0,
	}}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://beeline"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("daemon: HTTP %d", resp.StatusCode)
		}
		return errors.New(e.Error)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var s Status
	err := c.do(ctx, http.MethodGet, "/status", nil, &s)
	return s, err
}

// Shutdown asks the daemon to exit without revoking anything.
func (c *Client) Shutdown(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/shutdown", nil, nil)
}

// WaitRestored blocks until the daemon has finished re-hosting persisted
// shares, or timeout passes. Returns the last status seen.
func (c *Client) WaitRestored(ctx context.Context, timeout time.Duration) (Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := c.Status(ctx)
		if err != nil {
			return st, err
		}
		if !st.Restoring || time.Now().After(deadline) {
			return st, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func (c *Client) Shares(ctx context.Context) ([]host.Info, error) {
	var out []host.Info
	err := c.do(ctx, http.MethodGet, "/shares", nil, &out)
	return out, err
}

func (c *Client) Share(ctx context.Context, req ShareRequest) (host.Info, error) {
	var out host.Info
	err := c.do(ctx, http.MethodPost, "/shares", req, &out)
	return out, err
}

func (c *Client) Revoke(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/shares/"+id, nil, nil)
}

func (c *Client) Receive(ctx context.Context, req ReceiveRequest) (string, error) {
	var out struct {
		Job string `json:"job"`
	}
	err := c.do(ctx, http.MethodPost, "/receive", req, &out)
	return out.Job, err
}

func (c *Client) ReceiveStatus(ctx context.Context, job string) (peer.Progress, error) {
	var p peer.Progress
	err := c.do(ctx, http.MethodGet, "/receive/"+job, nil, &p)
	return p, err
}

// Ensure returns a client to a running daemon, starting one detached if needed.
func Ensure(ctx context.Context, cfg config.Config) (*Client, error) {
	c := Dial(cfg.Socket)
	if _, err := c.Status(ctx); err == nil {
		return c, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return Start(ctx, cfg, exe)
}

// Start launches `exe daemon` detached and waits for its socket. exe is
// explicit so an updater can start the freshly installed binary.
func Start(ctx context.Context, cfg config.Config, exe string) (*Client, error) {
	c := Dial(cfg.Socket)
	logPath := filepath.Join(config.DataDir(), "daemon.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = os.Environ()
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting daemon: %w", err)
	}
	_ = cmd.Process.Release()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Status(ctx); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("daemon did not start; see %s", logPath)
}

// Stop asks a running daemon to exit and waits for its socket to go away.
// Returns false if none was running.
func Stop(ctx context.Context, cfg config.Config) (bool, error) {
	c := Dial(cfg.Socket)
	if _, err := c.Status(ctx); err != nil {
		return false, nil
	}
	if err := c.Shutdown(ctx); err != nil {
		return true, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if _, err := c.Status(ctx); err != nil {
			return true, nil
		}
	}
	return true, errors.New("daemon did not stop within 5s")
}
