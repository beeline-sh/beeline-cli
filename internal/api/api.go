// Package api is the introduction server's HTTP API (PROTOCOL §3).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.beeline.sh/cli/internal/signal"
)

type Client struct {
	Base string
	HTTP *http.Client
}

func New(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 20 * time.Second}}
}

type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("server: HTTP %d", e.Status)
	}
	return "server: " + e.Code + ": " + e.Message
}

type ShareResp struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type ShareStatus struct {
	ID        string `json:"id"`
	Online    bool   `json:"online"`
	ExpiresAt int64  `json:"expires_at"`
}

type Info struct {
	Version string             `json:"version"`
	ICE     []signal.ICEServer `json:"ice"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, auth string, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		e := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(data, e)
		return e
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// CreateShare registers a new id. expiresIn <= 0 asks for the server maximum.
func (c *Client) CreateShare(ctx context.Context, expiresIn time.Duration) (ShareResp, error) {
	body := map[string]any{}
	if expiresIn > 0 {
		body["expires_in"] = int64(expiresIn.Seconds())
	} else {
		body["expires_in"] = int64(30 * 24 * 3600)
	}
	var r ShareResp
	err := c.do(ctx, http.MethodPost, "/v1/shares", body, "", &r)
	return r, err
}

func (c *Client) DeleteShare(ctx context.Context, id, token string) error {
	return c.do(ctx, http.MethodDelete, "/v1/shares/"+id, nil, token, nil)
}

func (c *Client) Share(ctx context.Context, id string) (ShareStatus, error) {
	var s ShareStatus
	err := c.do(ctx, http.MethodGet, "/v1/shares/"+id, nil, "", &s)
	return s, err
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	var i Info
	err := c.do(ctx, http.MethodGet, "/v1/info", nil, "", &i)
	return i, err
}
