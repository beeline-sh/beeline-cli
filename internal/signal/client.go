package signal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"go.beeline.sh/cli/internal/link"
)

// Error is a server-side error frame.
type Error struct {
	Code, Message string
}

func (e *Error) Error() string { return "server: " + e.Code + ": " + e.Message }

// Client is one signaling connection for one share.
type Client struct {
	ws      *websocket.Conn
	keys    link.Keys
	id      string
	Welcome Message
	cancel  context.CancelFunc
}

func wsURL(server string) string {
	s := strings.TrimRight(server, "/")
	if strings.HasPrefix(s, "https://") {
		return "wss://" + s[len("https://"):]
	}
	if strings.HasPrefix(s, "http://") {
		return "ws://" + s[len("http://"):]
	}
	return s
}

func dial(ctx context.Context, server, id, query string, keys link.Keys) (*Client, error) {
	u := wsURL(server) + "/v1/ws/" + id + "?" + query
	ws, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("signaling: %w", err)
	}
	ws.SetReadLimit(64 << 10)
	c := &Client{ws: ws, keys: keys, id: id}

	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var m Message
	if err := wsjson.Read(wctx, ws, &m); err != nil {
		ws.Close(websocket.StatusProtocolError, "no welcome")
		return nil, fmt.Errorf("signaling: %w", err)
	}
	if m.T == "error" {
		ws.Close(websocket.StatusNormalClosure, "")
		return nil, &Error{Code: m.Code, Message: m.Msg}
	}
	if m.T != "welcome" {
		ws.Close(websocket.StatusProtocolError, "expected welcome")
		return nil, errors.New("signaling: expected welcome")
	}
	c.Welcome = m

	pctx, pcancel := context.WithCancel(context.Background())
	c.cancel = pcancel
	go c.pingLoop(pctx)
	return c, nil
}

// DialHost connects as the sharing device.
func DialHost(ctx context.Context, server, id, token string, keys link.Keys) (*Client, error) {
	return dial(ctx, server, id, "role=host&token="+url.QueryEscape(token), keys)
}

// DialPeer connects as a receiver.
func DialPeer(ctx context.Context, server, id string, keys link.Keys) (*Client, error) {
	return dial(ctx, server, id, "role=peer", keys)
}

func (c *Client) pingLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = wsjson.Write(wctx, c.ws, Message{T: "ping"})
			cancel()
		}
	}
}

// Recv returns the next non-pong frame. Server error frames are returned as *Error.
func (c *Client) Recv(ctx context.Context) (Message, error) {
	for {
		var m Message
		if err := wsjson.Read(ctx, c.ws, &m); err != nil {
			return Message{}, err
		}
		switch m.T {
		case "pong":
			continue
		case "error":
			return m, &Error{Code: m.Code, Message: m.Msg}
		}
		return m, nil
	}
}

// Send seals payload and addresses it to peer ("" or "host" means the host).
func (c *Client) Send(ctx context.Context, to string, payload any) error {
	pt, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(pt) > 48<<10 {
		return errors.New("signaling payload too large")
	}
	sealed, err := link.Seal(c.keys.Sig, c.id, pt)
	if err != nil {
		return err
	}
	m := Message{T: "to", Data: sealed}
	if to != "" && to != "host" {
		m.Peer = to
	}
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return wsjson.Write(wctx, c.ws, m)
}

// Open decrypts a "from" frame's data and returns its kind and raw JSON.
func (c *Client) Open(data string) (string, json.RawMessage, error) {
	pt, err := link.Open(c.keys.Sig, c.id, data)
	if err != nil {
		return "", nil, err
	}
	var k kindOnly
	if err := json.Unmarshal(pt, &k); err != nil {
		return "", nil, err
	}
	return k.K, json.RawMessage(pt), nil
}

// Close ends the connection.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	_ = c.ws.Close(websocket.StatusNormalClosure, "")
}

// STUNServers extracts host:port for every stun: URL in an ICE list.
func STUNServers(ice []ICEServer) []string {
	var out []string
	for _, s := range ice {
		for _, u := range s.URLs {
			if strings.HasPrefix(u, "stun:") {
				hp := strings.TrimPrefix(u, "stun:")
				if i := strings.IndexByte(hp, '?'); i >= 0 {
					hp = hp[:i]
				}
				if !strings.Contains(hp, ":") {
					hp += ":3478"
				}
				out = append(out, hp)
			}
		}
	}
	return out
}
