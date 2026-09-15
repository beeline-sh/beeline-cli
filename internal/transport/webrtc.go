package transport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pion/webrtc/v4"

	"go.beeline.sh/cli/internal/signal"
)

// RTC is one peer connection with the single negotiated "beeline" channel.
type RTC struct {
	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	Conn   Conn
	opened chan struct{}
	failed chan struct{}
}

func iceConfig(ice []signal.ICEServer, relay bool) webrtc.Configuration {
	var servers []webrtc.ICEServer
	for _, s := range ice {
		var urls []string
		for _, u := range s.URLs {
			if !relay && strings.HasPrefix(u, "turn") {
				continue
			}
			urls = append(urls, u)
		}
		if len(urls) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: urls}
		if s.Username != "" {
			srv.Username = s.Username
			srv.Credential = s.Credential
		}
		servers = append(servers, srv)
	}
	return webrtc.Configuration{ICEServers: servers}
}

func newRTC(ice []signal.ICEServer, relay bool, sendICE func(json.RawMessage)) (*RTC, error) {
	pc, err := webrtc.NewPeerConnection(iceConfig(ice, relay))
	if err != nil {
		return nil, err
	}
	negotiated, ordered := true, false
	id := uint16(0)
	dc, err := pc.CreateDataChannel("beeline", &webrtc.DataChannelInit{Negotiated: &negotiated, ID: &id, Ordered: &ordered})
	if err != nil {
		pc.Close()
		return nil, err
	}
	r := &RTC{pc: pc, dc: dc, opened: make(chan struct{}), failed: make(chan struct{})}
	r.Conn = NewDataChannelConn(pc, dc)
	dc.OnOpen(func() { close(r.opened) })
	var failOnce bool
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if (s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed) && !failOnce {
			failOnce = true
			close(r.failed)
		}
	})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			sendICE(json.RawMessage("null"))
			return
		}
		b, err := json.Marshal(c.ToJSON())
		if err == nil {
			sendICE(b)
		}
	})
	return r, nil
}

// HostAnswer answers a peer's offer. sendICE is called from pion goroutines
// with each local candidate (or null) and must be safe to call concurrently.
func HostAnswer(ice []signal.ICEServer, relay bool, offerSDP string, sendICE func(json.RawMessage)) (*RTC, string, error) {
	r, err := newRTC(ice, relay, sendICE)
	if err != nil {
		return nil, "", err
	}
	if err := r.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offerSDP}); err != nil {
		r.Close()
		return nil, "", err
	}
	answer, err := r.pc.CreateAnswer(nil)
	if err != nil {
		r.Close()
		return nil, "", err
	}
	if err := r.pc.SetLocalDescription(answer); err != nil {
		r.Close()
		return nil, "", err
	}
	return r, r.pc.LocalDescription().SDP, nil
}

// PeerOffer creates the offer side.
func PeerOffer(ice []signal.ICEServer, relay bool, sendICE func(json.RawMessage)) (*RTC, string, error) {
	r, err := newRTC(ice, relay, sendICE)
	if err != nil {
		return nil, "", err
	}
	offer, err := r.pc.CreateOffer(nil)
	if err != nil {
		r.Close()
		return nil, "", err
	}
	if err := r.pc.SetLocalDescription(offer); err != nil {
		r.Close()
		return nil, "", err
	}
	return r, r.pc.LocalDescription().SDP, nil
}

// SetAnswer applies the host's answer on the offer side.
func (r *RTC) SetAnswer(sdp string) error {
	return r.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp})
}

// AddICE applies a remote candidate; JSON null (end of candidates) is a no-op.
func (r *RTC) AddICE(raw json.RawMessage) error {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return nil
	}
	var c webrtc.ICECandidateInit
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	if c.Candidate == "" {
		return nil
	}
	return r.pc.AddICECandidate(c)
}

// WaitOpen blocks until the data channel opens, the connection fails, or ctx ends.
func (r *RTC) WaitOpen(ctx context.Context) error {
	select {
	case <-r.opened:
		return nil
	case <-r.failed:
		return errors.New("webrtc: connection failed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the peer connection.
func (r *RTC) Close() { _ = r.Conn.Close() }
