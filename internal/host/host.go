// Package host serves shares: it registers them with the introduction server,
// answers signaling, and streams chunks over QUIC, WebTransport and WebRTC.
package host

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"

	"go.beeline.sh/cli/internal/api"
	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/signal"
	"go.beeline.sh/cli/internal/transport"
	"go.beeline.sh/cli/internal/wire"
)

const defaultSTUN = "stun.l.google.com:19302"

// Host owns the UDP endpoint and every active share.
type Host struct {
	cfg     config.Config
	api     *api.Client
	ep      *transport.Endpoint
	wt      *webtransport.Server
	tlsConf *tls.Config
	log     *log.Logger
	ctx     context.Context
	cancel  context.CancelFunc

	mu         sync.Mutex
	cert       *transport.Cert
	ice        []signal.ICEServer
	publicAddr string
	shares     map[string]*Share
	pending    []Saved // persisted shares not yet re-hosted (see store.go)
}

// New binds the endpoint, generates a certificate and starts serving.
func New(ctx context.Context, cfg config.Config, logger *log.Logger) (*Host, error) {
	ep, err := transport.Listen(cfg.Port)
	if err != nil {
		return nil, err
	}
	cert, err := transport.NewCert()
	if err != nil {
		ep.Close()
		return nil, err
	}
	hctx, cancel := context.WithCancel(ctx)
	h := &Host{cfg: cfg, api: api.New(cfg.Server), ep: ep, log: logger, ctx: hctx, cancel: cancel, cert: cert, shares: map[string]*Share{}}
	h.tlsConf = &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{transport.ALPNH3, transport.ALPNBeeline},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := h.currentCert()
			return &c.TLS, nil
		},
	}
	h.wt = transport.NewWebTransportServer(h.tlsConf, h.handleStream)

	ictx, icancel := context.WithTimeout(hctx, 8*time.Second)
	if info, err := h.api.Info(ictx); err == nil {
		h.ice = info.ICE
	} else {
		h.log.Printf("server info: %v (continuing with default STUN)", err)
	}
	icancel()
	h.refreshPublic(hctx)

	go func() {
		if err := ep.Serve(hctx, h.tlsConf, func(c transport.Conn) { h.handleStream("", c) }, h.wt); err != nil {
			h.log.Printf("quic serve: %v", err)
		}
	}()
	go h.rotateCerts(hctx)
	h.log.Printf("listening on udp/%d, public %q", ep.Port(), h.publicAddr)
	return h, nil
}

// Port is the UDP port in use.
func (h *Host) Port() int { return h.ep.Port() }

func (h *Host) currentCert() *transport.Cert {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cert
}

func (h *Host) stunServers() []string {
	h.mu.Lock()
	ice := h.ice
	h.mu.Unlock()
	s := signal.STUNServers(ice)
	if len(s) == 0 {
		s = []string{defaultSTUN}
	}
	return s
}

// refreshPublic re-learns our public address; the NAT mapping for our port
// must be fresh when a peer dials.
func (h *Host) refreshPublic(ctx context.Context) string {
	for _, s := range h.stunServers() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		addr, err := h.ep.STUN(sctx, s)
		cancel()
		if err == nil {
			h.mu.Lock()
			h.publicAddr = addr
			h.mu.Unlock()
			return addr
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.publicAddr
}

func (h *Host) rotateCerts(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Until(h.currentCert().NotAfter) > 24*time.Hour {
				continue
			}
			if c, err := transport.NewCert(); err == nil {
				h.mu.Lock()
				h.cert = c
				h.mu.Unlock()
				h.log.Printf("rotated certificate")
			}
		}
	}
}

// handleStream authenticates an incoming QUIC/WebTransport stream and serves it.
// id is known for WebTransport (/wt/<id>), empty for raw QUIC.
func (h *Host) handleStream(id string, c transport.Conn) {
	f, err := c.ReadFrame()
	if err != nil || f.Type != wire.TAuth || len(f.Payload) != 48 {
		_ = c.WriteFrame(wire.ErrorFrame(wire.ErrProtocol, "expected AUTH"))
		c.Close()
		return
	}
	nonce, mac := f.Payload[:16], f.Payload[16:]
	sh := h.authenticate(id, nonce, mac)
	if sh == nil {
		_ = c.WriteFrame(wire.ErrorFrame(wire.ErrProtocol, "unknown share"))
		c.Close()
		return
	}
	if sh.exhausted() {
		_ = c.WriteFrame(wire.ErrorFrame(wire.ErrExhausted, "no downloads left"))
		c.Close()
		return
	}
	if err := c.WriteFrame(wire.Frame{Type: wire.TManifestAck}); err != nil {
		c.Close()
		return
	}
	sh.serve(c, "")
}

func (h *Host) authenticate(id string, nonce, mac []byte) *Share {
	h.mu.Lock()
	defer h.mu.Unlock()
	if id != "" {
		sh := h.shares[id]
		if sh != nil && link.VerifyProof(sh.keys.Auth, "stream", nonce, mac) {
			return sh
		}
		return nil
	}
	for _, sh := range h.shares {
		if link.VerifyProof(sh.keys.Auth, "stream", nonce, mac) {
			return sh
		}
	}
	return nil
}

// Add registers and starts serving a path.
func (h *Host) Add(ctx context.Context, path string, opts Options) (*Share, error) {
	if opts.Relay == "" {
		opts.Relay = h.cfg.Relay
	}
	sh, err := newShare(ctx, h, path, opts)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.shares[sh.ID] = sh
	h.mu.Unlock()
	h.save()
	h.log.Printf("share %s: %s (%d bytes)", sh.ID, sh.Src.Name, sh.Src.Size)
	return sh, nil
}

// Get returns a share by id.
func (h *Host) Get(id string) *Share {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.shares[id]
}

// List returns all shares, oldest first.
func (h *Host) List() []*Share {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Share, 0, len(h.shares))
	for _, sh := range h.shares {
		out = append(out, sh)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CreatedAt.Before(out[j-1].CreatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Remove stops a share. reason: revoked | done | expired | gone.
func (h *Host) Remove(id, reason string) error {
	h.mu.Lock()
	sh := h.shares[id]
	delete(h.shares, id)
	h.mu.Unlock()
	if sh == nil {
		return errors.New("no such share")
	}
	sh.stop(reason)
	h.save()
	h.log.Printf("share %s: %s", id, reason)
	return nil
}

// Close stops everything.
func (h *Host) Close() {
	h.mu.Lock()
	shares := make([]*Share, 0, len(h.shares))
	for _, sh := range h.shares {
		shares = append(shares, sh)
	}
	h.shares = map[string]*Share{}
	h.mu.Unlock()
	for _, sh := range shares {
		sh.stop("gone")
	}
	h.cancel()
	_ = h.ep.Close()
}
