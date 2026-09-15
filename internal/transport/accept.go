package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"

	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/wire"
)

// authTimeout bounds how long an accepted stream may stay silent before AUTH.
const authTimeout = 10 * time.Second

// Listener serves QUIC + WebTransport on an Endpoint for the *receiving*
// side (PROTOCOL §6, reverse dial): a host that cannot listen dials us,
// sends AUTH then MANIFEST-ACK, and the stream is handed to the receive job
// registered for that share.
type Listener struct {
	ep   *Endpoint
	cert *Cert
	tls  *tls.Config
	wt   *webtransport.Server

	mu   sync.Mutex
	jobs map[string]*Incoming
}

// Incoming collects host-dialed streams for one share.
type Incoming struct {
	id   string
	auth []byte
	ch   chan Conn
	done chan struct{}
	once sync.Once
}

// NewListener generates a certificate and starts serving on ep until ctx ends.
func NewListener(ctx context.Context, ep *Endpoint) (*Listener, error) {
	cert, err := NewCert()
	if err != nil {
		return nil, err
	}
	l := &Listener{ep: ep, cert: cert, jobs: map[string]*Incoming{}}
	l.tls = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPNH3, ALPNBeeline},
		Certificates: []tls.Certificate{cert.TLS},
	}
	l.wt = NewWebTransportServer(l.tls, l.handleStream)
	go func() { _ = ep.Serve(ctx, l.tls, func(c Conn) { l.handleStream("", c) }, l.wt) }()
	return l, nil
}

// CertHash is the manifest/hello encoding of the listener certificate hash.
func (l *Listener) CertHash() string { return l.cert.HashB64() }

// Register starts accepting streams for share id; auth is the link's auth key.
func (l *Listener) Register(id string, auth []byte) *Incoming {
	inc := &Incoming{id: id, auth: auth, ch: make(chan Conn), done: make(chan struct{})}
	l.mu.Lock()
	l.jobs[id] = inc
	l.mu.Unlock()
	return inc
}

// Unregister stops accepting for id; streams arriving afterwards are refused.
func (l *Listener) Unregister(inc *Incoming) {
	l.mu.Lock()
	if l.jobs[inc.id] == inc {
		delete(l.jobs, inc.id)
	}
	l.mu.Unlock()
	inc.once.Do(func() { close(inc.done) })
}

// Accept blocks until the host has dialed us and completed AUTH + ACK.
func (inc *Incoming) Accept(ctx context.Context) (Conn, error) {
	select {
	case c := <-inc.ch:
		return c, nil
	case <-inc.done:
		return nil, errors.New("listener closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// handleStream runs the dialer's side of §7 on an accepted stream: AUTH from
// the host, then MANIFEST-ACK, then the stream belongs to the receive job.
// id is known for WebTransport (/wt/<id>), empty for raw QUIC.
func (l *Listener) handleStream(id string, c Conn) {
	authed := make(chan struct{})
	timer := time.AfterFunc(authTimeout, func() {
		select {
		case <-authed:
		default:
			c.Close()
		}
	})
	fail := func(msg string) {
		_ = c.WriteFrame(wire.ErrorFrame(wire.ErrProtocol, msg))
		c.Close()
	}
	f, err := c.ReadFrame()
	if err != nil || f.Type != wire.TAuth || len(f.Payload) != 48 {
		fail("expected AUTH")
		l.authFailed(c)
		return
	}
	inc := l.authenticate(id, f.Payload[:16], f.Payload[16:])
	if inc == nil {
		fail("unknown share")
		l.authFailed(c)
		return
	}
	f, err = c.ReadFrame()
	if err != nil || f.Type != wire.TManifestAck {
		fail("expected MANIFEST-ACK")
		return
	}
	close(authed)
	timer.Stop()
	// The WebTransport handler closes the session when we return, so stay
	// here until the receive job is done with the stream.
	closed := make(chan struct{})
	var once sync.Once
	c = withOnClose(c, func() { once.Do(func() { close(closed) }) })
	select {
	case inc.ch <- c:
		<-closed
	case <-inc.done:
		c.Close() // race already decided
	}
}

func (l *Listener) authFailed(c Conn) {
	if addr := RemoteAddr(c); addr != "" {
		l.ep.Auth.Fail(addr)
	}
}

func (l *Listener) authenticate(id string, nonce, mac []byte) *Incoming {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id != "" {
		inc := l.jobs[id]
		if inc != nil && link.VerifyProof(inc.auth, "stream", nonce, mac) {
			return inc
		}
		return nil
	}
	for _, inc := range l.jobs {
		if link.VerifyProof(inc.auth, "stream", nonce, mac) {
			return inc
		}
	}
	return nil
}
