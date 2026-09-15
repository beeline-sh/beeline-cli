package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/stun/v3"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// ALPN identifiers.
const (
	ALPNBeeline = "beeline/1"
	ALPNH3      = "h3"
)

// Endpoint is one UDP socket shared by QUIC (listen and dial), STUN and hole
// punching. quic-go hands us every non-QUIC datagram through
// ReadNonQUICPacket, which is how STUN answers reach us on the same port.
type Endpoint struct {
	// Auth blocks addresses that keep failing AUTH (see AuthLimiter).
	Auth *AuthLimiter
	udp  *net.UDPConn
	tr   *quic.Transport
	ln   *quic.Listener

	stunMu sync.Mutex
}

// Listen binds a UDP socket on port (0 = ephemeral). If the port is taken, an
// ephemeral one is used instead.
func Listen(port int) (*Endpoint, error) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil && port != 0 {
		udp, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	}
	if err != nil {
		return nil, err
	}
	return &Endpoint{udp: udp, tr: &quic.Transport{Conn: udp}, Auth: NewAuthLimiter()}, nil
}

func (e *Endpoint) Port() int { return e.udp.LocalAddr().(*net.UDPAddr).Port }

// LocalAddrs lists the reachable unicast addresses of this machine with our port.
func (e *Endpoint) LocalAddrs() []string {
	port := strconv.Itoa(e.Port())
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsMulticast() {
				continue
			}
			out = append(out, net.JoinHostPort(ipn.IP.String(), port))
		}
	}
	return out
}

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		MaxIdleTimeout:                 45 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		MaxIncomingStreams:             32,
		InitialStreamReceiveWindow:     4 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 8 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
	}
}

// STUN asks server (host:port) for our public address, using our own socket.
func (e *Endpoint) STUN(ctx context.Context, server string) (string, error) {
	e.stunMu.Lock()
	defer e.stunMu.Unlock()
	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return "", err
	}
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := e.tr.WriteTo(req.Raw, addr); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	buf := make([]byte, 1500)
	for {
		n, _, err := e.tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			return "", fmt.Errorf("stun: %w", err)
		}
		m := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := m.Decode(); err != nil || m.TransactionID != req.TransactionID {
			continue // a hole-punch datagram or someone else's packet
		}
		var xor stun.XORMappedAddress
		if err := xor.GetFrom(m); err != nil {
			return "", fmt.Errorf("stun: %w", err)
		}
		return net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), nil
	}
}

// Punch sends a few non-QUIC datagrams to each address so our NAT opens a
// mapping toward the peer before it dials us.
func (e *Endpoint) Punch(addrs []string) {
	var targets []*net.UDPAddr
	for _, a := range addrs {
		if ua, err := net.ResolveUDPAddr("udp", a); err == nil {
			targets = append(targets, ua)
		}
	}
	// First byte 0x00 has the QUIC fixed bit clear, so the other side's
	// transport treats it as a non-QUIC packet and drops it.
	pkt := []byte("\x00beeline-punch")
	for i := 0; i < 3; i++ {
		for _, t := range targets {
			_, _ = e.tr.WriteTo(pkt, t)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Serve accepts QUIC connections until ctx ends. Connections negotiating h3
// go to the WebTransport server; beeline/1 streams go to onStream.
func (e *Endpoint) Serve(ctx context.Context, tlsConf *tls.Config, onStream func(Conn), wt *webtransport.Server) error {
	ln, err := e.tr.Listen(tlsConf, quicConfig())
	if err != nil {
		return err
	}
	e.ln = ln
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !e.Auth.Allow(conn.RemoteAddr().String()) {
			_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "rate limited")
			continue
		}
		switch conn.ConnectionState().TLS.NegotiatedProtocol {
		case ALPNH3:
			if wt == nil {
				_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "no webtransport")
				continue
			}
			go func() { _ = wt.ServeQUICConn(conn) }()
		default:
			go func() {
				for {
					st, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go onStream(withRemote(NewStreamConn("quic", st, nil), conn.RemoteAddr().String()))
				}
			}()
		}
	}
}

// Dial opens a QUIC connection to addr, verifying the certificate by hash
// only, and returns its first stream.
func (e *Endpoint) Dial(ctx context.Context, addr string, certHash [32]byte) (Conn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "beeline",
		NextProtos:         []string{ALPNBeeline},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || sha256.Sum256(raw[0]) != certHash {
				return errors.New("certificate hash mismatch")
			}
			return nil
		},
	}
	conn, err := e.tr.Dial(ctx, ua, tlsConf, quicConfig())
	if err != nil {
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "")
		return nil, err
	}
	return NewStreamConn("quic", st, func() {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "done")
	}), nil
}

// Close releases the socket.
func (e *Endpoint) Close() error {
	if e.ln != nil {
		_ = e.ln.Close()
	}
	_ = e.tr.Close()
	return e.udp.Close()
}
