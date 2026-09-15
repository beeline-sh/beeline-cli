package transport

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/wire"
)

// dialReverse plays the host's part of a reverse-dialed stream: AUTH, then ACK.
func dialReverse(t *testing.T, ctx context.Context, from *Endpoint, to *Listener, auth []byte) Conn {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(to.ep.Port()))
	c, err := from.Dial(ctx, addr, to.cert.Hash)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	nonce, _ := link.Nonce(16)
	if err := c.WriteFrame(wire.Frame{Type: wire.TAuth, Payload: append(nonce, link.Proof(auth, "stream", nonce)...)}); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := c.WriteFrame(wire.Frame{Type: wire.TManifestAck}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	return c
}

func TestReverseAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	peerEp, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer peerEp.Close()
	lst, err := NewListener(ctx, peerEp)
	if err != nil {
		t.Fatal(err)
	}
	hostEp, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer hostEp.Close()

	auth := []byte("0123456789abcdef0123456789abcdef")
	inc := lst.Register("abcdef", auth)
	defer lst.Unregister(inc)

	hostConn := dialReverse(t, ctx, hostEp, lst, auth)
	defer hostConn.Close()

	peerConn, err := inc.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer peerConn.Close()
	if peerConn.Kind() != "quic" {
		t.Fatalf("kind %q", peerConn.Kind())
	}

	// the accepted stream carries §7 frames both ways
	if err := peerConn.WriteFrame(wire.Frame{Type: wire.TReq, First: 3, Count: 2}); err != nil {
		t.Fatal(err)
	}
	f, err := hostConn.ReadFrame()
	if err != nil || f.Type != wire.TReq || f.First != 3 || f.Count != 2 {
		t.Fatalf("host got %+v err=%v", f, err)
	}
}

func TestReverseAcceptRefusesBadAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	peerEp, _ := Listen(0)
	defer peerEp.Close()
	lst, err := NewListener(ctx, peerEp)
	if err != nil {
		t.Fatal(err)
	}
	hostEp, _ := Listen(0)
	defer hostEp.Close()

	inc := lst.Register("abcdef", []byte("right-key-right-key-right-key-00"))
	defer lst.Unregister(inc)

	c := dialReverse(t, ctx, hostEp, lst, []byte("wrong-key-wrong-key-wrong-key-00"))
	defer c.Close()
	f, err := c.ReadFrame()
	if err != nil || f.Type != wire.TError {
		t.Fatalf("expected ERROR, got %+v err=%v", f, err)
	}
	actx, acancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer acancel()
	if _, err := inc.Accept(actx); err == nil {
		t.Fatal("bad auth must not deliver a stream")
	}
}
