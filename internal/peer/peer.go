// Package peer receives a share: signaling, transport race, chunk scheduling,
// verification and resume.
package peer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/manifest"
	"go.beeline.sh/cli/internal/portmap"
	"go.beeline.sh/cli/internal/signal"
	"go.beeline.sh/cli/internal/transport"
	"go.beeline.sh/cli/internal/wire"
)

const (
	inFlight     = 64
	hashWindow   = 256
	maxAttempts  = 3
	helloTimeout = 60 * time.Second
	dialTimeout  = 8 * time.Second
	rtcTimeout   = 20 * time.Second
	doneTimeout  = 15 * time.Second
	defaultSTUN  = "stun.l.google.com:19302"
)

// Progress is reported during and after a transfer.
type Progress struct {
	State     string  `json:"state"` // connecting | waiting-host | transferring | done | error
	Name      string  `json:"name"`
	Size      int64   `json:"size"`
	Received  int64   `json:"received"`
	BPS       float64 `json:"bps"`
	Transport string  `json:"transport"`
	Path      string  `json:"path"`
	Root      string  `json:"root"`
	Error     string  `json:"error,omitempty"`
}

type inbound struct {
	kind string
	raw  json.RawMessage
}

// Receive downloads l into destDir. onProgress may be nil.
func Receive(ctx context.Context, cfg config.Config, l link.Link, destDir string, onProgress func(Progress)) (Progress, error) {
	if onProgress == nil {
		onProgress = func(Progress) {}
	}
	report := func(p Progress) { onProgress(p) }
	prog := Progress{State: "connecting"}
	report(prog)

	keys, err := link.Derive(l.Key)
	if err != nil {
		return prog, err
	}
	sig, err := signal.DialPeer(ctx, l.Server, l.ID, keys)
	if err != nil {
		return prog, err
	}
	defer sig.Close()

	ep, err := transport.Listen(0)
	if err != nil {
		return prog, err
	}
	defer ep.Close()
	addrs := ep.LocalAddrs()
	stuns := signal.STUNServers(sig.Welcome.ICE)
	if len(stuns) == 0 {
		stuns = []string{defaultSTUN}
	}
	for _, s := range stuns {
		if pub, err := ep.STUN(ctx, s); err == nil {
			addrs = append(addrs, pub)
			break
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A router mapping makes the reverse-dial listener reachable for browser
	// hosts behind a port-restricted NAT. Discovery is quick; wait briefly.
	pm := portmap.Start(ctx, ep.Port(), log.New(io.Discard, "", 0))
	defer pm.Close()
	for i := 0; i < 20 && pm.Kind() == "none" && pm.ExternalAddr() == ""; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	addrs = portmap.Merge(addrs, pm.ExternalAddr())

	// We listen too: a browser host cannot, so it dials us (reverse dial).
	lst, err := transport.NewListener(ctx, ep)
	if err != nil {
		return prog, err
	}
	incoming := lst.Register(l.ID, keys.Auth)
	defer lst.Unregister(incoming)
	listen := &signal.Listeners{QUIC: &signal.QUICTransport{Addrs: addrs, CertHash: lst.CertHash()}}
	if len(addrs) > 0 {
		urls := make([]string, 0, len(addrs))
		for _, a := range addrs {
			urls = append(urls, "https://"+a+"/wt/"+l.ID)
		}
		listen.WebTransport = &signal.WTTransport{URLs: urls, CertHash: lst.CertHash()}
	}
	manifestCh := make(chan signal.Manifest, 1)
	rtcMsgs := make(chan inbound, 64)
	hostOnline := make(chan bool, 4)
	errCh := make(chan error, 1)
	go func() {
		for {
			m, err := sig.Recv(ctx)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			switch m.T {
			case "host-online", "host-offline":
				select {
				case hostOnline <- m.T == "host-online":
				default:
				}
			case "from":
				if m.Peer != "" && m.Peer != "host" {
					continue
				}
				kind, raw, err := sig.Open(m.Data)
				if err != nil {
					continue
				}
				switch kind {
				case signal.KindManifest:
					var mf signal.Manifest
					if json.Unmarshal(raw, &mf) == nil {
						select {
						case manifestCh <- mf:
						default:
						}
					}
				case signal.KindSDP, signal.KindICE:
					select {
					case rtcMsgs <- inbound{kind, raw}:
					case <-ctx.Done():
						return
					}
				case signal.KindBye:
					var b signal.Bye
					_ = json.Unmarshal(raw, &b)
					select {
					case errCh <- fmt.Errorf("host ended the session: %s", b.Reason):
					default:
					}
				}
			}
		}
	}()

	sendHello := func() error {
		nonce, err := link.Nonce(16)
		if err != nil {
			return err
		}
		return sig.Send(ctx, "host", signal.Hello{
			K: signal.KindHello, Agent: "cli/" + config.Version,
			Caps: []string{"quic", "webrtc"}, Addrs: addrs, Listen: listen,
			Proof: base64.StdEncoding.EncodeToString(link.Proof(keys.Auth, "hello", nonce)),
			Nonce: base64.StdEncoding.EncodeToString(nonce),
		})
	}
	if sig.Welcome.HostOnline {
		if err := sendHello(); err != nil {
			return prog, err
		}
	} else {
		prog.State = "waiting-host"
		report(prog)
	}

	var mf signal.Manifest
	timer := time.NewTimer(helloTimeout)
	defer timer.Stop()
wait:
	for {
		select {
		case mf = <-manifestCh:
			break wait
		case on := <-hostOnline:
			if on {
				if err := sendHello(); err != nil {
					return prog, err
				}
			}
		case err := <-errCh:
			return prog, err
		case <-ctx.Done():
			return prog, ctx.Err()
		case <-timer.C:
			return prog, errors.New("the other side did not answer; is it still sharing?")
		}
	}

	layout, err := manifest.FromManifest(&mf)
	if err != nil {
		return prog, err
	}
	sink, err := manifest.OpenSink(layout, l.ID, destDir)
	if err != nil {
		return prog, err
	}
	prog.Name, prog.Size, prog.Path = layout.Name, layout.Size, sink.Dest
	prog.Received = sink.ReceivedBytes()
	report(prog)

	conn, err := transport.Race(ctx, candidates(ctx, ep, incoming, sig, keys, cfg, &mf, rtcMsgs))
	if err != nil {
		sink.Suspend()
		return prog, err
	}
	defer conn.Close()
	prog.State, prog.Transport = "transferring", conn.Kind()
	report(prog)

	r := &receiver{sink: sink, conn: conn, chunks: layout.Chunks(), errCh: errCh}
	r.received.Store(prog.Received)

	// progress ticker
	pctx, pcancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		last, lastAt := r.received.Load(), time.Now()
		for {
			select {
			case <-pctx.Done():
				return
			case now := <-t.C:
				cur := r.received.Load()
				p := prog
				p.Received = cur
				if dt := now.Sub(lastAt).Seconds(); dt > 0 {
					p.BPS = float64(cur-last) / dt
				}
				last, lastAt = cur, now
				report(p)
			}
		}
	}()
	err = r.run(ctx)
	pcancel()
	if err != nil {
		sink.Suspend()
		prog.State, prog.Error = "error", err.Error()
		report(prog)
		return prog, err
	}
	if err := sink.Finish(); err != nil {
		return prog, err
	}
	root := sink.Root()
	prog.State, prog.Received, prog.Root, prog.BPS = "done", layout.Size, hex.EncodeToString(root[:]), 0
	report(prog)
	_ = sig.Send(ctx, "host", signal.Bye{K: signal.KindBye, Reason: "done"})
	return prog, nil
}

// candidates builds the transport race for a manifest. Forward: we dial the
// host's QUIC listeners. Reverse (manifest.dial): the host dials ours and the
// candidate resolves when an authenticated, ACKed stream arrives. WebRTC
// runs alongside either way.
func candidates(ctx context.Context, ep *transport.Endpoint, incoming *transport.Incoming, sig *signal.Client, keys link.Keys, cfg config.Config, mf *signal.Manifest, rtcMsgs chan inbound) []transport.Candidate {
	var cands []transport.Candidate
	if mf.Dial {
		cands = append(cands, transport.Candidate{Kind: "incoming", Dial: func(ctx context.Context) (transport.Conn, error) {
			actx, cancel := context.WithTimeout(ctx, dialTimeout)
			defer cancel()
			return incoming.Accept(actx)
		}})
	} else if q := mf.Transports.QUIC; q != nil {
		if hash, ok := transport.ParseHash(q.CertHash); ok {
			for _, a := range q.Addrs {
				addr := a
				cands = append(cands, transport.Candidate{Kind: "quic " + addr, Dial: func(ctx context.Context) (transport.Conn, error) {
					dctx, cancel := context.WithTimeout(ctx, dialTimeout)
					defer cancel()
					c, err := ep.Dial(dctx, addr, hash)
					if err != nil {
						return nil, err
					}
					nonce, err := link.Nonce(16)
					if err != nil {
						c.Close()
						return nil, err
					}
					auth := append(nonce, link.Proof(keys.Auth, "stream", nonce)...)
					if err := c.WriteFrame(wire.Frame{Type: wire.TAuth, Payload: auth}); err != nil {
						c.Close()
						return nil, err
					}
					if err := expectAck(dctx, c); err != nil {
						c.Close()
						return nil, err
					}
					return c, nil
				}})
			}
		}
	}
	if mf.Transports.WebRTC {
		relay := cfg.Relay != "never"
		cands = append(cands, transport.Candidate{Kind: "webrtc", Dial: func(ctx context.Context) (transport.Conn, error) {
			r, offer, err := transport.PeerOffer(sig.Welcome.ICE, relay, func(c json.RawMessage) {
				_ = sig.Send(ctx, "host", signal.ICE{K: signal.KindICE, Candidate: c})
			})
			if err != nil {
				return nil, err
			}
			if err := sig.Send(ctx, "host", signal.SDP{K: signal.KindSDP, Type: "offer", SDP: offer}); err != nil {
				r.Close()
				return nil, err
			}
			go func() {
				for {
					select {
					case m := <-rtcMsgs:
						switch m.kind {
						case signal.KindSDP:
							var s signal.SDP
							if json.Unmarshal(m.raw, &s) == nil && s.Type == "answer" {
								_ = r.SetAnswer(s.SDP)
							}
						case signal.KindICE:
							var i signal.ICE
							if json.Unmarshal(m.raw, &i) == nil {
								_ = r.AddICE(i.Candidate)
							}
						}
					case <-ctx.Done():
						return
					}
				}
			}()
			wctx, cancel := context.WithTimeout(ctx, rtcTimeout)
			defer cancel()
			if err := r.WaitOpen(wctx); err != nil {
				r.Close()
				return nil, err
			}
			if err := expectAck(wctx, r.Conn); err != nil {
				r.Close()
				return nil, err
			}
			return r.Conn, nil
		}})
	}
	return cands
}

// expectAck reads the next frame, which must be MANIFEST-ACK, honouring ctx.
func expectAck(ctx context.Context, c transport.Conn) error {
	f, err := readFrame(ctx, c)
	if err != nil {
		return err
	}
	if f.Type == wire.TError {
		return fmt.Errorf("host refused: %s", f.Payload)
	}
	if f.Type != wire.TManifestAck {
		return errors.New("expected MANIFEST-ACK")
	}
	return nil
}

// readFrame closes the conn if ctx ends first, so the blocking read returns.
func readFrame(ctx context.Context, c transport.Conn) (wire.Frame, error) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// ctx may be cancelled right after a successful read (deferred
			// cancel in the caller); never close a conn whose read completed.
			select {
			case <-done:
				return
			default:
			}
			c.Close()
		case <-done:
		}
	}()
	f, err := c.ReadFrame()
	close(done)
	if err != nil && ctx.Err() != nil {
		return f, ctx.Err()
	}
	return f, err
}

// receiver runs the chunk scheduler on one data stream.
type receiver struct {
	sink   *manifest.Sink
	conn   transport.Conn
	chunks int
	errCh  chan error

	received atomic.Int64

	queue       []int
	outstanding int
	partial     map[int]*partialChunk
	attempts    map[int]int
	winRecv     []int  // chunks received per hash window
	winState    []byte // 0 pending, 1 hash requested, 2 verified
	verified    int
	root        []byte
}

type partialChunk struct {
	buf  []byte
	have int
}

func (r *receiver) windows() int { return (r.chunks + hashWindow - 1) / hashWindow }

func (r *receiver) windowSize(w int) int {
	n := r.chunks - w*hashWindow
	if n > hashWindow {
		n = hashWindow
	}
	return n
}

func (r *receiver) run(ctx context.Context) error {
	r.queue = r.sink.Missing()
	r.partial = map[int]*partialChunk{}
	r.attempts = map[int]int{}
	r.winRecv = make([]int, r.windows())
	r.winState = make([]byte, r.windows())
	for i := 0; i < r.chunks; i++ {
		if r.sink.Has(i) {
			r.winRecv[i/hashWindow]++
		}
	}
	// Windows already complete from a previous run still need the host's hashes.
	for w := range r.winRecv {
		if r.winRecv[w] == r.windowSize(w) {
			if err := r.requestHashes(w); err != nil {
				return err
			}
		}
	}
	if r.chunks == 0 {
		// Nothing to fetch; HASH-REQ 0+0 makes the host send DONE.
		if err := r.conn.WriteFrame(wire.Frame{Type: wire.THashReq}); err != nil {
			return err
		}
	}
	if err := r.fill(); err != nil {
		return err
	}

	var doneTimer *time.Timer
	for !r.finished() {
		if r.allVerified() && r.root == nil && doneTimer == nil {
			doneTimer = time.AfterFunc(doneTimeout, func() { r.conn.Close() })
		}
		f, err := readFrame(ctx, r.conn)
		if err != nil {
			select {
			case e := <-r.errCh:
				return e
			default:
			}
			if r.allVerified() && r.root == nil {
				return errors.New("host closed before confirming the transfer")
			}
			return err
		}
		switch f.Type {
		case wire.TData:
			if err := r.onData(f); err != nil {
				return err
			}
		case wire.THash:
			if err := r.onHash(f); err != nil {
				return err
			}
		case wire.TDone:
			r.root = f.Payload
		case wire.TError:
			return fmt.Errorf("host error %d: %s", f.Code, f.Payload)
		}
		if err := r.fill(); err != nil {
			return err
		}
	}
	if doneTimer != nil {
		doneTimer.Stop()
	}
	if root := r.sink.Root(); string(root[:]) != string(r.root) {
		return errors.New("root hash mismatch: the file changed during the transfer")
	}
	return nil
}

func (r *receiver) allVerified() bool {
	return r.sink.Complete() && r.verified == r.windows()
}

func (r *receiver) finished() bool { return r.allVerified() && r.root != nil }

// fill keeps up to inFlight chunks requested, coalescing consecutive indexes.
func (r *receiver) fill() error {
	for r.outstanding < inFlight && len(r.queue) > 0 {
		first := r.queue[0]
		n := 1
		for n < len(r.queue) && r.queue[n] == first+n && r.outstanding+n < inFlight {
			n++
		}
		r.queue = r.queue[n:]
		r.outstanding += n
		if err := r.conn.WriteFrame(wire.Frame{Type: wire.TReq, First: uint32(first), Count: uint32(n)}); err != nil {
			return err
		}
	}
	return nil
}

func (r *receiver) onData(f wire.Frame) error {
	i := int(f.Index)
	if i >= r.chunks {
		return errors.New("data for chunk out of range")
	}
	_, span := r.sink.ChunkSpan(i)
	if int(f.Offset)+len(f.Payload) > span {
		return errors.New("data exceeds chunk")
	}
	p := r.partial[i]
	if p == nil {
		p = &partialChunk{buf: make([]byte, span)}
		r.partial[i] = p
	}
	copy(p.buf[f.Offset:], f.Payload)
	p.have += len(f.Payload)
	r.received.Add(int64(len(f.Payload)))
	if p.have < span {
		return nil
	}
	delete(r.partial, i)
	r.outstanding--
	if err := r.sink.WriteChunk(i, p.buf); err != nil {
		return err
	}
	w := i / hashWindow
	r.winRecv[w]++
	if r.winRecv[w] == r.windowSize(w) && r.winState[w] == 0 {
		return r.requestHashes(w)
	}
	return nil
}

func (r *receiver) requestHashes(w int) error {
	r.winState[w] = 1
	return r.conn.WriteFrame(wire.Frame{Type: wire.THashReq, First: uint32(w * hashWindow), Count: uint32(r.windowSize(w))})
}

func (r *receiver) onHash(f wire.Frame) error {
	if r.chunks == 0 {
		return nil
	}
	w := int(f.First) / hashWindow
	if int(f.First)%hashWindow != 0 || w >= r.windows() || int(f.Count) != r.windowSize(w) {
		return errors.New("unexpected HASH range")
	}
	bad := r.sink.Verify(int(f.First), f.Payload)
	if len(bad) == 0 {
		if r.winState[w] != 2 {
			r.winState[w] = 2
			r.verified++
		}
		return nil
	}
	r.winState[w] = 0
	for _, i := range bad {
		r.attempts[i]++
		if r.attempts[i] > maxAttempts {
			return fmt.Errorf("chunk %d failed verification %d times", i, maxAttempts)
		}
		_, span := r.sink.ChunkSpan(i)
		r.received.Add(-int64(span))
		r.winRecv[w]--
	}
	r.queue = append(bad, r.queue...)
	return nil
}
