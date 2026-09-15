package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/manifest"
	"go.beeline.sh/cli/internal/signal"
	"go.beeline.sh/cli/internal/transport"
	"go.beeline.sh/cli/internal/wire"
)

// Options for a share.
type Options struct {
	Name         string
	ExpiresIn    time.Duration // 0 = server maximum
	MaxDownloads int           // 0 = unlimited
	Relay        string        // auto | never
}

// PeerInfo is one connected receiver, as shown by `beeline ls`.
type PeerInfo struct {
	Peer      string  `json:"peer"`
	Transport string  `json:"transport"`
	Progress  float64 `json:"progress"`
	BPS       float64 `json:"bps"`
}

// Info is the daemon-API view of a share.
type Info struct {
	ID            string     `json:"id"`
	Link          string     `json:"link"`
	Name          string     `json:"name"`
	Path          string     `json:"path"`
	Size          int64      `json:"size"`
	Files         int        `json:"files"`
	Peers         []PeerInfo `json:"peers"`
	ExpiresAt     int64      `json:"expires_at"`
	DownloadsLeft int        `json:"downloads_left"` // -1 = unlimited
	CreatedAt     int64      `json:"created_at"`
}

// Share is one served path.
type Share struct {
	ID        string
	Token     string
	Link      link.Link
	Src       *manifest.Source
	Opts      Options
	ExpiresAt int64
	CreatedAt time.Time

	h      *Host
	keys   link.Keys
	cancel context.CancelFunc

	mu            sync.Mutex
	sig           *signal.Client
	downloadsLeft int
	peers         map[string]*peerState
	sessions      map[*session]struct{}
	stopped       bool
	expiry        *time.Timer
}

type peerState struct {
	ip  string
	rtc *transport.RTC
}

type session struct {
	conn          transport.Conn
	peer          string
	start         time.Time
	mu            sync.Mutex
	sent          int64
	lastBytes     int64
	lastAt        time.Time
	bps           float64
	lastRequested bool
	doneSent      bool
}

func (s *session) addBytes(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent += int64(n)
	now := time.Now()
	if s.lastAt.IsZero() {
		s.lastAt = now
		return
	}
	if dt := now.Sub(s.lastAt); dt >= 500*time.Millisecond {
		s.bps = float64(s.sent-s.lastBytes) / dt.Seconds()
		s.lastBytes, s.lastAt = s.sent, now
	}
}

func newShare(ctx context.Context, h *Host, path string, opts Options) (*Share, error) {
	src, err := manifest.FromPath(path, opts.Name)
	if err != nil {
		return nil, err
	}
	key, err := link.NewKey()
	if err != nil {
		return nil, err
	}
	resp, err := h.api.CreateShare(ctx, opts.ExpiresIn)
	if err != nil {
		src.Close()
		return nil, err
	}
	left := -1
	if opts.MaxDownloads > 0 {
		left = opts.MaxDownloads
	}
	sh, err := assemble(h, src, opts, resp.ID, resp.Token, key, resp.ExpiresAt, time.Now(), left)
	if err != nil {
		src.Close()
		return nil, err
	}
	if err := sh.start(ctx); err != nil {
		src.Close()
		_ = h.api.DeleteShare(context.Background(), sh.ID, sh.Token)
		return nil, err
	}
	return sh, nil
}

// resumeShare re-hosts a share persisted by an earlier daemon run: the
// server already knows the id, so only the signaling connection is redone.
func resumeShare(ctx context.Context, h *Host, s Saved) (*Share, error) {
	src, err := manifest.FromPath(s.Path, s.Name)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(s.Key)
	if err != nil {
		src.Close()
		return nil, err
	}
	opts := Options{Name: s.Name, ExpiresIn: time.Duration(s.ExpiresIn) * time.Second, MaxDownloads: s.MaxDownloads, Relay: s.Relay}
	sh, err := assemble(h, src, opts, s.ID, s.Token, key, s.ExpiresAt, time.Unix(s.CreatedAt, 0), s.DownloadsLeft)
	if err != nil {
		src.Close()
		return nil, err
	}
	if err := sh.start(ctx); err != nil {
		src.Close()
		return nil, err
	}
	return sh, nil
}

func assemble(h *Host, src *manifest.Source, opts Options, id, token string, key []byte, expiresAt int64, createdAt time.Time, left int) (*Share, error) {
	keys, err := link.Derive(key)
	if err != nil {
		return nil, err
	}
	return &Share{
		ID: id, Token: token,
		Link: link.Link{Server: h.cfg.Server, ID: id, Key: key},
		Src:  src, Opts: opts, ExpiresAt: expiresAt, CreatedAt: createdAt,
		h: h, keys: keys,
		downloadsLeft: left,
		peers:         map[string]*peerState{},
		sessions:      map[*session]struct{}{},
	}, nil
}

// start opens signaling and begins serving.
func (sh *Share) start(ctx context.Context) error {
	sig, err := signal.DialHost(ctx, sh.h.cfg.Server, sh.ID, sh.Token, sh.keys)
	if err != nil {
		return err
	}
	sh.sig = sig
	sctx, cancel := context.WithCancel(sh.h.ctx)
	sh.cancel = cancel
	if sh.ExpiresAt > 0 {
		if d := time.Until(time.Unix(sh.ExpiresAt, 0)); d > 0 {
			sh.expiry = time.AfterFunc(d, func() { _ = sh.h.Remove(sh.ID, "expired") })
		}
	}
	go sh.loop(sctx)
	return nil
}

// saved is the persisted form of the share (see store.go).
func (sh *Share) saved() Saved {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return Saved{
		ID: sh.ID, Token: sh.Token, Key: base64.StdEncoding.EncodeToString(sh.Link.Key),
		Path: sh.Src.Path, Name: sh.Opts.Name,
		ExpiresIn: int64(sh.Opts.ExpiresIn.Seconds()), MaxDownloads: sh.Opts.MaxDownloads, Relay: sh.Opts.Relay,
		ExpiresAt: sh.ExpiresAt, CreatedAt: sh.CreatedAt.Unix(), DownloadsLeft: sh.downloadsLeft,
	}
}

func (sh *Share) exhausted() bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.stopped || sh.downloadsLeft == 0
}

// Info snapshots the share for the daemon API.
func (sh *Share) Info() Info {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	info := Info{
		ID: sh.ID, Link: sh.Link.String(), Name: sh.Src.Name, Path: sh.Src.Path,
		Size: sh.Src.Size, Files: len(sh.Src.Files), ExpiresAt: sh.ExpiresAt,
		DownloadsLeft: sh.downloadsLeft, CreatedAt: sh.CreatedAt.Unix(), Peers: []PeerInfo{},
	}
	for s := range sh.sessions {
		s.mu.Lock()
		p := PeerInfo{Peer: s.peer, Transport: s.conn.Kind(), BPS: s.bps}
		if sh.Src.Size > 0 {
			p.Progress = float64(s.sent) / float64(sh.Src.Size)
		} else {
			p.Progress = 1
		}
		s.mu.Unlock()
		info.Peers = append(info.Peers, p)
	}
	return info
}

// loop handles signaling for the share, reconnecting when the socket drops.
func (sh *Share) loop(ctx context.Context) {
	backoff := time.Second
	for {
		sh.mu.Lock()
		sig := sh.sig
		sh.mu.Unlock()
		err := sh.run(ctx, sig)
		if ctx.Err() != nil {
			return
		}
		var serr *signal.Error
		if errors.As(err, &serr) {
			switch serr.Code {
			case "not-found", "gone", "unauthorized":
				_ = sh.h.Remove(sh.ID, "gone")
				return
			}
		}
		sh.h.log.Printf("share %s: signaling lost (%v), reconnecting", sh.ID, err)
		sig.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			nsig, err := signal.DialHost(ctx, sh.h.cfg.Server, sh.ID, sh.Token, sh.keys)
			if err == nil {
				sh.mu.Lock()
				sh.sig = nsig
				sh.mu.Unlock()
				backoff = time.Second
				sh.h.log.Printf("share %s: signaling reconnected", sh.ID)
				break
			}
			if errors.As(err, &serr) && (serr.Code == "not-found" || serr.Code == "gone") {
				_ = sh.h.Remove(sh.ID, "gone")
				return
			}
			sh.h.log.Printf("share %s: reconnect failed (%v), retrying in %s", sh.ID, err, backoff*2)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func (sh *Share) run(ctx context.Context, sig *signal.Client) error {
	for {
		m, err := sig.Recv(ctx)
		if err != nil {
			return err
		}
		switch m.T {
		case "peer-join":
			sh.mu.Lock()
			sh.peers[m.Peer] = &peerState{ip: m.IP}
			sh.mu.Unlock()
		case "peer-leave":
			sh.dropPeer(m.Peer)
		case "from":
			kind, raw, err := sig.Open(m.Data)
			if err != nil {
				continue
			}
			sh.handle(ctx, sig, m.Peer, kind, raw)
		}
	}
}

func (sh *Share) dropPeer(peer string) {
	sh.mu.Lock()
	ps := sh.peers[peer]
	delete(sh.peers, peer)
	sh.mu.Unlock()
	if ps != nil && ps.rtc != nil {
		ps.rtc.Close()
	}
}

func (sh *Share) handle(ctx context.Context, sig *signal.Client, peer, kind string, raw json.RawMessage) {
	switch kind {
	case signal.KindHello:
		var h signal.Hello
		if json.Unmarshal(raw, &h) != nil {
			return
		}
		nonce, err1 := base64.StdEncoding.DecodeString(h.Nonce)
		proof, err2 := base64.StdEncoding.DecodeString(h.Proof)
		if err1 != nil || err2 != nil || !link.VerifyProof(sh.keys.Auth, "hello", nonce, proof) {
			return
		}
		if len(h.Addrs) > 0 {
			go sh.h.ep.Punch(h.Addrs)
		}
		sh.h.refreshPublic(ctx)
		_ = sig.Send(ctx, peer, sh.manifest())

	case signal.KindSDP:
		var s signal.SDP
		if json.Unmarshal(raw, &s) != nil || s.Type != "offer" {
			return
		}
		sh.mu.Lock()
		ice := sh.h.ice
		relay := sh.Opts.Relay != "never"
		ps := sh.peers[peer]
		if ps == nil {
			ps = &peerState{}
			sh.peers[peer] = ps
		}
		if ps.rtc != nil {
			ps.rtc.Close()
			ps.rtc = nil
		}
		sh.mu.Unlock()
		rtc, answer, err := transport.HostAnswer(ice, relay, s.SDP, func(c json.RawMessage) {
			_ = sig.Send(ctx, peer, signal.ICE{K: signal.KindICE, Candidate: c})
		})
		if err != nil {
			sh.h.log.Printf("share %s: webrtc answer: %v", sh.ID, err)
			return
		}
		sh.mu.Lock()
		ps.rtc = rtc
		sh.mu.Unlock()
		if err := sig.Send(ctx, peer, signal.SDP{K: signal.KindSDP, Type: "answer", SDP: answer}); err != nil {
			rtc.Close()
			return
		}
		go func() {
			wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := rtc.WaitOpen(wctx); err != nil {
				rtc.Close()
				return
			}
			if sh.exhausted() {
				_ = rtc.Conn.WriteFrame(wire.ErrorFrame(wire.ErrExhausted, "no downloads left"))
				rtc.Close()
				return
			}
			if rtc.Conn.WriteFrame(wire.Frame{Type: wire.TManifestAck}) != nil {
				rtc.Close()
				return
			}
			sh.serve(rtc.Conn, peer)
		}()

	case signal.KindICE:
		var i signal.ICE
		if json.Unmarshal(raw, &i) != nil {
			return
		}
		sh.mu.Lock()
		ps := sh.peers[peer]
		var rtc *transport.RTC
		if ps != nil {
			rtc = ps.rtc
		}
		sh.mu.Unlock()
		if rtc != nil {
			_ = rtc.AddICE(i.Candidate)
		}

	case signal.KindBye:
		sh.dropPeer(peer)
	}
}

func (sh *Share) manifest() signal.Manifest {
	cert := sh.h.currentCert()
	addrs := sh.h.ep.LocalAddrs()
	sh.h.mu.Lock()
	pub := sh.h.publicAddr
	sh.h.mu.Unlock()
	if pub != "" {
		addrs = append(addrs, pub)
	}
	sh.mu.Lock()
	left := sh.downloadsLeft
	sh.mu.Unlock()
	m := signal.Manifest{
		K: signal.KindManifest, Name: sh.Src.Name, Size: sh.Src.Size, Chunk: sh.Src.Chunk,
		Hash: "sha256", Files: sh.Src.Files, ExpiresAt: sh.ExpiresAt, DownloadsLeft: left,
		Transports: signal.Transports{WebRTC: true},
	}
	if len(addrs) > 0 {
		m.Transports.QUIC = &signal.QUICTransport{Addrs: addrs, CertHash: cert.HashB64()}
		urls := make([]string, 0, len(addrs))
		for _, a := range addrs {
			urls = append(urls, "https://"+a+"/wt/"+sh.ID)
		}
		m.Transports.WebTransport = &signal.WTTransport{URLs: urls, CertHash: cert.HashB64()}
	}
	return m
}

// serve answers REQ / HASH-REQ on one authenticated data stream.
func (sh *Share) serve(c transport.Conn, peer string) {
	s := &session{conn: c, peer: peer, start: time.Now()}
	sh.mu.Lock()
	sh.sessions[s] = struct{}{}
	sh.mu.Unlock()
	defer func() {
		sh.mu.Lock()
		delete(sh.sessions, s)
		sh.mu.Unlock()
		c.Close()
	}()

	chunks := sh.Src.Chunks()
	buf := make([]byte, wire.ChunkSize)
	for {
		f, err := c.ReadFrame()
		if err != nil {
			return
		}
		switch f.Type {
		case wire.TReq:
			if uint64(f.First)+uint64(f.Count) > uint64(chunks) {
				_ = c.WriteFrame(wire.ErrorFrame(wire.ErrProtocol, "chunk out of range"))
				return
			}
			for i := f.First; i < f.First+f.Count; i++ {
				if sh.isStopped() {
					_ = c.WriteFrame(wire.ErrorFrame(wire.ErrRevoked, "share ended"))
					return
				}
				data, err := sh.Src.ReadChunk(int(i), buf)
				if err != nil {
					_ = c.WriteFrame(wire.ErrorFrame(wire.ErrIO, err.Error()))
					return
				}
				if err := c.WriteFrame(wire.Frame{Type: wire.TData, Index: i, Payload: data}); err != nil {
					return
				}
				s.addBytes(len(data))
			}
			if f.Count > 0 && int(f.First+f.Count) == chunks {
				s.lastRequested = true
			}
		case wire.THashReq:
			hs, err := sh.Src.Hashes(int(f.First), int(f.Count))
			if err != nil {
				_ = c.WriteFrame(wire.ErrorFrame(wire.ErrProtocol, err.Error()))
				return
			}
			if err := c.WriteFrame(wire.Frame{Type: wire.THash, First: f.First, Count: f.Count, Payload: hs}); err != nil {
				return
			}
		case wire.TCancel:
			// Chunks are served synchronously per REQ; nothing is queued to cancel.
		default:
		}
		if !s.doneSent && (s.lastRequested || chunks == 0) && sh.Src.AllKnown() {
			root := sh.Src.Root()
			if err := c.WriteFrame(wire.Frame{Type: wire.TDone, Payload: root[:]}); err != nil {
				return
			}
			s.doneSent = true
			sh.completed()
		}
	}
}

func (sh *Share) isStopped() bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.stopped
}

// completed counts one finished download.
func (sh *Share) completed() {
	sh.mu.Lock()
	if sh.downloadsLeft > 0 {
		sh.downloadsLeft--
	}
	last := sh.downloadsLeft == 0
	sh.mu.Unlock()
	sh.h.save()
	if last {
		// Give the receiver time to read DONE before the share disappears.
		time.AfterFunc(5*time.Second, func() { _ = sh.h.Remove(sh.ID, "done") })
	}
}

func (sh *Share) stop(reason string) {
	sh.mu.Lock()
	if sh.stopped {
		sh.mu.Unlock()
		return
	}
	sh.stopped = true
	if sh.expiry != nil {
		sh.expiry.Stop()
	}
	sig := sh.sig
	peers := make([]string, 0, len(sh.peers))
	rtcs := make([]*transport.RTC, 0, len(sh.peers))
	for id, ps := range sh.peers {
		peers = append(peers, id)
		if ps.rtc != nil {
			rtcs = append(rtcs, ps.rtc)
		}
	}
	sessions := make([]*session, 0, len(sh.sessions))
	for s := range sh.sessions {
		sessions = append(sessions, s)
	}
	sh.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, p := range peers {
		_ = sig.Send(ctx, p, signal.Bye{K: signal.KindBye, Reason: reason})
	}
	sh.cancel()
	sig.Close()
	for _, r := range rtcs {
		r.Close()
	}
	for _, s := range sessions {
		s.conn.Close()
	}
	sh.Src.Close()
	if reason == "revoked" || reason == "done" {
		_ = sh.h.api.DeleteShare(ctx, sh.ID, sh.Token)
	}
}
