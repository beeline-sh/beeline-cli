// Package daemon is the local control API (PROTOCOL §8): an HTTP/1.1 server on
// a unix socket in front of one host.Host, plus receive jobs.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/host"
	"go.beeline.sh/cli/internal/link"
	"go.beeline.sh/cli/internal/peer"
)

// Status is GET /status.
type Status struct {
	Version   string `json:"version"`
	Server    string `json:"server"`
	UptimeS   int64  `json:"uptime_s"`
	Port      int    `json:"port"`
	PID       int    `json:"pid"`
	Shares    int    `json:"shares"`
	Restoring bool   `json:"restoring"` // still re-hosting shares from the previous run
}

// ShareRequest is POST /shares.
type ShareRequest struct {
	Path         string `json:"path"`
	Name         string `json:"name,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"` // seconds; 0 = server maximum
	MaxDownloads int    `json:"max_downloads,omitempty"`
	Relay        string `json:"relay,omitempty"`
}

// ReceiveRequest is POST /receive.
type ReceiveRequest struct {
	Link string `json:"link"`
	Dest string `json:"dest,omitempty"`
}

type job struct {
	mu     sync.Mutex
	prog   peer.Progress
	err    error
	cancel context.CancelFunc
}

// Server is the daemon.
type Server struct {
	cfg   config.Config
	host  *host.Host
	start time.Time
	log   *log.Logger
	stop  context.CancelFunc

	mu        sync.Mutex
	jobs      map[string]*job
	subs      map[chan string]struct{}
	restoring bool
}

// Run serves until ctx ends. It refuses to start if another daemon answers on the socket.
func Run(ctx context.Context, cfg config.Config) error {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if _, err := Dial(cfg.Socket).Status(ctx); err == nil {
		return errors.New("a beeline daemon is already running on " + cfg.Socket)
	}
	_ = os.Remove(cfg.Socket)
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		return err
	}
	h, err := host.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		h.Close()
		return err
	}
	_ = os.Chmod(cfg.Socket, 0o600)

	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	s := &Server{cfg: cfg, host: h, start: time.Now(), log: logger, stop: rcancel, jobs: map[string]*job{}, subs: map[chan string]struct{}{}, restoring: true}
	srv := &http.Server{Handler: s.routes()}
	go s.ticker(rctx)
	go func() {
		<-rctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		// Re-host what the previous run was serving; the socket answers
		// meanwhile so `beeline share` never waits for it.
		n := h.Restore(rctx)
		s.mu.Lock()
		s.restoring = false
		s.mu.Unlock()
		if n > 0 {
			logger.Printf("re-hosted %d share(s)", n)
		}
		s.publish()
	}()
	logger.Printf("beeline daemon %s (pid %d) on %s (server %s)", config.Version, os.Getpid(), cfg.Socket, cfg.Server)
	err = srv.Serve(ln)
	h.Close()
	_ = os.Remove(cfg.Socket)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("POST /shutdown", s.shutdown)
	mux.HandleFunc("GET /shares", s.listShares)
	mux.HandleFunc("POST /shares", s.addShare)
	mux.HandleFunc("DELETE /shares/{id}", s.revoke)
	mux.HandleFunc("POST /receive", s.receive)
	mux.HandleFunc("GET /receive/{job}", s.receiveStatus)
	mux.HandleFunc("GET /events", s.events)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	restoring := s.restoring
	s.mu.Unlock()
	writeJSON(w, 200, Status{
		Version: config.Version, Server: s.cfg.Server, UptimeS: int64(time.Since(s.start).Seconds()),
		Port: s.host.Port(), PID: os.Getpid(), Shares: len(s.host.List()), Restoring: restoring,
	})
}

// shutdown exits after replying. Shares are not revoked: they are persisted
// and re-hosted by the next daemon (`beeline daemon restart`, `beeline update`).
func (s *Server) shutdown(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(204)
	s.log.Printf("shutdown requested")
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.stop()
	}()
}

func (s *Server) snapshot() []host.Info {
	shares := s.host.List()
	out := make([]host.Info, 0, len(shares))
	for _, sh := range shares {
		out = append(out, sh.Info())
	}
	return out
}

func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.snapshot())
}

func (s *Server) addShare(w http.ResponseWriter, r *http.Request) {
	var req ShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Path == "" {
		writeErr(w, 400, errors.New("path is required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	sh, err := s.host.Add(ctx, req.Path, host.Options{
		Name: req.Name, ExpiresIn: time.Duration(req.ExpiresIn) * time.Second,
		MaxDownloads: req.MaxDownloads, Relay: req.Relay,
	})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.publish()
	writeJSON(w, 201, sh.Info())
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.host.Remove(r.PathValue("id"), "revoked"); err != nil {
		writeErr(w, 404, err)
		return
	}
	s.publish()
	w.WriteHeader(204)
}

func (s *Server) receive(w http.ResponseWriter, r *http.Request) {
	var req ReceiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	l, err := link.Parse(req.Link)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	dest := req.Dest
	if dest == "" {
		dest, _ = os.Getwd()
	}
	var idb [8]byte
	_, _ = rand.Read(idb[:])
	id := hex.EncodeToString(idb[:])
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{cancel: cancel, prog: peer.Progress{State: "connecting"}}
	s.mu.Lock()
	s.jobs[id] = j
	s.mu.Unlock()
	go func() {
		p, err := peer.Receive(ctx, s.cfg, l, dest, func(p peer.Progress) {
			j.mu.Lock()
			j.prog = p
			j.mu.Unlock()
		})
		j.mu.Lock()
		j.prog, j.err = p, err
		if err != nil {
			j.prog.State, j.prog.Error = "error", err.Error()
		}
		j.mu.Unlock()
		s.publish()
	}()
	writeJSON(w, 202, map[string]string{"job": id})
}

func (s *Server) receiveStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.jobs[r.PathValue("job")]
	s.mu.Unlock()
	if j == nil {
		writeErr(w, 404, errors.New("no such job"))
		return
	}
	j.mu.Lock()
	p := j.prog
	j.mu.Unlock()
	writeJSON(w, 200, p)
}

// events streams share snapshots as server-sent events.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan string, 8)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()
	send := func(data string) bool {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	b, _ := json.Marshal(s.snapshot())
	if !send(string(b)) {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			if !send(data) {
				return
			}
		}
	}
}

func (s *Server) publish() {
	b, _ := json.Marshal(s.snapshot())
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- string(b):
		default:
		}
	}
}

// ticker publishes once a second while anything is moving.
func (s *Server) ticker(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			active := false
			for _, sh := range s.host.List() {
				if len(sh.Info().Peers) > 0 {
					active = true
					break
				}
			}
			if !active {
				s.mu.Lock()
				for _, j := range s.jobs {
					j.mu.Lock()
					st := j.prog.State
					j.mu.Unlock()
					if st == "transferring" || st == "connecting" {
						active = true
						break
					}
				}
				s.mu.Unlock()
			}
			if active {
				s.publish()
			}
		}
	}
}
