package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"go.beeline.sh/cli/internal/config"
	"go.beeline.sh/cli/internal/signal"
)

// Saved is one hosted share as written to ~/.beeline/shares.json, so a
// daemon restart (or `beeline update`) keeps links working. The key is the
// only copy outside the link itself; the file is 0600.
type Saved struct {
	ID            string `json:"id"`
	Token         string `json:"token"`
	Key           string `json:"key"`
	Path          string `json:"path"`
	Name          string `json:"name,omitempty"`
	ExpiresIn     int64  `json:"expires_in,omitempty"`
	MaxDownloads  int    `json:"max_downloads,omitempty"`
	Relay         string `json:"relay,omitempty"`
	ExpiresAt     int64  `json:"expires_at"`
	CreatedAt     int64  `json:"created_at"`
	DownloadsLeft int    `json:"downloads_left"`
}

func storePath() string { return filepath.Join(config.DataDir(), "shares.json") }

// save writes every live share plus entries that could not be resumed yet.
func (h *Host) save() {
	h.mu.Lock()
	out := make([]Saved, 0, len(h.shares)+len(h.pending))
	for _, sh := range h.shares {
		out = append(out, sh.saved())
	}
	out = append(out, h.pending...)
	h.mu.Unlock()
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	tmp := storePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		h.log.Printf("shares.json: %v", err)
		return
	}
	if err := os.Rename(tmp, storePath()); err != nil {
		h.log.Printf("shares.json: %v", err)
	}
}

func loadSaved() ([]Saved, error) {
	b, err := os.ReadFile(storePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Saved
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Restore re-hosts the shares of the previous daemon run. Entries that
// expired or whose path is gone are dropped; entries the server refuses
// (not-found, gone, unauthorized) are dropped; entries that fail for a
// transient reason stay in the file and are retried a few times in the
// background. Returns how many are live when it returns.
func (h *Host) Restore(ctx context.Context) int {
	saved, err := loadSaved()
	if err != nil {
		h.log.Printf("shares.json: %v", err)
		return 0
	}
	if len(saved) == 0 {
		return 0
	}
	var retry []Saved
	live := 0
	now := time.Now().Unix()
	for _, s := range saved {
		if s.ExpiresAt > 0 && s.ExpiresAt <= now {
			h.log.Printf("share %s: expired while the daemon was down, dropped", s.ID)
			continue
		}
		if _, err := os.Stat(s.Path); err != nil {
			h.log.Printf("share %s: %s is gone, dropped", s.ID, s.Path)
			continue
		}
		if s.DownloadsLeft == 0 {
			continue
		}
		switch h.resume(ctx, s) {
		case resumed:
			live++
		case dropped:
		case transient:
			retry = append(retry, s)
		}
	}
	h.mu.Lock()
	h.pending = retry
	h.mu.Unlock()
	h.save()
	if len(retry) > 0 {
		go h.retryPending(ctx)
	}
	return live
}

type resumeResult int

const (
	resumed resumeResult = iota
	dropped
	transient
)

func (h *Host) resume(ctx context.Context, s Saved) resumeResult {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	sh, err := resumeShare(rctx, h, s)
	cancel()
	if err == nil {
		h.mu.Lock()
		h.shares[sh.ID] = sh
		h.mu.Unlock()
		h.log.Printf("share %s: re-hosted %s", sh.ID, sh.Src.Name)
		return resumed
	}
	var serr *signal.Error
	if errors.As(err, &serr) && (serr.Code == "not-found" || serr.Code == "gone" || serr.Code == "unauthorized") {
		h.log.Printf("share %s: server says %s, dropped", s.ID, serr.Code)
		return dropped
	}
	h.log.Printf("share %s: cannot re-host yet (%v)", s.ID, err)
	return transient
}

func (h *Host) retryPending(ctx context.Context) {
	for attempt := 0; attempt < 6; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
		h.mu.Lock()
		todo := h.pending
		h.pending = nil
		h.mu.Unlock()
		if len(todo) == 0 {
			return
		}
		var again []Saved
		for _, s := range todo {
			if h.resume(ctx, s) == transient {
				again = append(again, s)
			}
		}
		h.mu.Lock()
		h.pending = again
		h.mu.Unlock()
		h.save()
		if len(again) == 0 {
			return
		}
	}
}
