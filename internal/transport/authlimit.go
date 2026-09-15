package transport

import (
	"net"
	"sync"
	"time"
)

// AuthLimiter blocks a source address for a while after repeated failed
// AUTH frames, so an open port cannot be used to hammer HMAC checks.
type AuthLimiter struct {
	mu      sync.Mutex
	fails   map[string][]time.Time
	blocked map[string]time.Time
	limit   int
	window  time.Duration
	ban     time.Duration
}

func NewAuthLimiter() *AuthLimiter {
	return &AuthLimiter{fails: map[string][]time.Time{}, blocked: map[string]time.Time{}, limit: 10, window: time.Minute, ban: time.Minute}
}

// Allow reports whether addr may open a connection or stream right now.
func (l *AuthLimiter) Allow(addr string) bool {
	ip := hostOf(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blocked[ip]
	if ok && time.Now().Before(until) {
		return false
	}
	if ok {
		delete(l.blocked, ip)
	}
	return true
}

// Fail records a failed AUTH from addr; the limit-th failure inside the
// window blocks the address for the ban duration. Returns true when the
// address just became blocked.
func (l *AuthLimiter) Fail(addr string) bool {
	ip := hostOf(addr)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 4096 { // keep the map bounded under a spray of addresses
		l.fails = map[string][]time.Time{}
	}
	keep := l.fails[ip][:0]
	for _, t := range l.fails[ip] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	l.fails[ip] = keep
	if len(keep) >= l.limit {
		l.blocked[ip] = now.Add(l.ban)
		delete(l.fails, ip)
		return true
	}
	return false
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
