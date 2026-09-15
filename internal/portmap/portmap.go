// Package portmap asks the local router (UPnP IGD or NAT-PMP/PCP) to forward
// our UDP port. Behind a port-restricted NAT that is the only way a browser,
// which cannot hole-punch, can reach the daemon over WebTransport.
package portmap

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-nat"
)

const (
	discoverTimeout = 3 * time.Second
	lifetime        = time.Hour
	renewEvery      = 30 * time.Minute
)

// Mapper keeps one UDP mapping alive until Close.
type Mapper struct {
	port int
	log  *log.Logger

	mu       sync.Mutex
	gw       nat.NAT
	kind     string
	external string
	cancel   context.CancelFunc
}

// Disabled reports whether BEELINE_NO_PORTMAP=1 is set.
func Disabled() bool { return os.Getenv("BEELINE_NO_PORTMAP") == "1" }

// Start discovers a gateway and maps port. It never fails: without a
// cooperative router the Mapper simply reports Kind() == "none".
func Start(ctx context.Context, port int, logger *log.Logger) *Mapper {
	m := &Mapper{port: port, log: logger, kind: "none"}
	if Disabled() {
		return m
	}
	mctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	go m.run(mctx)
	return m
}

func (m *Mapper) run(ctx context.Context) {
	dctx, dcancel := context.WithTimeout(ctx, discoverTimeout)
	gw, err := nat.DiscoverGateway(dctx)
	dcancel()
	if err != nil {
		m.log.Printf("port mapping: no gateway support; forward UDP %d on the router for browser transfers", m.port)
		return
	}
	m.mu.Lock()
	m.gw = gw
	m.kind = kindOf(gw.Type())
	m.mu.Unlock()
	if !m.renew(ctx) {
		return
	}
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.renew(ctx)
		}
	}
}

// renew (re)requests the mapping. The gateway picks the external port; UPnP
// and NAT-PMP both try our own port first.
func (m *Mapper) renew(ctx context.Context) bool {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ext, err := m.gw.AddPortMapping(rctx, "udp", m.port, "beeline", lifetime)
	if err != nil {
		m.log.Printf("port mapping: %s refused udp/%d (%v); forward UDP %d on the router for browser transfers", m.kind, m.port, err, m.port)
		m.mu.Lock()
		m.external = ""
		m.mu.Unlock()
		return false
	}
	ip, err := m.gw.GetExternalAddress()
	if err != nil || ip == nil || ip.IsUnspecified() {
		m.log.Printf("port mapping: %s mapped udp/%d but reports no external address", m.kind, m.port)
		return false
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(ext))
	m.mu.Lock()
	first := m.external == ""
	m.external = addr
	m.mu.Unlock()
	if first {
		m.log.Printf("port mapping: %s %s", m.kind, addr)
	}
	return true
}

// External returns the mapped public ip:port, when there is one.
func (m *Mapper) External() (ip string, port int, ok bool) {
	m.mu.Lock()
	addr := m.external
	m.mu.Unlock()
	if addr == "" {
		return "", 0, false
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	n, _ := strconv.Atoi(p)
	return h, n, true
}

// ExternalAddr is External as "ip:port" ("" when unmapped).
func (m *Mapper) ExternalAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.external
}

// Kind is "upnp", "nat-pmp" or "none".
func (m *Mapper) Kind() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kind
}

// Close removes the mapping and stops renewing.
func (m *Mapper) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	gw := m.gw
	m.mu.Unlock()
	if gw != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = gw.DeletePortMapping(ctx, "udp", m.port)
		cancel()
	}
}

func kindOf(t string) string {
	switch strings.ToLower(t) {
	case "upnp":
		return "upnp"
	case "nat-pmp":
		return "nat-pmp"
	default:
		return strings.ToLower(t)
	}
}

// Merge appends extra to addrs, skipping empties and duplicates, in order.
func Merge(addrs []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(addrs)+len(extra))
	out := make([]string, 0, len(addrs)+len(extra))
	for _, a := range append(append([]string{}, addrs...), extra...) {
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
