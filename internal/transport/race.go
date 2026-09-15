package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Candidate is one way to reach the host. Dial must return a Conn that has
// already received MANIFEST-ACK (PROTOCOL §6): the race ends on the first one.
type Candidate struct {
	Kind string
	Dial func(ctx context.Context) (Conn, error)
}

// Race dials every candidate concurrently and returns the first success.
// Losers are closed; if every candidate fails the errors are joined.
func Race(ctx context.Context, cands []Candidate) (Conn, error) {
	if len(cands) == 0 {
		return nil, errors.New("no transport available")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		kind string
		conn Conn
		err  error
	}
	results := make(chan result, len(cands))
	var wg sync.WaitGroup
	for _, c := range cands {
		wg.Add(1)
		go func(c Candidate) {
			defer wg.Done()
			conn, err := c.Dial(ctx)
			results <- result{c.Kind, conn, err}
		}(c)
	}
	go func() { wg.Wait(); close(results) }()

	var errs []string
	var winner Conn
	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.kind, r.err))
			continue
		}
		if winner == nil {
			winner = r.conn
			cancel() // tell the others to stop; they close their own conns on ctx error
		} else {
			_ = r.conn.Close()
		}
	}
	if winner != nil {
		return winner, nil
	}
	return nil, errors.New("all transports failed: " + strings.Join(errs, "; "))
}
