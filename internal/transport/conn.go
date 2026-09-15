// Package transport provides the data-stream carriers (QUIC, WebTransport,
// WebRTC), the UDP endpoint with STUN and hole punching, and the peer-side race.
package transport

import (
	"bufio"
	"errors"
	"io"
	"sync"

	"github.com/pion/webrtc/v4"

	"go.beeline.sh/cli/internal/wire"
)

// Conn carries wire frames in both directions.
type Conn interface {
	ReadFrame() (wire.Frame, error)
	WriteFrame(wire.Frame) error
	Close() error
	Kind() string
}

// streamConn frames a reliable byte stream.
type streamConn struct {
	kind    string
	s       io.ReadWriteCloser
	br      *bufio.Reader
	wmu     sync.Mutex
	onClose func()
}

// NewStreamConn wraps a byte stream. onClose (optional) runs after the stream closes.
func NewStreamConn(kind string, s io.ReadWriteCloser, onClose func()) Conn {
	return &streamConn{kind: kind, s: s, br: bufio.NewReaderSize(s, 1<<20), onClose: onClose}
}

func (c *streamConn) Kind() string { return c.kind }

// withOnClose returns c with fn run after Close, in addition to any
// existing hook. Non-stream conns are returned unchanged.
func withOnClose(c Conn, fn func()) Conn {
	sc, ok := c.(*streamConn)
	if !ok {
		return c
	}
	prev := sc.onClose
	sc.onClose = func() {
		if prev != nil {
			prev()
		}
		fn()
	}
	return sc
}

func (c *streamConn) ReadFrame() (wire.Frame, error) { return wire.Read(c.br) }

func (c *streamConn) WriteFrame(f wire.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	b := wire.Encode(f)
	for len(b) > 0 {
		n, err := c.s.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (c *streamConn) Close() error {
	err := c.s.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

// dcConn frames a WebRTC data channel: one message per frame, DATA split to
// fit MaxMessage, sends paced by bufferedAmount.
type dcConn struct {
	pc     *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	in     chan []byte
	low    chan struct{}
	closed chan struct{}
	once   sync.Once
	wmu    sync.Mutex
	err    error
}

const (
	dcLowWater  = 1 << 20
	dcHighWater = 4 << 20
)

var errClosed = errors.New("data channel closed")

// NewDataChannelConn must be called before the channel opens so no message is missed.
func NewDataChannelConn(pc *webrtc.PeerConnection, dc *webrtc.DataChannel) Conn {
	c := &dcConn{pc: pc, dc: dc, in: make(chan []byte, 1024), low: make(chan struct{}, 1), closed: make(chan struct{})}
	dc.SetBufferedAmountLowThreshold(dcLowWater)
	dc.OnBufferedAmountLow(func() {
		select {
		case c.low <- struct{}{}:
		default:
		}
	})
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		select {
		case c.in <- m.Data:
		case <-c.closed:
		}
	})
	dc.OnClose(func() { c.shutdown(errClosed) })
	dc.OnError(func(err error) { c.shutdown(err) })
	return c
}

func (c *dcConn) shutdown(err error) {
	c.once.Do(func() {
		c.err = err
		close(c.closed)
	})
}

func (c *dcConn) Kind() string { return "webrtc" }

func (c *dcConn) ReadFrame() (wire.Frame, error) {
	select {
	case b := <-c.in:
		return wire.Decode(b)
	case <-c.closed:
		// drain anything that arrived before the close
		select {
		case b := <-c.in:
			return wire.Decode(b)
		default:
		}
		if c.err != nil {
			return wire.Frame{}, c.err
		}
		return wire.Frame{}, io.EOF
	}
}

func (c *dcConn) WriteFrame(f wire.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for _, part := range wire.SplitData(f, wire.MaxMessage) {
		for c.dc.BufferedAmount() > dcHighWater {
			select {
			case <-c.low:
			case <-c.closed:
				return errClosed
			}
		}
		if err := c.dc.Send(wire.Encode(part)); err != nil {
			return err
		}
	}
	return nil
}

func (c *dcConn) Close() error {
	c.shutdown(errClosed)
	_ = c.dc.Close()
	return c.pc.Close()
}
