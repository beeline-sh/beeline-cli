// Package wire encodes the data-stream frames of PROTOCOL §7.
//
// Every frame is self-delimiting on a byte stream.
package wire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	TAuth        byte = 0x01
	TManifestAck byte = 0x02
	TReq         byte = 0x10
	TData        byte = 0x11
	THashReq     byte = 0x12
	THash        byte = 0x13
	TDone        byte = 0x14
	TCancel      byte = 0x20
	TError       byte = 0x7f
)

// Error codes.
const (
	ErrRevoked   byte = 1
	ErrExhausted byte = 2
	ErrIO        byte = 3
	ErrProtocol  byte = 4
)

const (
	ChunkSize = 262144
	// MaxMessage is the largest message on a WebRTC data channel.
	MaxMessage     = 65536
	dataHeader     = 1 + 4 + 4 + 4
	MaxDataPerMsg  = MaxMessage - dataHeader
	maxHashCount   = 4096
	maxErrorMsgLen = 4096
)

var ErrMalformed = errors.New("wire: malformed frame")

// Frame is any frame; which fields are meaningful depends on Type.
type Frame struct {
	Type byte
	// REQ, HASH-REQ, HASH, CANCEL
	First, Count uint32
	// DATA
	Index, Offset uint32
	// DATA bytes; HASH 32*Count; AUTH nonce||hmac (48); DONE root (32); ERROR message
	Payload []byte
	// ERROR
	Code byte
}

func (f Frame) String() string {
	switch f.Type {
	case TReq:
		return fmt.Sprintf("REQ %d+%d", f.First, f.Count)
	case TData:
		return fmt.Sprintf("DATA %d@%d len=%d", f.Index, f.Offset, len(f.Payload))
	case TError:
		return fmt.Sprintf("ERROR %d %q", f.Code, f.Payload)
	}
	return fmt.Sprintf("frame 0x%02x", f.Type)
}

var le = binary.LittleEndian

// Encode serialises a frame.
func Encode(f Frame) []byte {
	switch f.Type {
	case TAuth, TDone:
		b := make([]byte, 1+len(f.Payload))
		b[0] = f.Type
		copy(b[1:], f.Payload)
		return b
	case TManifestAck:
		return []byte{f.Type}
	case TReq, THashReq, TCancel:
		b := make([]byte, 9)
		b[0] = f.Type
		le.PutUint32(b[1:], f.First)
		le.PutUint32(b[5:], f.Count)
		return b
	case TData:
		b := make([]byte, dataHeader+len(f.Payload))
		b[0] = f.Type
		le.PutUint32(b[1:], f.Index)
		le.PutUint32(b[5:], f.Offset)
		le.PutUint32(b[9:], uint32(len(f.Payload)))
		copy(b[dataHeader:], f.Payload)
		return b
	case THash:
		b := make([]byte, 9+len(f.Payload))
		b[0] = f.Type
		le.PutUint32(b[1:], f.First)
		le.PutUint32(b[5:], f.Count)
		copy(b[9:], f.Payload)
		return b
	case TError:
		msg := f.Payload
		if len(msg) > maxErrorMsgLen {
			msg = msg[:maxErrorMsgLen]
		}
		b := make([]byte, 4+len(msg))
		b[0] = f.Type
		b[1] = f.Code
		le.PutUint16(b[2:], uint16(len(msg)))
		copy(b[4:], msg)
		return b
	}
	return []byte{f.Type}
}

// Read parses one frame from a byte stream.
func Read(r *bufio.Reader) (Frame, error) {
	t, err := r.ReadByte()
	if err != nil {
		return Frame{}, err
	}
	f := Frame{Type: t}
	switch t {
	case TAuth:
		f.Payload = make([]byte, 48)
		_, err = io.ReadFull(r, f.Payload)
	case TDone:
		f.Payload = make([]byte, 32)
		_, err = io.ReadFull(r, f.Payload)
	case TManifestAck:
	case TReq, THashReq, TCancel:
		var h [8]byte
		if _, err = io.ReadFull(r, h[:]); err == nil {
			f.First, f.Count = le.Uint32(h[:4]), le.Uint32(h[4:])
		}
	case TData:
		var h [12]byte
		if _, err = io.ReadFull(r, h[:]); err != nil {
			break
		}
		f.Index, f.Offset = le.Uint32(h[:4]), le.Uint32(h[4:8])
		n := le.Uint32(h[8:])
		if n > ChunkSize {
			return f, ErrMalformed
		}
		f.Payload = make([]byte, n)
		_, err = io.ReadFull(r, f.Payload)
	case THash:
		var h [8]byte
		if _, err = io.ReadFull(r, h[:]); err != nil {
			break
		}
		f.First, f.Count = le.Uint32(h[:4]), le.Uint32(h[4:])
		if f.Count > maxHashCount {
			return f, ErrMalformed
		}
		f.Payload = make([]byte, 32*f.Count)
		_, err = io.ReadFull(r, f.Payload)
	case TError:
		var h [3]byte
		if _, err = io.ReadFull(r, h[:]); err != nil {
			break
		}
		f.Code = h[0]
		n := le.Uint16(h[1:])
		if int(n) > maxErrorMsgLen {
			return f, ErrMalformed
		}
		f.Payload = make([]byte, n)
		_, err = io.ReadFull(r, f.Payload)
	default:
		return f, ErrMalformed
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return f, err
	}
	return f, nil
}

// Decode parses exactly one frame from a message.
func Decode(b []byte) (Frame, error) {
	br := bufio.NewReader(bytes.NewReader(b))
	f, err := Read(br)
	if err != nil {
		return f, err
	}
	if br.Buffered() != 0 {
		return f, ErrMalformed
	}
	return f, nil
}

// SplitData breaks a DATA frame into frames whose encoded size fits max bytes.
func SplitData(f Frame, max int) []Frame {
	if f.Type != TData || len(f.Payload)+dataHeader <= max {
		return []Frame{f}
	}
	per := max - dataHeader
	var out []Frame
	for off := 0; off < len(f.Payload); off += per {
		end := off + per
		if end > len(f.Payload) {
			end = len(f.Payload)
		}
		out = append(out, Frame{Type: TData, Index: f.Index, Offset: f.Offset + uint32(off), Payload: f.Payload[off:end]})
	}
	return out
}

// ErrorFrame builds an ERROR frame.
func ErrorFrame(code byte, msg string) Frame {
	return Frame{Type: TError, Code: code, Payload: []byte(msg)}
}
