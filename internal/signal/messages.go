// Package signal speaks the introduction server's WebSocket (PROTOCOL §4) and
// defines the sealed payloads exchanged through it (PROTOCOL §5).
package signal

import "encoding/json"

// ICEServer mirrors RTCIceServer.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	TTL        int      `json:"ttl,omitempty"`
}

// Message is a WebSocket frame in either direction.
type Message struct {
	T          string      `json:"t"`
	Role       string      `json:"role,omitempty"`
	Peer       string      `json:"peer,omitempty"`
	IP         string      `json:"ip,omitempty"`
	HostIP     string      `json:"host_ip,omitempty"`
	HostOnline bool        `json:"host_online,omitempty"`
	Data       string      `json:"data,omitempty"`
	ICE        []ICEServer `json:"ice,omitempty"`
	ExpiresAt  int64       `json:"expires_at,omitempty"`
	Code       string      `json:"code,omitempty"`
	Msg        string      `json:"message,omitempty"`
}

// Sealed payload kinds.
const (
	KindHello    = "hello"
	KindManifest = "manifest"
	KindSDP      = "sdp"
	KindICE      = "ice"
	KindBye      = "bye"
)

type Hello struct {
	K     string   `json:"k"`
	Agent string   `json:"agent"`
	Caps  []string `json:"caps"`
	Addrs []string `json:"addrs,omitempty"`
	// Listen advertises the peer's own listeners so a host that cannot
	// listen (a browser) dials the peer instead (PROTOCOL §5/§6 reverse).
	Listen *Listeners `json:"listen,omitempty"`
	Proof  string     `json:"proof"`
	Nonce  string     `json:"nonce"`
}

// Listeners is Transports without webrtc: what a CLI peer accepts on.
type Listeners struct {
	QUIC         *QUICTransport `json:"quic,omitempty"`
	WebTransport *WTTransport   `json:"webtransport,omitempty"`
}

type File struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type QUICTransport struct {
	Addrs    []string `json:"addrs"`
	CertHash string   `json:"certhash"`
}

type WTTransport struct {
	URLs     []string `json:"urls"`
	CertHash string   `json:"certhash"`
}

type Transports struct {
	QUIC         *QUICTransport `json:"quic,omitempty"`
	WebTransport *WTTransport   `json:"webtransport,omitempty"`
	WebRTC       bool           `json:"webrtc"`
}

type Manifest struct {
	K          string     `json:"k"`
	Name       string     `json:"name"`
	Size       int64      `json:"size"`
	Chunk      int        `json:"chunk"`
	Hash       string     `json:"hash"`
	Files      []File     `json:"files"`
	Transports Transports `json:"transports"`
	// Dial is set by a host that will dial the peer's hello.listen itself.
	Dial          bool  `json:"dial,omitempty"`
	ExpiresAt     int64 `json:"expires_at"`
	DownloadsLeft int   `json:"downloads_left"`
}

type SDP struct {
	K    string `json:"k"`
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

// ICE carries an RTCIceCandidateInit, or JSON null for end-of-candidates.
type ICE struct {
	K         string          `json:"k"`
	Candidate json.RawMessage `json:"candidate"`
}

type Bye struct {
	K       string `json:"k"`
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

// kindOnly is used to peek at the kind of an opened payload.
type kindOnly struct {
	K string `json:"k"`
}
