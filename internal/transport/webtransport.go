package transport

import (
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// NewWebTransportServer serves /wt/<id>. For each session it accepts one
// bidirectional stream and hands it to handle, blocking until handle
// returns so the session stays alive for the whole transfer.
func NewWebTransportServer(tlsConf *tls.Config, handle func(id string, c Conn)) *webtransport.Server {
	s := &webtransport.Server{
		H3: http3.Server{
			TLSConfig:       tlsConf,
			EnableDatagrams: true,
		},
		CheckOrigin: func(*http.Request) bool { return true },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/wt/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/wt/"), "/")
		sess, err := s.Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st, err := sess.AcceptStream(sess.Context())
		if err != nil {
			_ = sess.CloseWithError(0, "no stream")
			return
		}
		handle(id, NewStreamConn("webtransport", st, nil))
		_ = sess.CloseWithError(0, "")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	s.H3.Handler = mux
	return s
}
