package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"time"
)

// CertValidity stays under the 14-day limit WebTransport imposes on
// serverCertificateHashes.
const CertValidity = 13 * 24 * time.Hour

// Cert is a self-signed ECDSA P-256 certificate and its SHA-256 (DER) hash.
type Cert struct {
	TLS      tls.Certificate
	Hash     [32]byte
	NotAfter time.Time
}

// NewCert generates a fresh certificate.
func NewCert() (*Cert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "beeline"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Cert{
		TLS:      tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
		Hash:     sha256.Sum256(der),
		NotAfter: tmpl.NotAfter,
	}, nil
}

// HashB64 is the manifest encoding of the certificate hash.
func (c *Cert) HashB64() string { return base64.StdEncoding.EncodeToString(c.Hash[:]) }

// ParseHash decodes a manifest certhash.
func ParseHash(s string) ([32]byte, bool) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}
