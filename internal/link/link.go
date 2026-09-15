// Package link implements the beeline link format and key schedule (PROTOCOL §1, §2).
package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	// Alphabet is the share id alphabet: 31 symbols, no 0/o/1/l/i.
	Alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	IDLen    = 6
	KeyLen   = 16
	nonceLen = 12
)

var ErrInvalid = errors.New("not a beeline link")

// Link is a parsed https://host/<id>#<key>.
type Link struct {
	Server string // scheme://host[:port]
	ID     string
	Key    []byte
}

// Parse accepts a full link. The key lives in the fragment and is never sent anywhere.
func Parse(s string) (Link, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Link{}, ErrInvalid
	}
	id := strings.Trim(u.Path, "/")
	if !ValidID(id) {
		return Link{}, fmt.Errorf("%w: bad id", ErrInvalid)
	}
	key, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil || len(key) != KeyLen {
		return Link{}, fmt.Errorf("%w: bad key", ErrInvalid)
	}
	return Link{Server: u.Scheme + "://" + u.Host, ID: id, Key: key}, nil
}

func (l Link) String() string {
	return strings.TrimRight(l.Server, "/") + "/" + l.ID + "#" + base64.RawURLEncoding.EncodeToString(l.Key)
}

// ValidID reports whether s is a well-formed share id.
func ValidID(s string) bool {
	if len(s) != IDLen {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(Alphabet, c) {
			return false
		}
	}
	return true
}

// NewKey returns 16 random bytes.
func NewKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Keys is the derived key schedule.
type Keys struct {
	Sig  []byte // AES-256-GCM key for sealed signaling payloads
	Auth []byte // HMAC-SHA256 key for proofs
}

// Derive runs HKDF-SHA256 over the link key.
func Derive(key []byte) (Keys, error) {
	if len(key) != KeyLen {
		return Keys{}, ErrInvalid
	}
	sig, err := hkdf.Key(sha256.New, key, nil, "beeline/v1/signal", 32)
	if err != nil {
		return Keys{}, err
	}
	auth, err := hkdf.Key(sha256.New, key, nil, "beeline/v1/auth", 32)
	if err != nil {
		return Keys{}, err
	}
	return Keys{Sig: sig, Auth: auth}, nil
}

func aad(id string) []byte { return []byte("beeline/v1/" + id) }

// Seal encrypts a signaling payload: base64url(nonce || AES-256-GCM(sig, nonce, plaintext, aad)).
func Seal(sig []byte, id string, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(sig)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	out := make([]byte, nonceLen, nonceLen+len(plaintext)+gcm.Overhead())
	if _, err := rand.Read(out); err != nil {
		return "", err
	}
	out = gcm.Seal(out, out[:nonceLen], plaintext, aad(id))
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open reverses Seal. Any failure is returned as ErrInvalid so callers cannot distinguish reasons.
func Open(sig []byte, id string, sealed string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < nonceLen {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(sig)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, raw[:nonceLen], raw[nonceLen:], aad(id))
	if err != nil {
		return nil, ErrInvalid
	}
	return pt, nil
}

// Proof returns HMAC-SHA256(auth, label || nonce).
func Proof(auth []byte, label string, nonce []byte) []byte {
	m := hmac.New(sha256.New, auth)
	m.Write([]byte(label))
	m.Write(nonce)
	return m.Sum(nil)
}

// VerifyProof checks a proof in constant time.
func VerifyProof(auth []byte, label string, nonce, proof []byte) bool {
	return hmac.Equal(Proof(auth, label, nonce), proof)
}

// Nonce returns n random bytes.
func Nonce(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
