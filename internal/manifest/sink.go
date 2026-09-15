package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Sink writes received chunks into their final files and keeps a sidecar
// (<dest>.beeline-part) so an interrupted transfer resumes.
type Sink struct {
	*Layout
	ID      string
	Dest    string // final path of the file, or of the folder
	sidecar string
	files   []*os.File

	mu       sync.Mutex
	bitmap   []byte
	hashes   []byte // 32 bytes per chunk, valid where the bit is set
	received int
	dirty    int
}

type partFile struct {
	ID     string `json:"id"`
	Size   int64  `json:"size"`
	Chunk  int    `json:"chunk"`
	Bitmap string `json:"bitmap"`
	Hashes string `json:"hashes"`
}

// OpenSink creates (or resumes into) destDir/<name>.
func OpenSink(l *Layout, id, destDir string) (*Sink, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	dest := filepath.Join(destDir, l.Name)
	s := &Sink{Layout: l, ID: id, Dest: dest, sidecar: dest + ".beeline-part"}
	n := l.Chunks()
	s.bitmap = make([]byte, (n+7)/8)
	s.hashes = make([]byte, 32*n)

	resuming := s.loadSidecar()
	if !resuming {
		if _, err := os.Lstat(dest); err == nil {
			return nil, fmt.Errorf("%s already exists", dest)
		}
	}
	base := destDir
	if l.IsDir() {
		base = dest
	}
	s.files = make([]*os.File, len(l.Files))
	for i, f := range l.Files {
		p := filepath.Join(base, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, err
		}
		fd, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}
		if err := fd.Truncate(f.Size); err != nil {
			fd.Close()
			return nil, err
		}
		s.files[i] = fd
	}
	if err := s.SaveSidecar(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sink) loadSidecar() bool {
	b, err := os.ReadFile(s.sidecar)
	if err != nil {
		return false
	}
	var sc partFile
	if json.Unmarshal(b, &sc) != nil || sc.ID != s.ID || sc.Size != s.Size || sc.Chunk != s.Chunk {
		return false
	}
	bm, err1 := base64.StdEncoding.DecodeString(sc.Bitmap)
	hs, err2 := base64.StdEncoding.DecodeString(sc.Hashes)
	if err1 != nil || err2 != nil || len(bm) != len(s.bitmap) || len(hs) != len(s.hashes) {
		return false
	}
	s.bitmap, s.hashes = bm, hs
	for i := 0; i < s.Chunks(); i++ {
		if s.has(i) {
			s.received++
		}
	}
	return true
}

// SaveSidecar persists the bitmap and hashes.
func (s *Sink) SaveSidecar() error {
	s.mu.Lock()
	sc := partFile{ID: s.ID, Size: s.Size, Chunk: s.Chunk,
		Bitmap: base64.StdEncoding.EncodeToString(s.bitmap),
		Hashes: base64.StdEncoding.EncodeToString(s.hashes)}
	s.dirty = 0
	s.mu.Unlock()
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	tmp := s.sidecar + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.sidecar)
}

func (s *Sink) has(i int) bool { return s.bitmap[i/8]&(1<<(i%8)) != 0 }
func (s *Sink) set(i int)      { s.bitmap[i/8] |= 1 << (i % 8) }
func (s *Sink) clear(i int)    { s.bitmap[i/8] &^= 1 << (i % 8) }
func (s *Sink) Has(i int) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.has(i) }
func (s *Sink) Received() int  { s.mu.Lock(); defer s.mu.Unlock(); return s.received }
func (s *Sink) ReceivedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.Chunks()
	if n == 0 {
		return 0
	}
	var b int64
	full := int64(s.Chunk)
	for i := 0; i < n; i++ {
		if s.has(i) {
			if i == n-1 {
				_, last := s.ChunkSpan(i)
				b += int64(last)
			} else {
				b += full
			}
		}
	}
	return b
}

// Missing lists chunk indexes not yet received, in order.
func (s *Sink) Missing() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []int
	for i := 0; i < s.Chunks(); i++ {
		if !s.has(i) {
			out = append(out, i)
		}
	}
	return out
}

// WriteChunk stores chunk i, records its hash and sets its bit.
func (s *Sink) WriteChunk(i int, data []byte) error {
	off, n := s.ChunkSpan(i)
	if len(data) != n {
		return errors.New("chunk length mismatch")
	}
	pos := 0
	for _, seg := range s.segments(off, n) {
		if _, err := s.files[seg.file].WriteAt(data[pos:pos+seg.n], seg.inFile); err != nil {
			return err
		}
		pos += seg.n
	}
	sum := sha256.Sum256(data)
	s.mu.Lock()
	copy(s.hashes[32*i:], sum[:])
	if !s.has(i) {
		s.set(i)
		s.received++
	}
	s.dirty++
	flush := s.dirty >= 64
	s.mu.Unlock()
	if flush {
		return s.SaveSidecar()
	}
	return nil
}

// Verify compares the host's hashes for [first, first+count) with what we
// computed. Mismatching chunks are cleared and returned.
func (s *Sink) Verify(first int, hashes []byte) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var bad []int
	for k := 0; 32*k+32 <= len(hashes); k++ {
		i := first + k
		if i >= s.Chunks() {
			break
		}
		if !s.has(i) {
			continue
		}
		if string(s.hashes[32*i:32*i+32]) != string(hashes[32*k:32*k+32]) {
			s.clear(i)
			s.received--
			bad = append(bad, i)
		}
	}
	return bad
}

// Complete reports whether every chunk has been received.
func (s *Sink) Complete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received == s.Chunks()
}

// Root is SHA-256 over all chunk hashes in order.
func (s *Sink) Root() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sha256.Sum256(s.hashes)
}

// Finish syncs and closes the files and removes the sidecar.
func (s *Sink) Finish() error {
	for _, f := range s.files {
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return os.Remove(s.sidecar)
}

// Suspend saves the sidecar and closes files without removing anything.
func (s *Sink) Suspend() {
	_ = s.SaveSidecar()
	for _, f := range s.files {
		f.Close()
	}
}
