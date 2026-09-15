package manifest

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"go.beeline.sh/cli/internal/signal"
	"go.beeline.sh/cli/internal/wire"
)

// Source serves chunks from local files and caches their hashes. Nothing is
// hashed up front: a chunk is hashed the first time it is read.
type Source struct {
	*Layout
	Path  string // local path that was shared
	local []string

	mu     sync.Mutex
	fds    map[int]*os.File
	hashes [][32]byte
	have   []bool
	known  int
}

// FromPath builds a source from a file or a directory. name overrides the
// display name (default: base name of p).
func FromPath(p, name string) (*Source, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = filepath.Base(abs)
	}
	var files []signal.File
	var local []string
	if st.IsDir() {
		err := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(abs, path)
			if err != nil {
				return err
			}
			files = append(files, signal.File{Path: filepath.ToSlash(rel), Size: info.Size()})
			local = append(local, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, errors.New("folder is empty")
		}
		idx := make([]int, len(files))
		for i := range idx {
			idx[i] = i
		}
		sort.Slice(idx, func(a, b int) bool { return files[idx[a]].Path < files[idx[b]].Path })
		sf := make([]signal.File, len(files))
		sl := make([]string, len(files))
		for i, k := range idx {
			sf[i], sl[i] = files[k], local[k]
		}
		files, local = sf, sl
	} else {
		if !st.Mode().IsRegular() {
			return nil, errors.New("not a regular file")
		}
		files = []signal.File{{Path: name, Size: st.Size()}}
		local = []string{abs}
	}
	l, err := NewLayout(name, files, wire.ChunkSize)
	if err != nil {
		return nil, err
	}
	n := l.Chunks()
	return &Source{
		Layout: l, Path: abs, local: local,
		fds: map[int]*os.File{}, hashes: make([][32]byte, n), have: make([]bool, n),
	}, nil
}

func (s *Source) file(i int) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.fds[i]; ok {
		return f, nil
	}
	f, err := os.Open(s.local[i])
	if err != nil {
		return nil, err
	}
	s.fds[i] = f
	return f, nil
}

// ReadChunk fills buf with chunk i (buf is reused when large enough) and
// records its hash.
func (s *Source) ReadChunk(i int, buf []byte) ([]byte, error) {
	if i < 0 || i >= s.Chunks() {
		return nil, errors.New("chunk out of range")
	}
	off, n := s.ChunkSpan(i)
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	pos := 0
	for _, seg := range s.segments(off, n) {
		f, err := s.file(seg.file)
		if err != nil {
			return nil, err
		}
		if _, err := f.ReadAt(buf[pos:pos+seg.n], seg.inFile); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		pos += seg.n
	}
	if pos != n {
		return nil, io.ErrUnexpectedEOF
	}
	sum := sha256.Sum256(buf)
	s.mu.Lock()
	if !s.have[i] {
		s.hashes[i], s.have[i] = sum, true
		s.known++
	}
	s.mu.Unlock()
	return buf, nil
}

// Hashes returns the hashes of chunks [first, first+count), reading any it
// does not know yet.
func (s *Source) Hashes(first, count int) ([]byte, error) {
	if first < 0 || count < 0 || first+count > s.Chunks() {
		return nil, errors.New("hash range out of range")
	}
	out := make([]byte, 0, 32*count)
	var buf []byte
	for i := first; i < first+count; i++ {
		s.mu.Lock()
		ok := s.have[i]
		h := s.hashes[i]
		s.mu.Unlock()
		if !ok {
			var err error
			if buf, err = s.ReadChunk(i, buf); err != nil {
				return nil, err
			}
			s.mu.Lock()
			h = s.hashes[i]
			s.mu.Unlock()
		}
		out = append(out, h[:]...)
	}
	return out, nil
}

// AllKnown reports whether every chunk has been hashed.
func (s *Source) AllKnown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known == len(s.have)
}

// Root is SHA-256 over all chunk hashes in order. Only meaningful when AllKnown.
func (s *Source) Root() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.New()
	for i := range s.hashes {
		h.Write(s.hashes[i][:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (s *Source) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.fds {
		f.Close()
	}
	s.fds = map[int]*os.File{}
}

// DisplayPath is the shared path relative to the working directory when possible.
func (s *Source) DisplayPath() string {
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, s.Path); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return s.Path
}
