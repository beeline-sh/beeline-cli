// Package manifest handles the file layout, chunk math, the sending side's
// chunk reader with hash cache, and the receiving side's sink with resume.
package manifest

import (
	"errors"
	"path"
	"sort"
	"strings"

	"go.beeline.sh/cli/internal/signal"
	"go.beeline.sh/cli/internal/wire"
)

// Layout is what a manifest describes: files laid out back to back.
type Layout struct {
	Name  string
	Size  int64
	Chunk int
	Files []signal.File
	// starts[i] is the byte offset of Files[i] in the concatenation.
	starts []int64
}

func NewLayout(name string, files []signal.File, chunk int) (*Layout, error) {
	if chunk <= 0 || chunk > wire.ChunkSize {
		return nil, errors.New("manifest: bad chunk size")
	}
	l := &Layout{Name: name, Chunk: chunk, Files: files}
	l.starts = make([]int64, len(files))
	for i, f := range files {
		if f.Size < 0 || !safePath(f.Path) {
			return nil, errors.New("manifest: bad file entry " + f.Path)
		}
		l.starts[i] = l.Size
		l.Size += f.Size
	}
	return l, nil
}

// FromManifest builds a layout from a received manifest.
func FromManifest(m *signal.Manifest) (*Layout, error) {
	if m.Hash != "sha256" {
		return nil, errors.New("manifest: unsupported hash " + m.Hash)
	}
	if !safePath(m.Name) || strings.Contains(m.Name, "/") {
		return nil, errors.New("manifest: bad name")
	}
	l, err := NewLayout(m.Name, m.Files, m.Chunk)
	if err != nil {
		return nil, err
	}
	if l.Size != m.Size {
		return nil, errors.New("manifest: size does not match files")
	}
	return l, nil
}

// Chunks is ceil(Size/Chunk).
func (l *Layout) Chunks() int {
	if l.Size == 0 {
		return 0
	}
	return int((l.Size + int64(l.Chunk) - 1) / int64(l.Chunk))
}

// ChunkSpan returns the byte offset and length of chunk i.
func (l *Layout) ChunkSpan(i int) (off int64, n int) {
	off = int64(i) * int64(l.Chunk)
	n = l.Chunk
	if rem := l.Size - off; rem < int64(n) {
		n = int(rem)
	}
	return
}

// IsDir reports whether the layout is a folder rather than a single file.
func (l *Layout) IsDir() bool {
	return len(l.Files) != 1 || l.Files[0].Path != l.Name
}

// fileAt returns the index of the file containing offset off.
func (l *Layout) fileAt(off int64) int {
	// last file whose start <= off; zero-length files share a start with the
	// next file, and the later index wins, which is the non-empty one.
	i := sort.Search(len(l.starts), func(k int) bool { return l.starts[k] > off }) - 1
	if i < 0 {
		i = 0
	}
	return i
}

// segments splits [off, off+n) into per-file pieces.
type segment struct {
	file   int
	inFile int64
	n      int
}

func (l *Layout) segments(off int64, n int) []segment {
	var out []segment
	for n > 0 {
		fi := l.fileAt(off)
		inFile := off - l.starts[fi]
		avail := l.Files[fi].Size - inFile
		if avail <= 0 {
			// Only reachable if off >= Size; guard against an infinite loop.
			break
		}
		k := int64(n)
		if k > avail {
			k = avail
		}
		out = append(out, segment{file: fi, inFile: inFile, n: int(k)})
		off += k
		n -= int(k)
	}
	return out
}

func safePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return false
	}
	clean := path.Clean(p)
	if clean != p || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." || part == "" {
			return false
		}
	}
	return true
}
