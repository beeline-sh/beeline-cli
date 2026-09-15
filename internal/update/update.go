// Package update fetches the latest beeline-cli release from GitHub,
// replaces the running binary, and answers the "is there a newer version?"
// question that share/get/ls/revoke print a hint for.
package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.beeline.sh/cli/internal/config"
)

const (
	repo      = "beeline-sh/beeline-cli"
	latestURL = "https://api.github.com/repos/" + repo + "/releases/latest"
	userAgent = "beeline/" + "cli"
)

// Release is what we need from the GitHub release object.
type Release struct {
	Tag    string
	Assets map[string]string // name -> download url
}

// Latest asks GitHub for the newest release.
func Latest(ctx context.Context, timeout time.Duration) (Release, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("User-Agent", userAgent+"/"+config.Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Release{}, fmt.Errorf("github: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return Release{}, err
	}
	if body.Tag == "" {
		return Release{}, errors.New("github: no tag in latest release")
	}
	r := Release{Tag: body.Tag, Assets: map[string]string{}}
	for _, a := range body.Assets {
		r.Assets[a.Name] = a.URL
	}
	return r, nil
}

// Newer reports whether tag (vX.Y.Z) is newer than cur (X.Y.Z). Anything
// unparsable in cur (a dev build) counts as older.
func Newer(cur, tag string) bool {
	a, okA := parse(cur)
	b, okB := parse(tag)
	if !okB {
		return false
	}
	if !okA {
		return true
	}
	for i := 0; i < 3; i++ {
		if b[i] != a[i] {
			return b[i] > a[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	var out [3]int
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// AssetName is the release archive for this platform.
func AssetName(tag string) string {
	num := strings.TrimPrefix(tag, "v")
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("beeline_%s_%s_%s%s", num, runtime.GOOS, runtime.GOARCH, ext)
}

// Apply downloads the release for this platform, verifies its checksum and
// swaps it over the running executable. Returns the executable path.
func Apply(ctx context.Context, r Release) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("automatic update is not available on Windows; download %s from https://github.com/%s/releases/tag/%s and replace beeline.exe", AssetName(r.Tag), repo, r.Tag)
	}
	name := AssetName(r.Tag)
	url, ok := r.Assets[name]
	if !ok {
		return "", fmt.Errorf("release %s has no build for %s/%s", r.Tag, runtime.GOOS, runtime.GOARCH)
	}
	sums, ok := r.Assets["checksums.txt"]
	if !ok {
		return "", fmt.Errorf("release %s has no checksums.txt", r.Tag)
	}
	archive, err := fetch(ctx, url, 200<<20)
	if err != nil {
		return "", err
	}
	sumList, err := fetch(ctx, sums, 1<<20)
	if err != nil {
		return "", err
	}
	want := ""
	for _, line := range strings.Split(string(sumList), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			want = f[0]
		}
	}
	if want == "" {
		return "", fmt.Errorf("%s is not listed in checksums.txt", name)
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s", name)
	}
	bin, err := extract(archive, name)
	if err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	tmp := filepath.Join(filepath.Dir(exe), ".beeline.new")
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return exe, nil
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent+"/"+config.Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// extract pulls the single `beeline` binary out of the archive.
func extract(archive []byte, name string) ([]byte, error) {
	if strings.HasSuffix(name, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == "beeline.exe" {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, errors.New("beeline.exe not in archive")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(h.Name) == "beeline" && h.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, errors.New("beeline binary not in archive")
}

// ---- background check for the "run beeline update" hint ----

type cache struct {
	CheckedAt int64  `json:"checked_at"`
	Latest    string `json:"latest"`
}

func cachePath() string { return filepath.Join(config.DataDir(), "update-check.json") }

// Check returns a function that yields the latest known tag, or "" if
// unknown. The network is asked at most once per 24 h, with the given
// timeout, in the background; the returned function never blocks longer
// than that timeout. Disabled by BEELINE_NO_UPDATE_CHECK=1.
func Check(ctx context.Context, timeout time.Duration) func() string {
	if os.Getenv("BEELINE_NO_UPDATE_CHECK") == "1" {
		return func() string { return "" }
	}
	var c cache
	if b, err := os.ReadFile(cachePath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if time.Since(time.Unix(c.CheckedAt, 0)) < 24*time.Hour {
		latest := c.Latest
		return func() string { return latest }
	}
	done := make(chan string, 1)
	go func() {
		r, err := Latest(ctx, timeout)
		if err != nil {
			done <- ""
			return
		}
		if b, err := json.Marshal(cache{CheckedAt: time.Now().Unix(), Latest: r.Tag}); err == nil {
			_ = os.WriteFile(cachePath(), b, 0o600)
		}
		done <- r.Tag
	}()
	return func() string {
		select {
		case v := <-done:
			return v
		case <-time.After(timeout + 200*time.Millisecond):
			return ""
		}
	}
}
