// Package config resolves settings: defaults < ~/.config/beeline/config.json < environment.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

const (
	Version       = "0.1.0"
	DefaultServer = "https://beeline.sh"
	DefaultPort   = 41820
)

type Config struct {
	Server string `json:"server"` // introduction server base URL
	Port   int    `json:"port"`   // UDP port the daemon listens on (0 = random)
	Socket string `json:"socket"` // daemon control socket
	Relay  string `json:"relay"`  // "auto" | "never"
}

func Load() Config {
	c := Config{Server: DefaultServer, Port: DefaultPort, Socket: SocketPath(), Relay: "auto"}
	if dir, err := os.UserConfigDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "beeline", "config.json")); err == nil {
			_ = json.Unmarshal(b, &c)
		}
	}
	if v := os.Getenv("BEELINE_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("BEELINE_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.Port = p
		}
	}
	if v := os.Getenv("BEELINE_SOCKET"); v != "" {
		c.Socket = v
	}
	if v := os.Getenv("BEELINE_RELAY"); v != "" {
		c.Relay = v
	}
	return c
}

// SocketPath is $XDG_RUNTIME_DIR/beeline.sock, else ~/.beeline/beeline.sock.
func SocketPath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "beeline.sock")
	}
	return filepath.Join(DataDir(), "beeline.sock")
}

// DataDir is ~/.beeline (spool files, daemon log).
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	d := filepath.Join(home, ".beeline")
	_ = os.MkdirAll(d, 0o700)
	return d
}
