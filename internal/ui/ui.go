// Package ui formats sizes, rates and progress bars the way the landing page shows them.
package ui

import (
	"fmt"
	"strings"
	"time"
)

// Size renders SI sizes: 3.8 GB, 412 MB, 27.4 GB.
func Size(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(b)
	i := 0
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	switch {
	case i == 0:
		return fmt.Sprintf("%d %s", b, units[i])
	case f < 10:
		return fmt.Sprintf("%.2f %s", f, units[i])
	case f < 100:
		return fmt.Sprintf("%.1f %s", f, units[i])
	default:
		return fmt.Sprintf("%.0f %s", f, units[i])
	}
}

// Rate renders bytes per second.
func Rate(bps float64) string {
	if bps < 1e3 {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	if bps < 1e6 {
		return fmt.Sprintf("%.0f KB/s", bps/1e3)
	}
	if bps < 1e9 {
		return fmt.Sprintf("%.0f MB/s", bps/1e6)
	}
	return fmt.Sprintf("%.2f GB/s", bps/1e9)
}

// Bar renders a 24-cell progress bar.
func Bar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	n := int(frac*float64(width) + 0.5)
	return strings.Repeat("█", n) + strings.Repeat("░", width-n)
}

// ETA renders remaining time as mm:ss or h:mm:ss.
func ETA(remaining int64, bps float64) string {
	if bps <= 0 {
		return "--:--"
	}
	d := time.Duration(float64(remaining)/bps) * time.Second
	if d >= time.Hour {
		return fmt.Sprintf("%d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

// Duration parses "24h", "7d", "30m", "0".
func Duration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(s, "%gd", &days); err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}
