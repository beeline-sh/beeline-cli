//go:build !unix

package daemon

import "os/exec"

// detach is a no-op here; on Windows run `beeline daemon` as a service or in
// its own window (see README).
func detach(cmd *exec.Cmd) {}
