//go:build !linux && !darwin && !windows && !freebsd
// +build !linux,!darwin,!windows,!freebsd

package memory

import (
	"fmt"
	"runtime"
)

// Get memory statistics
func Get() (*Stats, error) {
	return nil, fmt.Errorf("memory statistics not implemented for: %s", runtime.GOOS)
}

// Stats represents memory statistics
type Stats struct {
	Total, Used, Cached, Free, Active, Inactive, SwapTotal, SwapUsed, SwapFree uint64
}
