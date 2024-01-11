//go:build windows
// +build windows

package loadavg

import (
	"errors"
)

func get() (*Stats, error) {
	return nil, errors.New("loadavg for Windows is not supported")
}
