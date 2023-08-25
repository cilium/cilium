// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safeio

import (
	"fmt"
	"io"
)

// ErrLimitReached indicates that ReadAllLimit has
// reached its limit before completing a full read
// of the io.Reader.
var ErrLimitReached = fmt.Errorf("read limit reached")

// ByteSize expresses the size of bytes
type ByteSize float64

const (
	_ = iota // ignore first value by assigning to blank identifier
	// KB is a Kilobyte
	KB ByteSize = 1 << (10 * iota)
	// MB is a Megabyte
	MB
	// GB is a Gigabyte
	GB
	// TB is a Terabyte
	TB
	// PB is a Petabyte
	PB
	// EB is an Exabyte
	EB
	// ZB is a Zettabyte
	ZB
	// YB is a Yottabyte
	YB
)

// String converts a ByteSize to a string
func (b ByteSize) String() string {
	switch {
	case b >= YB:
		return fmt.Sprintf("%.1fYB", b/YB)
	case b >= ZB:
		return fmt.Sprintf("%.1fZB", b/ZB)
	case b >= EB:
		return fmt.Sprintf("%.1fEB", b/EB)
	case b >= PB:
		return fmt.Sprintf("%.1fPB", b/PB)
	case b >= TB:
		return fmt.Sprintf("%.1fTB", b/TB)
	case b >= GB:
		return fmt.Sprintf("%.1fGB", b/GB)
	case b >= MB:
		return fmt.Sprintf("%.1fMB", b/MB)
	case b >= KB:
		return fmt.Sprintf("%.1fKB", b/KB)
	}
	return fmt.Sprintf("%.1fB", b)
}

// ReadAllLimit reads from r until an error, EOF, or after n bytes and returns
// the data it read. A successful call returns err == nil, not err == EOF.
// Because ReadAllLimit is defined to read from src until EOF it does not
// treat an EOF from Read as an error to be reported. If the limit is reached
// ReadAllLimit will return ErrLimitReached as an error.
func ReadAllLimit(r io.Reader, n ByteSize) ([]byte, error) {
	limit := int(n + 1)
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit)))
	if err != nil {
		return buf, err
	}
	if len(buf) >= limit {
		return buf[:limit-1], ErrLimitReached
	}
	return buf, nil
}
