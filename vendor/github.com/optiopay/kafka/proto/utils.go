package proto

import (
	"fmt"
	"math"
)

const (
	maxParseBufSize = 10 * math.MaxUint16
)

func messageSizeError(size int) error {
	return fmt.Errorf("unreasonable message/block size %d (max:%d)", size, maxParseBufSize)
}

// allocParseBuf is used to allocate buffers used for parsing
func allocParseBuf(size int) ([]byte, error) {
	if size < 0 || size > maxParseBufSize {
		return nil, messageSizeError(size)
	}

	return make([]byte, size), nil
}
