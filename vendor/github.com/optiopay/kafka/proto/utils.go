package proto

import (
	"errors"
	"math"
)

const (
	maxParseBufSize = 10 * math.MaxUint16
)

var (
	// ErrInvalidBufferLen is returned when a Kafka protocol field contains
	// an unreasonable value for the size of the message or the size of a
	// variable length field which would result in an unreasonable memory
	// allocation attempt
	ErrInvalidBufferLen = errors.New("unreasonable message/block size")
)

// allocParseBuf is used to allocate buffers used for parsing
func allocParseBuf(size int) ([]byte, error) {
	if size < 0 || size > maxParseBufSize {
		return nil, ErrInvalidBufferLen
	}

	return make([]byte, size), nil
}
