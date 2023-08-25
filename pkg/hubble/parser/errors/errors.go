// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package errors

import (
	"errors"
	"fmt"
)

var (
	// ErrEmptyData gets returns when monitoring payload contained no data
	ErrEmptyData = errors.New("empty data")
	// ErrUnknownEventType is returned if the monitor event is an unknown type
	ErrUnknownEventType = errors.New("unknown event type")
	// ErrInvalidAgentMessageType is returned if an agent message is of invalid type
	ErrInvalidAgentMessageType = errors.New("invalid agent message type")
	// ErrEventSkipped is returned when an event was skipped (e.g. due to configuration
	// or incomplete data)
	ErrEventSkipped = errors.New("event was skipped")
)

// ErrInvalidType specifies when it was given a packet type that was not
// possible to be decoded by the decoder.
type ErrInvalidType struct {
	invalidType byte
}

// NewErrInvalidType returns a new ErrInvalidType
func NewErrInvalidType(invalidType byte) error {
	return ErrInvalidType{invalidType: invalidType}
}

func (e ErrInvalidType) Error() string {
	return fmt.Sprintf("can't decode following payload type: %v", e.invalidType)
}

// IsErrInvalidType returns true if the given error is type of ErrInvalidType
func IsErrInvalidType(err error) bool {
	_, ok := err.(ErrInvalidType)
	return ok
}
