// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"errors"
)

var (
	// ErrUnsupportedID represents an error of unsupported IP address format.
	ErrUnsupportedID = errors.New("unsupported IP address format")
)

// ErrInvalidPrefix represents the error of an invalid prefix.
type ErrInvalidPrefix struct {
	// InvalidPrefix contains the invalid prefix.
	InvalidPrefix string
}

// Error returns the string representation of the ErrInvalidPrefix.
func (e ErrInvalidPrefix) Error() string {
	return "unknown endpoint prefix '" + e.InvalidPrefix + "'"
}

// IsErrUnsupportedID returns true if the given error is the type of
// ErrUnsupportedID.
func IsErrUnsupportedID(err error) bool {
	return errors.Is(err, ErrUnsupportedID)
}

// IsErrInvalidPrefix returns true if the given error is the type of
// ErrInvalidPrefix.
func IsErrInvalidPrefix(err error) bool {
	_, ok := err.(ErrInvalidPrefix)
	return ok
}
