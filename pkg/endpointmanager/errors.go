// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
