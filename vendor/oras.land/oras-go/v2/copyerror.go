/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oras

import "fmt"

// CopyErrorOrigin defines the source of a copy error.
type CopyErrorOrigin int

const (
	// CopyErrorOriginSource indicates the error occurred at the source side.
	CopyErrorOriginSource CopyErrorOrigin = 1

	// CopyErrorOriginDestination indicates the error occurred at the destination side.
	CopyErrorOriginDestination CopyErrorOrigin = 2
)

// String returns the string representation of the CopyErrorOrigin.
func (o CopyErrorOrigin) String() string {
	switch o {
	case CopyErrorOriginSource:
		return "source"
	case CopyErrorOriginDestination:
		return "destination"
	default:
		return "unknown"
	}
}

// CopyError represents an error encountered during a copy operation.
type CopyError struct {
	// Op is the operation that caused the error.
	Op string
	// Origin indicates the source of the error.
	Origin CopyErrorOrigin
	// Err is the underlying error.
	Err error
}

// newCopyError creates a new CopyError.
func newCopyError(op string, origin CopyErrorOrigin, err error) error {
	if err == nil {
		return nil
	}
	return &CopyError{
		Op:     op,
		Origin: origin,
		Err:    err,
	}
}

// Error implements the error interface for CopyError.
func (e *CopyError) Error() string {
	switch e.Origin {
	case CopyErrorOriginSource, CopyErrorOriginDestination:
		return fmt.Sprintf("failed to perform %q on %s: %v", e.Op, e.Origin, e.Err)
	default:
		return fmt.Sprintf("failed to perform %q: %v", e.Op, e.Err)
	}
}

// Unwrap implements the errors.Unwrap interface for CopyError.
func (e *CopyError) Unwrap() error {
	return e.Err
}
