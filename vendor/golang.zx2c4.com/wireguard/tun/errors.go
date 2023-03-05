package tun

import (
	"errors"
	"fmt"
)

var (
	// ErrTooManySegments is returned by Device.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")
)

type errorBatch []error

// ErrorBatch takes a possibly nil or empty list of errors, and if the list is
// non-nil returns an error type that wraps all of the errors. Expected usage is
// to append to an []errors and coerce the set to an error using this method.
func ErrorBatch(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errorBatch(errs)
}

func (e errorBatch) Error() string {
	if len(e) == 0 {
		return ""
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("batch operation: %v (and %d more errors)", e[0], len(e)-1)
}

func (e errorBatch) Is(target error) bool {
	for _, err := range e {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (e errorBatch) As(target interface{}) bool {
	for _, err := range e {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

func (e errorBatch) Unwrap() error {
	if len(e) == 0 {
		return nil
	}
	return e[0]
}
