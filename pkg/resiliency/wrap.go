// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

import (
	"errors"
)

// RetryableErr represents an error that can possibly be retried.
type RetryableErr struct {
	error

	Kind Category
}

// Retry checks whether error could be retried.
// TODO will need m'o tuning..
func (b RetryableErr) Retryable() bool {
	switch b.Kind {
	case ResLimit:
		return false
	default:
		return true
	}
}

// Wrap returns a new instance.
func Wrap(e error, k Category) RetryableErr {
	return RetryableErr{
		error: e,
		Kind:  k,
	}
}

// WrapResExt returns a new resExt error.
func WrapResExt(e error) RetryableErr {
	return Wrap(e, ResExt)
}

// WrapResLimit returns a new resLimit error.
func WrapResLimit(e error) RetryableErr {
	return Wrap(e, ResLimit)
}

// WrapExtSys returns a new extSys error.
func WrapExtSys(e error) RetryableErr {
	return Wrap(e, ExtSys)
}

// IsRetryable checks if an error is retryable.
func IsRetryable(e error) bool {
	re := new(RetryableErr)

	errs, ok := e.(interface {
		Unwrap() []error
	})
	if !ok {
		return errors.As(e, re) && e.(RetryableErr).Retryable()
	}
	for _, err := range errs.Unwrap() {
		if errors.As(err, re) {
			return err.(RetryableErr).Retryable()
		}
	}

	return false
}
