// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

import (
	"errors"
)

// IsRetryable checks if an error is classified as retryable.
// Returns true if so, false otherwise.
func IsRetryable(e error) bool {
	re := new(RetryableErr)

	errs, ok := e.(interface {
		Unwrap() []error
	})
	if !ok {
		return errors.As(e, re)
	}
	for _, err := range errs.Unwrap() {
		if errors.As(err, re) {
			return true
		}
	}

	return false
}
