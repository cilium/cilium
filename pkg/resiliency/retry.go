// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

import (
	"errors"
)

// IsRetryable checks if an error can be retried.
func IsRetryable(e error) bool {
	return errors.As(e, new(retryableErr))
}
