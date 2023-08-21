// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

// RetryableErr tracks errors that could be retried.
type RetryableErr struct {
	error
}

// NewRetryableErr returns a new instance.
func NewRetryableErr(e error) RetryableErr {
	return RetryableErr{error: e}
}
