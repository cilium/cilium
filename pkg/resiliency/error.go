// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

// retryableErr tracks errors that could be retried.
type retryableErr struct {
	error
}

// Retryable returns a new instance.
func Retryable(e error) retryableErr {
	return retryableErr{error: e}
}
