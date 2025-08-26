// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

type ErrorAction string

var (
	// ErrorActionRetry instructs to retry the processing. The key is requeued after
	// rate limiting.
	ErrorActionRetry ErrorAction = "retry"

	// ErrorActionIgnore instructs to ignore the error.
	ErrorActionIgnore ErrorAction = "ignore"

	// ErrorActionStop instructs to stop the processing for this subscriber.
	ErrorActionStop ErrorAction = "stop"
)

// ErrorHandler is a function that takes the key of the failing object (zero key if event
// was sync), the number of times the key has been retried and the error that occurred.
// The function returns the action that should be taken.
type ErrorHandler func(key Key, numRetries int, err error) ErrorAction

// AlwaysRetry is an error handler that always retries the error.
func AlwaysRetry(Key, int, error) ErrorAction {
	return ErrorActionRetry
}

// RetryUpTo is an error handler that retries a key up to specified number of
// times before stopping.
func RetryUpTo(n int) ErrorHandler {
	return func(key Key, numRetries int, err error) ErrorAction {
		if numRetries >= n {
			return ErrorActionStop
		}
		return ErrorActionRetry
	}
}
