package aws

import (
	"context"
	"fmt"
	"time"
)

// Retryer is an interface to determine if a given error from a
// request should be retried, and if so what backoff delay to apply. The
// default implementation used by most services is the retry package's Standard
// type. Which contains basic retry logic using exponential backoff.
type Retryer interface {
	// IsErrorRetryable returns if the failed request is retryable. This check
	// should determine if the error can be retried, or if the error is
	// terminal.
	IsErrorRetryable(error) bool

	// MaxAttempts returns the maximum number of attempts that can be made for
	// a request before failing. A value of 0 implies that the request should
	// be retried until it succeeds if the errors are retryable.
	MaxAttempts() int

	// RetryDelay returns the delay that should be used before retrying the
	// request. Will return error if the if the delay could not be determined.
	RetryDelay(attempt int, opErr error) (time.Duration, error)

	// GetRetryToken attempts to deduct the retry cost from the retry token pool.
	// Returning the token release function, or error.
	GetRetryToken(ctx context.Context, opErr error) (releaseToken func(error) error, err error)

	// GetInitalToken returns the initial request token that can increment the
	// retry token pool if the request is successful.
	GetInitialToken() (releaseToken func(error) error)
}

// NoOpRetryer provides a RequestRetryDecider implementation that will flag
// all attempt errors as not retryable, with a max attempts of 1.
type NoOpRetryer struct{}

// IsErrorRetryable returns false for all error values.
func (NoOpRetryer) IsErrorRetryable(error) bool { return false }

// MaxAttempts always returns 1 for the original request attempt.
func (NoOpRetryer) MaxAttempts() int { return 1 }

// RetryDelay is not valid for the NoOpRetryer. Will always return error.
func (NoOpRetryer) RetryDelay(int, error) (time.Duration, error) {
	return 0, fmt.Errorf("not retrying any request errors")
}

// GetRetryToken returns a stub function that does nothing.
func (NoOpRetryer) GetRetryToken(context.Context, error) (func(error) error, error) {
	return nopReleaseToken, nil
}

// GetInitialToken returns a stub function that does nothing.
func (NoOpRetryer) GetInitialToken() func(error) error {
	return nopReleaseToken
}

func nopReleaseToken(error) error { return nil }
