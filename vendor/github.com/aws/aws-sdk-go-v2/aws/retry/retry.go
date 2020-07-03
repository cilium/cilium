package retry

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Retryer defines an interface for extension utilities to extend the built in
// retryer.
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

// AddWithErrorCodes returns a Retryer with additional error codes considered
// for determining if the error should be retried.
func AddWithErrorCodes(r Retryer, codes ...string) Retryer {
	retryable := &RetryableErrorCode{
		Codes: map[string]struct{}{},
	}
	for _, c := range codes {
		retryable.Codes[c] = struct{}{}
	}

	return &withIsErrorRetryable{
		Retryer:   r,
		Retryable: retryable,
	}
}

type withIsErrorRetryable struct {
	Retryer
	Retryable IsErrorRetryable
}

func (r *withIsErrorRetryable) IsErrorRetryable(err error) bool {
	if v := r.Retryable.IsErrorRetryable(err); v != aws.UnknownTernary {
		return v.Bool()
	}
	return r.Retryer.IsErrorRetryable(err)
}

// AddWithMaxAttempts returns a Retryer with MaxAttempts set to the value
// specified.
func AddWithMaxAttempts(r Retryer, max int) Retryer {
	return &withMaxAttempts{
		Retryer: r,
		Max:     max,
	}
}

type withMaxAttempts struct {
	Retryer
	Max int
}

func (w *withMaxAttempts) MaxAttempts() int {
	return w.Max
}

// AddWithMaxBackoffDelay returns a retryer wrapping the passed in retryer
// overriding the RetryDelay behavior for a alternate minimum initial backoff
// delay.
func AddWithMaxBackoffDelay(r Retryer, delay time.Duration) Retryer {
	return &withMinBackoffDelay{
		Retryer: r,
		backoff: NewExponentialJitterBackoff(delay),
	}
}

type withMinBackoffDelay struct {
	Retryer
	backoff *ExponentialJitterBackoff
}

func (r *withMinBackoffDelay) RetryDelay(attempt int, err error) (time.Duration, error) {
	return r.backoff.BackoffDelay(attempt, err)
}
