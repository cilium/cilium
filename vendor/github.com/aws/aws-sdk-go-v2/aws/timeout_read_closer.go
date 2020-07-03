package aws

import (
	"fmt"
	"io"
	"time"
)

type readResult struct {
	n   int
	err error
}

// ResponseTimeoutError is an error when the reads from the response are
// delayed longer than the timeout the read was configured for.
type ResponseTimeoutError struct {
	TimeoutDur time.Duration
}

// Timeout returns that the error is was caused by a timeout, and can be
// retried.
func (*ResponseTimeoutError) Timeout() bool { return true }

func (e *ResponseTimeoutError) Error() string {
	return fmt.Sprintf("read on body reach timeout limit, %v", e.TimeoutDur)
}

// timeoutReadCloser will handle body reads that take too long.
// We will return a ErrReadTimeout error if a timeout occurs.
type timeoutReadCloser struct {
	reader   io.ReadCloser
	duration time.Duration
}

// Read will spin off a goroutine to call the reader's Read method. We will
// select on the timer's channel or the read's channel. Whoever completes first
// will be returned.
func (r *timeoutReadCloser) Read(b []byte) (int, error) {
	timer := time.NewTimer(r.duration)
	c := make(chan readResult, 1)

	go func() {
		n, err := r.reader.Read(b)
		timer.Stop()
		c <- readResult{n: n, err: err}
	}()

	select {
	case data := <-c:
		return data.n, data.err
	case <-timer.C:
		return 0, &ResponseTimeoutError{TimeoutDur: r.duration}
	}
}

func (r *timeoutReadCloser) Close() error {
	return r.reader.Close()
}

const (
	// HandlerResponseTimeout is what we use to signify the name of the
	// response timeout handler.
	HandlerResponseTimeout = "ResponseTimeoutHandler"
)

// WithResponseReadTimeout is a request option that will wrap the body in a timeout read closer.
// This will allow for per read timeouts. If a timeout occurred, we will return the
// ErrCodeResponseTimeout.
//
//     svc.PutObjectWithContext(ctx, params, request.WithTimeoutReadCloser(30 * time.Second)
func WithResponseReadTimeout(duration time.Duration) Option {
	return func(r *Request) {
		var timeoutHandler = NamedHandler{
			HandlerResponseTimeout,
			func(req *Request) {
				req.HTTPResponse.Body = &timeoutReadCloser{
					reader:   req.HTTPResponse.Body,
					duration: duration,
				}
			}}

		// remove the handler so we are not stomping over any new durations.
		r.Handlers.Send.RemoveByName(HandlerResponseTimeout)
		r.Handlers.Send.PushBackNamed(timeoutHandler)
	}
}
