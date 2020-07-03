package defaults

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

// Interface for matching types which also have a Len method.
type lener interface {
	Len() int
}

// BuildContentLengthHandler builds the content length of a request based on the body,
// or will use the HTTPRequest.Header's "Content-Length" if defined. If unable
// to determine request body length and no "Content-Length" was specified it will panic.
//
// The Content-Length will only be added to the request if the length of the body
// is greater than 0. If the body is empty or the current `Content-Length`
// header is <= 0, the header will also be stripped.
var BuildContentLengthHandler = aws.NamedHandler{Name: "core.BuildContentLengthHandler", Fn: func(r *aws.Request) {
	var length int64

	if slength := r.HTTPRequest.Header.Get("Content-Length"); slength != "" {
		length, _ = strconv.ParseInt(slength, 10, 64)
	} else {
		switch body := r.Body.(type) {
		case nil:
			length = 0
		case lener:
			length = int64(body.Len())
		case io.Seeker:
			var err error
			r.BodyStart, err = body.Seek(0, io.SeekCurrent)
			if err != nil {
				r.Error = awserr.New(aws.ErrCodeSerialization, "failed to determine start of the request body", err)
			}
			end, err := body.Seek(0, io.SeekEnd)
			if err != nil {
				r.Error = awserr.New(aws.ErrCodeSerialization, "failed to determine end of the request body", err)
			}
			_, err = body.Seek(r.BodyStart, io.SeekStart) // make sure to seek back to original location
			if err != nil {
				r.Error = awserr.New(aws.ErrCodeSerialization, "failed to seek back to the original location", err)
			}
			length = end - r.BodyStart
		default:
			panic("Cannot get length of body, must provide `ContentLength`")
		}
	}

	if length > 0 {
		r.HTTPRequest.ContentLength = length
		r.HTTPRequest.Header.Set("Content-Length", fmt.Sprintf("%d", length))
	} else {
		r.HTTPRequest.ContentLength = 0
		r.HTTPRequest.Header.Del("Content-Length")
	}
}}

var reStatusCode = regexp.MustCompile(`^(\d{3})`)

// ValidateReqSigHandler is a request handler to ensure that the request's
// signature doesn't expire before it is sent. This can happen when a request
// is built and signed significantly before it is sent. Or significant delays
// occur when retrying requests that would cause the signature to expire.
var ValidateReqSigHandler = aws.NamedHandler{
	Name: "core.ValidateReqSigHandler",
	Fn: func(r *aws.Request) {
		// Unsigned requests are not signed
		if r.Config.Credentials == aws.AnonymousCredentials {
			return
		}

		signedTime := r.Time
		if !r.LastSignedAt.IsZero() {
			signedTime = r.LastSignedAt
		}

		// 10 minutes to allow for some clock skew/delays in transmission.
		// Would be improved with aws/aws-sdk-go#423
		if signedTime.Add(10 * time.Minute).After(time.Now()) {
			return
		}

		r.Sign()
	},
}

// SendHandler is a request handler to send service request using HTTP client.
var SendHandler = aws.NamedHandler{
	Name: "core.SendHandler",
	Fn: func(r *aws.Request) {

		// TODO remove this complexity the SDK's built http.Request should
		// set Request.Body to nil, if there is no body to send. #318
		if http.NoBody == r.HTTPRequest.Body {
			// Strip off the request body if the NoBody reader was used as a
			// place holder for a request body. This prevents the SDK from
			// making requests with a request body when it would be invalid
			// to do so.
			//
			// Use a shallow copy of the http.Request to ensure the race condition
			// of transport on Body will not trigger
			reqOrig, reqCopy := r.HTTPRequest, *r.HTTPRequest
			reqCopy.Body = nil
			r.HTTPRequest = &reqCopy
			defer func() {
				r.HTTPRequest = reqOrig
			}()
		}

		var err error
		r.HTTPResponse, err = r.Config.HTTPClient.Do(r.HTTPRequest)
		r.ResponseAt = sdk.NowTime()
		if err != nil {
			handleSendError(r, err)
		}
	},
}

func handleSendError(r *aws.Request, err error) {
	// Prevent leaking if an HTTPResponse was returned. Clean up
	// the body.
	if r.HTTPResponse != nil {
		r.HTTPResponse.Body.Close()
	}

	// Capture the case where url.Error is returned for error processing
	// response. e.g. 301 without location header comes back as string
	// error and r.HTTPResponse is nil. Other URL redirect errors will
	// comeback in a similar method.
	if e, ok := err.(*url.Error); ok && e.Err != nil {
		if s := reStatusCode.FindStringSubmatch(e.Err.Error()); s != nil {
			code, _ := strconv.ParseInt(s[1], 10, 64)
			r.HTTPResponse = &http.Response{
				StatusCode: int(code),
				Status:     http.StatusText(int(code)),
				Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
			}
			return
		}
	}
	if r.HTTPResponse == nil {
		// Add a dummy request response object to ensure the HTTPResponse
		// value is consistent.
		r.HTTPResponse = &http.Response{
			StatusCode: int(0),
			Status:     http.StatusText(int(0)),
			Body:       ioutil.NopCloser(bytes.NewReader([]byte{})),
		}
	}

	// Catch all request errors, and let the retryer determine
	// if the error is retryable.
	r.Error = &aws.RequestSendError{Response: r.HTTPResponse, Err: err}

	// Override the error with a context canceled error, if that was canceled.
	ctx := r.Context()
	select {
	case <-ctx.Done():
		r.Error = &aws.RequestCanceledError{Err: ctx.Err()}
	default:
	}
}

// ValidateResponseHandler is a request handler to validate service response.
var ValidateResponseHandler = aws.NamedHandler{
	Name: "core.ValidateResponseHandler",
	Fn: func(r *aws.Request) {
		if r.HTTPResponse.StatusCode >= 300 {
			// This may be replaced by a protocol's UnmarshalError handler
			r.Error = &aws.HTTPResponseError{Response: r.HTTPResponse}
		}
	}}

// RequestInvocationIDHeaderHandler sets the invocation id header for request
// tracking across attempts.
var RequestInvocationIDHeaderHandler = aws.NamedHandler{
	Name: "core.RequestInvocationIDHeaderHandler",
	Fn: func(r *aws.Request) {
		if r.ExpireTime != 0 {
			// ExpireTime set implies a presigned URL which will not have the
			// header applied.
			return
		}

		const invocationIDHeader = "amz-sdk-invocation-id"
		r.HTTPRequest.Header.Set(invocationIDHeader, r.InvocationID)
	}}

// RetryMetricHeaderHandler sets an additional header to the API request that
// includes retry details for the service to consider.
var RetryMetricHeaderHandler = aws.NamedHandler{
	Name: "core.RetryMetricHeaderHandler",
	Fn: func(r *aws.Request) {
		if r.ExpireTime != 0 {
			// ExpireTime set implies a presigned URL which will not have the
			// header applied.
			return
		}

		const retryMetricHeader = "amz-sdk-request"
		var parts []string

		parts = append(parts, fmt.Sprintf("attempt=%d", r.AttemptNum))
		if max := r.Retryer.MaxAttempts(); max != 0 {
			parts = append(parts, fmt.Sprintf("max=%d", max))
		}

		type timeoutGetter interface {
			GetTimeout() time.Duration
		}

		var ttl time.Time
		// Attempt extract the TTL from context deadline, or timeout on the client.
		if v, ok := r.Config.HTTPClient.(timeoutGetter); ok {
			if t := v.GetTimeout(); t > 0 {
				ttl = sdk.NowTime().Add(t)
			}
		}
		if ttl.IsZero() {
			if deadline, ok := r.Context().Deadline(); ok {
				ttl = deadline
			}
		}

		// Only append the TTL if it can be determined.
		if !ttl.IsZero() && len(r.AttemptClockSkews) > 0 {
			const unixTimeFormat = "20060102T150405Z"
			ttl = ttl.Add(r.AttemptClockSkews[len(r.AttemptClockSkews)-1])
			parts = append(parts, fmt.Sprintf("ttl=%s", ttl.Format(unixTimeFormat)))
		}

		r.HTTPRequest.Header.Set(retryMetricHeader, strings.Join(parts, "; "))
	}}

// RetryableCheckHandler performs final checks to determine if the request should
// be retried and how long to delay.
var RetryableCheckHandler = aws.NamedHandler{
	Name: "core.RetryableCheckHandler",
	Fn: func(r *aws.Request) {
		r.ShouldRetry = false

		retryable := r.Retryer.IsErrorRetryable(r.Error)
		if !retryable {
			return
		}

		if max := r.Retryer.MaxAttempts(); max > 0 && r.AttemptNum >= max {
			r.Error = &aws.MaxAttemptsError{
				Attempt: r.AttemptNum,
				Err:     r.Error,
			}
			return
		}

		var err error
		r.RetryDelay, err = r.Retryer.RetryDelay(r.AttemptNum, r.Error)
		if err != nil {
			r.Error = err
			return
		}

		r.ShouldRetry = true
	}}

// ValidateEndpointHandler is a request handler to validate a request had the
// appropriate Region and Endpoint set. Will set r.Error if the endpoint or
// region is not valid.
var ValidateEndpointHandler = aws.NamedHandler{Name: "core.ValidateEndpointHandler", Fn: func(r *aws.Request) {
	if r.Endpoint.SigningRegion == "" && r.Config.Region == "" {
		r.Error = &aws.MissingRegionError{}
	} else if len(r.Endpoint.URL) == 0 {
		r.Error = &aws.MissingEndpointError{}
	}
}}

// AttemptClockSkewHandler records the estimated clock skew between the client
// and service response clocks. This estimation will be no more granular than
// one second. It will not be populated until after at least the first
// attempt's response is received.
var AttemptClockSkewHandler = aws.NamedHandler{
	Name: "core.AttemptClockSkewHandler",
	Fn: func(r *aws.Request) {
		if r.ResponseAt.IsZero() || r.HTTPResponse == nil || r.HTTPResponse.StatusCode == 0 {
			return
		}

		respDateHeader := r.HTTPResponse.Header.Get("Date")
		if len(respDateHeader) == 0 {
			return
		}

		respDate, err := http.ParseTime(respDateHeader)
		if err != nil {
			// Fallback trying the SDK's RFC 822 datetime format parsing which handles 1digit formatted
			// day of month pattern. RFC 2616 states the RFC 822 datetime muse use 2digit days, but some
			// APIs may respond with the incorrect format.
			respDate, err = protocol.ParseTime(protocol.RFC822TimeFormatName, respDateHeader)
		}
		if err != nil {
			if r.Config.Logger != nil {
				r.Config.Logger.Log(fmt.Sprintf("ERROR: unable to determine clock skew for %s/%s API response, invalid Date header value, %v",
					r.Metadata.ServiceName, r.Operation.Name, respDateHeader))
			}
			return
		}

		r.AttemptClockSkews = append(r.AttemptClockSkews,
			respDate.Sub(r.ResponseAt),
		)
	},
}
