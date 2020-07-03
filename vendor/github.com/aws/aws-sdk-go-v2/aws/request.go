package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/internal/sdk"
)

const (
	// ErrCodeSerialization is the serialization error code that is received
	// during protocol unmarshaling.
	ErrCodeSerialization = "SerializationError"

	// ErrCodeRead is an error that is returned during HTTP reads.
	ErrCodeRead = "ReadError"
)

// SerializationError provides a generic request serialization error
type SerializationError struct {
	Err error // original error
}

// Error returns a formatted error for SerializationError
func (e *SerializationError) Error() string {
	return fmt.Sprintf("serialization failed: %v", e.Err)
}

// Unwrap returns the underlying Error in DeserializationError
func (e *SerializationError) Unwrap() error { return e.Err }

// DeserializationError provides a HTTP transport specific
// request deserialization error
type DeserializationError struct {
	Err error //  original error
}

// Error returns a formatted error for DeserializationError
func (e *DeserializationError) Error() string {
	return fmt.Sprintf("deserialization failed, %v", e.Err)
}

// Unwrap returns the underlying Error in DeserializationError
func (e *DeserializationError) Unwrap() error { return e.Err }

// RequestSendError provides a generic request transport error.
type RequestSendError struct {
	Response interface{}
	Err      error
}

// ConnectionError return that the error is related to not being able to send
// the request.
func (e *RequestSendError) ConnectionError() bool {
	return true
}

// Unwrap returns the underlying error, if there was one.
func (e *RequestSendError) Unwrap() error {
	return e.Err
}

func (e *RequestSendError) Error() string {
	return fmt.Sprintf("request send failed, %v", e.Err)
}

// HTTPResponseError provides the error type for an HTTP error response.
type HTTPResponseError struct {
	Response *http.Response
}

func (e *HTTPResponseError) Error() string {
	return fmt.Sprintf("HTTP response error, %s, %d",
		e.Response.Status, e.Response.StatusCode)
}

// StatusCode returns the underlying status code for the request error.
func (e *HTTPResponseError) StatusCode() int {
	return e.Response.StatusCode
}

// MaxAttemptsError provides the error when the maximum number of attempts have
// been exceeded.
type MaxAttemptsError struct {
	Attempt int
	Err     error
}

func (e *MaxAttemptsError) Error() string {
	return fmt.Sprintf("exceeded maximum number of attempts, %d, %v", e.Attempt, e.Err)
}

// Unwrap returns the nested error causing the max attempts error. Provides the
// implementation for errors.Is and errors.As to unwrap nested errors.
func (e *MaxAttemptsError) Unwrap() error {
	return e.Err
}

// RequestCanceledError is the error that will be returned by an API request
// that was canceled. Requests given a Context may return this error when
// canceled.
type RequestCanceledError struct {
	Err error
}

// CanceledError returns true to satisfy interfaces checking for canceled errors.
func (*RequestCanceledError) CanceledError() bool { return true }

// Unwrap returns the underlying error, if there was one.
func (e *RequestCanceledError) Unwrap() error {
	return e.Err
}
func (e *RequestCanceledError) Error() string {
	return fmt.Sprintf("request canceled, %v", e.Err)
}

// A Request is the service request to be made.
type Request struct {
	Config           Config
	Metadata         Metadata
	Endpoint         Endpoint
	Handlers         Handlers
	Retryer          Retryer
	AttemptTime      time.Time
	Time             time.Time
	ExpireTime       time.Duration
	Operation        *Operation
	HTTPRequest      *http.Request
	HTTPResponse     *http.Response
	Body             io.ReadSeeker
	BodyStart        int64 // offset from beginning of Body that the request body starts
	Params           interface{}
	Error            error
	Data             interface{}
	RequestID        string
	NotHoist         bool
	SignedHeaderVals http.Header
	LastSignedAt     time.Time

	// The time the response headers were received from the API call.
	ResponseAt time.Time

	// AttemptClockSkews are the estimated clock skew between the service
	// response Date header, and when the SDK received the response per
	// attempt. This estimate will include the latency of receiving the
	// service's response headers.
	AttemptClockSkews []time.Duration

	// ID for this operation's request that is shared across attempts.
	InvocationID string

	// The attempt number of this request for the operation.
	AttemptNum int
	// The number of times the operation has be retried.
	RetryCount int

	// Set by the request ShouldRetry handler to direct the request to retry
	// the attempt.
	ShouldRetry bool
	// The backoff delay before retrying the request.
	RetryDelay time.Duration

	context context.Context
	built   bool

	// Additional API error codes that should be retried with throttle backoff
	// delay. IsErrorThrottle will consider these codes in addition to its
	// built in cases.
	ThrottleErrorCodes []string

	// Need to persist an intermediate body between the input Body and HTTP
	// request body because the HTTP Client's transport can maintain a reference
	// to the HTTP request's body after the client has returned. This value is
	// safe to use concurrently and wrap the input Body for each HTTP request.
	safeBody *offsetReader
}

// An Operation is the service API operation to be made.
type Operation struct {
	Name       string
	HTTPMethod string
	HTTPPath   string
	*Paginator

	BeforePresignFn func(r *Request) error
}

// New returns a new Request pointer for the service API
// operation and parameters.
//
// Params is any value of input parameters to be the request payload.
// Data is pointer value to an object which the request's response
// payload will be deserialized to.
func New(cfg Config, metadata Metadata, handlers Handlers,
	retryDecider Retryer, operation *Operation, params interface{}, data interface{}) *Request {

	// TODO improve this experience for config copy?
	cfg = cfg.Copy()

	method := operation.HTTPMethod
	if method == "" {
		method = "POST"
	}

	httpReq, _ := http.NewRequest(method, "", nil)
	r := &Request{
		Config:      cfg,
		Metadata:    metadata,
		Handlers:    handlers.Copy(),
		Retryer:     retryDecider,
		Time:        time.Now(),
		Operation:   operation,
		HTTPRequest: httpReq,
		Params:      params,
		Data:        data,
	}
	r.SetBufferBody([]byte{})

	if r.Retryer == nil {
		r.Retryer = &NoOpRetryer{}
	}

	// TODO need better way of handling this error... NewRequest should return
	// error.
	uuid, err := sdk.UUIDVersion4()
	if err != nil {
		r.Error = err
		return r
	}
	r.InvocationID = uuid

	endpoint, err := cfg.EndpointResolver.ResolveEndpoint(
		metadata.EndpointsID, cfg.Region)

	if err == nil {
		r.SetEndpoint(endpoint)
	} else {
		r.Error = err
	}

	return r
}

// A Option is a functional option that can augment or modify a request when
// using a WithContext API operation method.
type Option func(*Request)

// WithGetResponseHeader builds a request Option which will retrieve a single
// header value from the HTTP Response. If there are multiple values for the
// header key use WithGetResponseHeaders instead to access the http.Header
// map directly. The passed in val pointer must be non-nil.
//
// This Option can be used multiple times with a single API operation.
//
//    var id2, versionID string
//    svc.PutObjectWithContext(ctx, params,
//        request.WithGetResponseHeader("x-amz-id-2", &id2),
//        request.WithGetResponseHeader("x-amz-version-id", &versionID),
//    )
func WithGetResponseHeader(key string, val *string) Option {
	return func(r *Request) {
		r.Handlers.Complete.PushBack(func(req *Request) {
			*val = req.HTTPResponse.Header.Get(key)
		})
	}
}

// WithGetResponseHeaders builds a request Option which will retrieve the
// headers from the HTTP response and assign them to the passed in headers
// variable. The passed in headers pointer must be non-nil.
//
//    var headers http.Header
//    svc.PutObjectWithContext(ctx, params, request.WithGetResponseHeaders(&headers))
func WithGetResponseHeaders(headers *http.Header) Option {
	return func(r *Request) {
		r.Handlers.Complete.PushBack(func(req *Request) {
			*headers = req.HTTPResponse.Header
		})
	}
}

// WithLogLevel is a request option that will set the request to use a specific
// log level when the request is made.
//
//     svc.PutObjectWithContext(ctx, params, request.WithLogLevel(LogDebugWithHTTPBody)
func WithLogLevel(l LogLevel) Option {
	return func(r *Request) {
		r.Config.LogLevel = l
	}
}

// ApplyOptions will apply each option to the request calling them in the order
// the were provided.
func (r *Request) ApplyOptions(opts ...Option) {
	for _, opt := range opts {
		opt(r)
	}
}

// Context will always returns a non-nil context. If Request does not have a
// context the context.Background will be returned.
func (r *Request) Context() context.Context {
	if r.context != nil {
		return r.context
	}
	return context.Background()
}

// SetContext adds a Context to the current request that can be used to cancel
// a in-flight request. The Context value must not be nil, or this method will
// panic.
//
// Unlike http.Request.WithContext, SetContext does not return a copy of the
// Request. It is not safe to use use a single Request value for multiple
// requests. A new Request should be created for each API operation request.
//
// The http.Request.WithContext will be used to set the context on the underlying
// http.Request. This will create a shallow copy of the http.Request. The SDK
// may create sub contexts in the future for nested requests such as retries.
func (r *Request) SetContext(ctx context.Context) {
	if ctx == nil {
		panic("context cannot be nil")
	}
	setRequestContext(ctx, r)
}

// fmtAttemptCount returns a formatted string with attempt count
func fmtAttemptCount(retryCount, maxRetries int) string {
	return fmt.Sprintf("attempt %v/%v", retryCount, maxRetries)
}

// ParamsFilled returns if the request's parameters have been populated
// and the parameters are valid. False is returned if no parameters are
// provided or invalid.
func (r *Request) ParamsFilled() bool {
	return r.Params != nil && reflect.ValueOf(r.Params).Elem().IsValid()
}

// SetBufferBody will set the request's body bytes that will be sent to
// the service API.
func (r *Request) SetBufferBody(buf []byte) {
	r.SetReaderBody(bytes.NewReader(buf))
}

// SetStringBody sets the body of the request to be backed by a string.
func (r *Request) SetStringBody(s string) {
	r.SetReaderBody(strings.NewReader(s))
}

// SetReaderBody will set the request's body reader.
func (r *Request) SetReaderBody(reader io.ReadSeeker) {
	r.Body = reader
	if IsReaderSeekable(reader) {
		var err error
		// Get the Bodies current offset so retries will start from the same
		// initial position.
		r.BodyStart, err = reader.Seek(0, io.SeekCurrent)
		if err != nil {
			r.Error = awserr.New(ErrCodeSerialization,
				"failed to determine start of request body", err)
			return
		}
	}
	r.ResetBody()
}

// Presign returns the request's signed URL. Error will be returned
// if the signing fails.
func (r *Request) Presign(expireTime time.Duration) (string, error) {
	r.ExpireTime = expireTime
	r.NotHoist = false

	if r.Operation.BeforePresignFn != nil {
		r = r.copy()
		err := r.Operation.BeforePresignFn(r)
		if err != nil {
			return "", err
		}
	}

	r.Sign()
	if r.Error != nil {
		return "", r.Error
	}
	return r.HTTPRequest.URL.String(), nil
}

// PresignRequest behaves just like presign, with the addition of returning a
// set of headers that were signed.
//
// Returns the URL string for the API operation with signature in the query string,
// and the HTTP headers that were included in the signature. These headers must
// be included in any HTTP request made with the presigned URL.
//
// To prevent hoisting any headers to the query string set NotHoist to true on
// this Request value prior to calling PresignRequest.
func (r *Request) PresignRequest(expireTime time.Duration) (string, http.Header, error) {
	r.ExpireTime = expireTime
	r.Sign()
	if r.Error != nil {
		return "", nil, r.Error
	}
	return r.HTTPRequest.URL.String(), r.SignedHeaderVals, nil
}

const (
	notRetrying = "not retrying"
)

func debugLogReqError(r *Request, stage string, retryStr string, err error) {
	if !r.Config.LogLevel.Matches(LogDebugWithRequestErrors) {
		return
	}

	r.Config.Logger.Log(fmt.Sprintf("DEBUG: %s %s/%s failed, %s, error %v",
		stage, r.Metadata.ServiceName, r.Operation.Name, retryStr, err))
}

// Build will build the request's object so it can be signed and sent
// to the service. Build will also validate all the request's parameters.
// Anny additional build Handlers set on this request will be run
// in the order they were set.
//
// The request will only be built once. Multiple calls to build will have
// no effect.
//
// If any Validate or Build errors occur the build will stop and the error
// which occurred will be returned.
func (r *Request) Build() error {
	if !r.built {
		r.Handlers.Validate.Run(r)
		if r.Error != nil {
			debugLogReqError(r, "Validate Request", notRetrying, r.Error)
			return r.Error
		}
		r.Handlers.Build.Run(r)
		if r.Error != nil {
			debugLogReqError(r, "Build Request", notRetrying, r.Error)
			return r.Error
		}
		r.built = true
	}

	return r.Error
}

// Sign will sign the request returning error if errors are encountered.
//
// Send will build the request prior to signing. All Sign Handlers will
// be executed in the order they were set.
func (r *Request) Sign() error {
	r.Build()
	if r.Error != nil {
		debugLogReqError(r, "Build Request", notRetrying, r.Error)
		return r.Error
	}

	r.Handlers.Sign.Run(r)
	return r.Error
}

func (r *Request) getNextRequestBody() (body io.ReadCloser, err error) {
	if r.safeBody != nil {
		r.safeBody.Close()
	}

	r.safeBody, err = newOffsetReader(r.Body, r.BodyStart)
	if err != nil {
		return nil, awserr.New(ErrCodeSerialization,
			"failed to get request body error", err)
	}

	// Go 1.8 tightened and clarified the rules code needs to use when building
	// requests with the http package. Go 1.8 removed the automatic detection
	// of if the Request.Body was empty, or actually had bytes in it. The SDK
	// always sets the Request.Body even if it is empty and should not actually
	// be sent. This is incorrect.
	//
	// Go 1.8 did add a http.NoBody value that the SDK can use to tell the http
	// client that the request really should be sent without a body. The
	// Request.Body cannot be set to nil, which is preferable, because the
	// field is exported and could introduce nil pointer dereferences for users
	// of the SDK if they used that field.
	//
	// Related golang/go#18257
	l, err := SeekerLen(r.Body)
	if err != nil {
		return nil, awserr.New(ErrCodeSerialization,
			"failed to compute request body size", err)
	}

	if l == 0 {
		body = http.NoBody
	} else if l > 0 {
		body = r.safeBody
	} else {
		// Hack to prevent sending bodies for methods where the body
		// should be ignored by the server. Sending bodies on these
		// methods without an associated ContentLength will cause the
		// request to socket timeout because the server does not handle
		// Transfer-Encoding: chunked bodies for these methods.
		//
		// This would only happen if a ReaderSeekerCloser was used with
		// a io.Reader that was not also an io.Seeker, or did not
		// implement Len() method.
		switch r.Operation.HTTPMethod {
		case "GET", "HEAD", "DELETE":
			body = http.NoBody
		default:
			body = r.safeBody
		}
	}

	return body, nil
}

// GetBody will return an io.ReadSeeker of the Request's underlying
// input body with a concurrency safe wrapper.
func (r *Request) GetBody() io.ReadSeeker {
	return r.safeBody
}

// Send will send the request returning error if errors are encountered.
//
// Send will sign the request prior to sending. All Send Handlers will
// be executed in the order they were set.
//
// Canceling a request is non-deterministic. If a request has been canceled,
// then the transport will choose, randomly, one of the state channels during
// reads or getting the connection.
//
// readLoop() and getConn(req *Request, cm connectMethod)
// https://github.com/golang/go/blob/master/src/net/http/transport.go
//
// Send will not close the request.Request's body.
func (r *Request) Send() error {
	defer func() {
		// Regardless of success or failure of the request trigger the Complete
		// request handlers.
		r.Handlers.Complete.Run(r)
	}()

	if err := r.Error; err != nil {
		return err
	}

	// TODO (jasdel), Issue #74 - Refactoring request error handling needs to
	// consider the difference between API, connection, and SDK behavior
	// errors. This consideration must include wrapping of underlying error
	// when any SDK error occurs.

	relRetryToken := r.Retryer.GetInitialToken()
	for {
		r.Error = nil
		r.RetryDelay = 0
		r.ShouldRetry = false
		r.AttemptTime = sdk.NowTime()
		r.AttemptNum++

		var err error
		if err = r.Sign(); err != nil {
			debugLogReqError(r, "Sign Request", notRetrying, err)
			r.Error = err
			return err
		}

		reqErr := r.sendRequest()
		relRetryToken(reqErr)
		if reqErr == nil {
			return nil
		}
		debugLogReqError(r, "Send Request",
			fmtAttemptCount(r.AttemptNum, r.Retryer.MaxAttempts()),
			reqErr)

		if !r.ShouldRetry {
			return r.Error
		}

		relRetryToken, err = r.Retryer.GetRetryToken(r.Context(), reqErr)
		if err != nil {
			r.Error = err
			return err
		}

		if err = sdk.SleepWithContext(r.Context(), r.RetryDelay); err != nil {
			r.Error = &RequestCanceledError{Err: err}
			return r.Error
		}

		r.Error = nil
		if err = r.prepareRetry(); err != nil {
			r.Error = err
			return err
		}

		r.RetryCount++
	}
}

func (r *Request) prepareRetry() error {
	if r.Config.LogLevel.Matches(LogDebugWithRequestRetries) {
		r.Config.Logger.Log(fmt.Sprintf("DEBUG: Retrying Request %s/%s, attempt %d",
			r.Metadata.ServiceName, r.Operation.Name, r.RetryCount))
	}

	// The previous http.Request will have a reference to the r.Body
	// and the HTTP Client's Transport may still be reading from
	// the request's body even though the Client's Do returned.
	r.HTTPRequest = copyHTTPRequest(r.HTTPRequest, nil)
	r.ResetBody()
	if err := r.Error; err != nil {
		return awserr.New(ErrCodeSerialization,
			"failed to prepare body for retry", err)

	}

	// Closing response body to ensure that no response body is leaked
	// between retry attempts.
	if r.HTTPResponse != nil && r.HTTPResponse.Body != nil {
		r.HTTPResponse.Body.Close()
	}

	return nil
}

func (r *Request) sendRequest() (sendErr error) {
	defer r.Handlers.CompleteAttempt.Run(r)
	defer func() {
		if r.Error != nil {
			r.Handlers.ShouldRetry.Run(r)
		}
	}()

	r.Handlers.Send.Run(r)
	if r.Error != nil {
		return r.Error
	}

	r.Handlers.UnmarshalMeta.Run(r)
	r.Handlers.ValidateResponse.Run(r)
	if r.Error != nil {
		r.Handlers.UnmarshalError.Run(r)
		return r.Error
	}

	r.Handlers.Unmarshal.Run(r)
	if r.Error != nil {
		return r.Error
	}

	return nil
}

// copy will copy a request which will allow for local manipulation of the
// request.
func (r *Request) copy() *Request {
	req := &Request{}
	*req = *r
	req.Handlers = r.Handlers.Copy()
	op := *r.Operation
	req.Operation = &op
	return req
}

// AddToUserAgent adds the string to the end of the request's current user agent.
func AddToUserAgent(r *Request, s string) {
	curUA := r.HTTPRequest.Header.Get("User-Agent")
	if len(curUA) > 0 {
		s = curUA + " " + s
	}
	r.HTTPRequest.Header.Set("User-Agent", s)
}

// SanitizeHostForHeader removes default port from host and updates request.Host
func SanitizeHostForHeader(r *http.Request) {
	host := getHost(r)
	port := portOnly(host)
	if port != "" && isDefaultPort(r.URL.Scheme, port) {
		r.Host = stripPort(host)
	}
}

// Returns host from request
func getHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}

	return r.URL.Host
}

// Hostname returns u.Host, without any port number.
//
// If Host is an IPv6 literal with a port number, Hostname returns the
// IPv6 literal without the square brackets. IPv6 literals may include
// a zone identifier.
//
// Copied from the Go 1.8 standard library (net/url)
func stripPort(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return hostport
	}
	if i := strings.IndexByte(hostport, ']'); i != -1 {
		return strings.TrimPrefix(hostport[:i], "[")
	}
	return hostport[:colon]
}

// Port returns the port part of u.Host, without the leading colon.
// If u.Host doesn't contain a port, Port returns an empty string.
//
// Copied from the Go 1.8 standard library (net/url)
func portOnly(hostport string) string {
	colon := strings.IndexByte(hostport, ':')
	if colon == -1 {
		return ""
	}
	if i := strings.Index(hostport, "]:"); i != -1 {
		return hostport[i+len("]:"):]
	}
	if strings.Contains(hostport, "]") {
		return ""
	}
	return hostport[colon+len(":"):]
}

// Returns true if the specified URI is using the standard port
// (i.e. port 80 for HTTP URIs or 443 for HTTPS URIs)
func isDefaultPort(scheme, port string) bool {
	if port == "" {
		return true
	}

	lowerCaseScheme := strings.ToLower(scheme)
	if (lowerCaseScheme == "http" && port == "80") || (lowerCaseScheme == "https" && port == "443") {
		return true
	}

	return false
}

// ResetBody rewinds the request body back to its starting position, and
// set's the HTTP Request body reference. When the body is read prior
// to being sent in the HTTP request it will need to be rewound.
//
// ResetBody will automatically be called by the SDK's build handler, but if
// the request is being used directly ResetBody must be called before the request
// is Sent.  SetStringBody, SetBufferBody, and SetReaderBody will automatically
// call ResetBody.
//
func (r *Request) ResetBody() {
	body, err := r.getNextRequestBody()
	if err != nil {
		r.Error = awserr.New(ErrCodeSerialization,
			"failed to reset request body", err)
		return
	}

	r.HTTPRequest.Body = body
	r.HTTPRequest.GetBody = r.getNextRequestBody
}

// SetEndpoint updates the request to use the provided endpoint
func (r *Request) SetEndpoint(endpoint Endpoint) {
	var err error

	if len(endpoint.SigningRegion) == 0 {
		endpoint.SigningRegion = r.Metadata.SigningRegion
	}

	if len(endpoint.SigningName) == 0 || (len(endpoint.SigningName) > 0 && endpoint.SigningNameDerived) {
		endpoint.SigningName = r.Metadata.SigningName
	}

	r.Endpoint = endpoint

	r.HTTPRequest.URL, err = url.Parse(endpoint.URL + r.Operation.HTTPPath)

	if err != nil {
		r.HTTPRequest.URL = &url.URL{}
		r.Error = awserr.New("InvalidEndpointURL", "invalid endpoint uri", err)
	}
}
