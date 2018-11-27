package aws

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/awserr"
)

const (
	// ErrCodeSerialization is the serialization error code that is received
	// during protocol unmarshaling.
	ErrCodeSerialization = "SerializationError"

	// ErrCodeRead is an error that is returned during HTTP reads.
	ErrCodeRead = "ReadError"

	// ErrCodeResponseTimeout is the connection timeout error that is received
	// during body reads.
	ErrCodeResponseTimeout = "ResponseTimeout"

	// ErrCodeRequestCanceled is the error code that will be returned by an
	// API request that was canceled. Requests given a Context may
	// return this error when canceled.
	ErrCodeRequestCanceled = "RequestCanceled"
)

// A Request is the service request to be made.
type Request struct {
	Config   Config
	Metadata Metadata
	Handlers Handlers

	Retryer
	Time                   time.Time
	ExpireTime             time.Duration
	Operation              *Operation
	HTTPRequest            *http.Request
	HTTPResponse           *http.Response
	Body                   io.ReadSeeker
	BodyStart              int64 // offset from beginning of Body that the request body starts
	Params                 interface{}
	Error                  error
	Data                   interface{}
	RequestID              string
	RetryCount             int
	Retryable              *bool
	RetryDelay             time.Duration
	NotHoist               bool
	SignedHeaderVals       http.Header
	LastSignedAt           time.Time
	DisableFollowRedirects bool

	context Context

	built bool

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
	retryer Retryer, operation *Operation, params interface{}, data interface{}) *Request {

	// TODO improve this experiance for config copy?
	cfg = cfg.Copy()

	method := operation.HTTPMethod
	if method == "" {
		method = "POST"
	}

	httpReq, _ := http.NewRequest(method, "", nil)

	// TODO need better way of handling this error... NewRequest should return error.
	endpoint, err := cfg.EndpointResolver.ResolveEndpoint(metadata.ServiceName, cfg.Region)
	if err == nil {
		// TODO so ugly
		metadata.Endpoint = endpoint.URL
		if len(endpoint.SigningName) > 0 && !endpoint.SigningNameDerived {
			metadata.SigningName = endpoint.SigningName
		}
		if len(endpoint.SigningRegion) > 0 {
			metadata.SigningRegion = endpoint.SigningRegion
		}

		httpReq.URL, err = url.Parse(endpoint.URL + operation.HTTPPath)
		if err != nil {
			httpReq.URL = &url.URL{}
			err = awserr.New("InvalidEndpointURL", "invalid endpoint uri", err)
		}
	}

	r := &Request{
		Config:   cfg,
		Metadata: metadata,
		Handlers: handlers.Copy(),

		Retryer:     retryer,
		Time:        time.Now(),
		ExpireTime:  0,
		Operation:   operation,
		HTTPRequest: httpReq,
		Body:        nil,
		Params:      params,
		Error:       err,
		Data:        data,
	}
	r.SetBufferBody([]byte{})

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
// context BackgroundContext will be returned.
func (r *Request) Context() Context {
	if r.context != nil {
		return r.context
	}
	return BackgroundContext()
}

// SetContext adds a Context to the current request that can be used to cancel
// a in-flight request. The Context value must not be nil, or this method will
// panic.
//
// Unlike http.Request.WithContext, SetContext does not return a copy of the
// Request. It is not safe to use use a single Request value for multiple
// requests. A new Request should be created for each API operation request.
//
// Go 1.6 and below:
// The http.Request's Cancel field will be set to the Done() value of
// the context. This will overwrite the Cancel field's value.
//
// Go 1.7 and above:
// The http.Request.WithContext will be used to set the context on the underlying
// http.Request. This will create a shallow copy of the http.Request. The SDK
// may create sub contexts in the future for nested requests such as retries.
func (r *Request) SetContext(ctx Context) {
	if ctx == nil {
		panic("context cannot be nil")
	}
	setRequestContext(r, ctx)
}

// WillRetry returns if the request's can be retried.
func (r *Request) WillRetry() bool {
	return r.Error != nil && BoolValue(r.Retryable) && r.RetryCount < r.MaxRetries()
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

func debugLogReqError(r *Request, stage string, retrying bool, err error) {
	if !r.Config.LogLevel.Matches(LogDebugWithRequestErrors) {
		return
	}

	retryStr := "not retrying"
	if retrying {
		retryStr = "will retry"
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
			debugLogReqError(r, "Validate Request", false, r.Error)
			return r.Error
		}
		r.Handlers.Build.Run(r)
		if r.Error != nil {
			debugLogReqError(r, "Build Request", false, r.Error)
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
		debugLogReqError(r, "Build Request", false, r.Error)
		return r.Error
	}

	r.Handlers.Sign.Run(r)
	return r.Error
}

func (r *Request) getNextRequestBody() (io.ReadCloser, error) {
	if r.safeBody != nil {
		r.safeBody.Close()
	}

	r.safeBody = newOffsetReader(r.Body, r.BodyStart)

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
	l, err := computeBodyLength(r.Body)
	if err != nil {
		return nil, awserr.New(ErrCodeSerialization, "failed to compute request body size", err)
	}

	var body io.ReadCloser
	if l == 0 {
		body = NoBody
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
		// a io.Reader that was not also an io.Seeker.
		switch r.Operation.HTTPMethod {
		case "GET", "HEAD", "DELETE":
			body = NoBody
		default:
			body = r.safeBody
		}
	}

	return body, nil
}

// Attempts to compute the length of the body of the reader using the
// io.Seeker interface. If the value is not seekable because of being
// a ReaderSeekerCloser without an unerlying Seeker -1 will be returned.
// If no error occurs the length of the body will be returned.
func computeBodyLength(r io.ReadSeeker) (int64, error) {
	seekable := true
	// Determine if the seeker is actually seekable. ReaderSeekerCloser
	// hides the fact that a io.Readers might not actually be seekable.
	switch v := r.(type) {
	case ReaderSeekerCloser:
		seekable = v.IsSeeker()
	case *ReaderSeekerCloser:
		seekable = v.IsSeeker()
	}
	if !seekable {
		return -1, nil
	}

	curOffset, err := r.Seek(0, 1)
	if err != nil {
		return 0, err
	}

	endOffset, err := r.Seek(0, 2)
	if err != nil {
		return 0, err
	}

	_, err = r.Seek(curOffset, 0)
	if err != nil {
		return 0, err
	}

	return endOffset - curOffset, nil
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

	for {
		if BoolValue(r.Retryable) {
			if r.Config.LogLevel.Matches(LogDebugWithRequestRetries) {
				r.Config.Logger.Log(fmt.Sprintf("DEBUG: Retrying Request %s/%s, attempt %d",
					r.Metadata.ServiceName, r.Operation.Name, r.RetryCount))
			}

			// The previous http.Request will have a reference to the r.Body
			// and the HTTP Client's Transport may still be reading from
			// the request's body even though the Client's Do returned.
			r.HTTPRequest = copyHTTPRequest(r.HTTPRequest, nil)
			r.ResetBody()

			// Closing response body to ensure that no response body is leaked
			// between retry attempts.
			if r.HTTPResponse != nil && r.HTTPResponse.Body != nil {
				r.HTTPResponse.Body.Close()
			}
		}

		r.Sign()
		if r.Error != nil {
			return r.Error
		}

		r.Retryable = nil

		r.Handlers.Send.Run(r)
		if r.Error != nil {
			if !shouldRetryCancel(r) {
				return r.Error
			}

			err := r.Error
			r.Handlers.Retry.Run(r)
			r.Handlers.AfterRetry.Run(r)
			if r.Error != nil {
				debugLogReqError(r, "Send Request", false, err)
				return r.Error
			}
			debugLogReqError(r, "Send Request", true, err)
			continue
		}
		r.Handlers.UnmarshalMeta.Run(r)
		r.Handlers.ValidateResponse.Run(r)
		if r.Error != nil {
			r.Handlers.UnmarshalError.Run(r)
			err := r.Error

			r.Handlers.Retry.Run(r)
			r.Handlers.AfterRetry.Run(r)
			if r.Error != nil {
				debugLogReqError(r, "Validate Response", false, err)
				return r.Error
			}
			debugLogReqError(r, "Validate Response", true, err)
			continue
		}

		r.Handlers.Unmarshal.Run(r)
		if r.Error != nil {
			err := r.Error
			r.Handlers.Retry.Run(r)
			r.Handlers.AfterRetry.Run(r)
			if r.Error != nil {
				debugLogReqError(r, "Unmarshal Response", false, err)
				return r.Error
			}
			debugLogReqError(r, "Unmarshal Response", true, err)
			continue
		}

		break
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

func shouldRetryCancel(r *Request) bool {
	awsErr, ok := r.Error.(awserr.Error)
	timeoutErr := false
	errStr := r.Error.Error()
	if ok {
		if awsErr.Code() == ErrCodeRequestCanceled {
			return false
		}
		err := awsErr.OrigErr()
		netErr, netOK := err.(net.Error)
		timeoutErr = netOK && netErr.Temporary()
		if urlErr, ok := err.(*url.Error); !timeoutErr && ok {
			errStr = urlErr.Err.Error()
		}
	}

	// There can be two types of canceled errors here.
	// The first being a net.Error and the other being an error.
	// If the request was timed out, we want to continue the retry
	// process. Otherwise, return the canceled error.
	return timeoutErr ||
		(errStr != "net/http: request canceled" &&
			errStr != "net/http: request canceled while waiting for connection")

}
