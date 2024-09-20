package probing

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

const (
	defaultHTTPCallFrequency      = time.Second
	defaultHTTPMaxConcurrentCalls = 1
	defaultHTTPMethod             = http.MethodGet
	defaultTimeout                = time.Second * 10
)

type httpCallerOptions struct {
	client *http.Client

	callFrequency      time.Duration
	maxConcurrentCalls int

	host    string
	headers http.Header
	method  string
	body    []byte
	timeout time.Duration

	isValidResponse func(response *http.Response, body []byte) bool

	onDNSStart          func(suite *TraceSuite, info httptrace.DNSStartInfo)
	onDNSDone           func(suite *TraceSuite, info httptrace.DNSDoneInfo)
	onConnStart         func(suite *TraceSuite, network, addr string)
	onConnDone          func(suite *TraceSuite, network, addr string, err error)
	onTLSStart          func(suite *TraceSuite)
	onTLSDone           func(suite *TraceSuite, state tls.ConnectionState, err error)
	onWroteHeaders      func(suite *TraceSuite)
	onFirstByteReceived func(suite *TraceSuite)
	onReq               func(suite *TraceSuite)
	onResp              func(suite *TraceSuite, info *HTTPCallInfo)

	logger Logger
}

// HTTPCallerOption represents a function type for a functional parameter passed to a NewHttpCaller constructor.
type HTTPCallerOption func(options *httpCallerOptions)

// WithHTTPCallerClient is a functional parameter for a HTTPCaller which specifies a http.Client.
func WithHTTPCallerClient(client *http.Client) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.client = client
	}
}

// WithHTTPCallerCallFrequency is a functional parameter for a HTTPCaller which specifies a call frequency.
// If this option is not provided the default one will be used. You can check default value in const
// defaultHTTPCallFrequency.
func WithHTTPCallerCallFrequency(frequency time.Duration) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.callFrequency = frequency
	}
}

// WithHTTPCallerMaxConcurrentCalls is a functional parameter for a HTTPCaller which specifies a number of
// maximum concurrent calls. If this option is not provided the default one will be used. You can check default value in const
// defaultHTTPMaxConcurrentCalls.
func WithHTTPCallerMaxConcurrentCalls(max int) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.maxConcurrentCalls = max
	}
}

// WithHTTPCallerHeaders is a functional parameter for a HTTPCaller which specifies headers that should be
// set in request.
// To override a Host header use a WithHTTPCallerHost method.
func WithHTTPCallerHeaders(headers http.Header) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.headers = headers
	}
}

// WithHTTPCallerMethod is a functional parameter for a HTTPCaller which specifies a method that should be
// set in request. If this option is not provided the default one will be used. You can check default value in const
// defaultHTTPMethod.
func WithHTTPCallerMethod(method string) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.method = method
	}
}

// WithHTTPCallerHost is a functional parameter for a HTTPCaller which allowed to override a host header.
func WithHTTPCallerHost(host string) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.host = host
	}
}

// WithHTTPCallerBody is a functional parameter for a HTTPCaller which specifies a body that should be set
// in request.
func WithHTTPCallerBody(body []byte) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.body = body
	}
}

// WithHTTPCallerTimeout is a functional parameter for a HTTPCaller which specifies request timeout.
// If this option is not provided the default one will be used. You can check default value in const defaultTimeout.
func WithHTTPCallerTimeout(timeout time.Duration) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.timeout = timeout
	}
}

// WithHTTPCallerIsValidResponse is a functional parameter for a HTTPCaller which specifies a function that
// will be used to assess whether a response is valid. If not specified, all responses will be treated as valid.
// You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerIsValidResponse(isValid func(response *http.Response, body []byte) bool) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.isValidResponse = isValid
	}
}

// WithHTTPCallerOnDNSStart is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when dns resolving starts. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnDNSStart(onDNSStart func(suite *TraceSuite, info httptrace.DNSStartInfo)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onDNSStart = onDNSStart
	}
}

// WithHTTPCallerOnDNSDone is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when dns resolving ended. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnDNSDone(onDNSDone func(suite *TraceSuite, info httptrace.DNSDoneInfo)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onDNSDone = onDNSDone
	}
}

// WithHTTPCallerOnConnStart is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when connection establishment started. You can read more explanation about this parameter in HTTPCaller
// annotation.
func WithHTTPCallerOnConnStart(onConnStart func(suite *TraceSuite, network, addr string)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onConnStart = onConnStart
	}
}

// WithHTTPCallerOnConnDone is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when connection establishment finished. You can read more explanation about this parameter in HTTPCaller
// annotation.
func WithHTTPCallerOnConnDone(conConnDone func(suite *TraceSuite, network, addr string, err error)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onConnDone = conConnDone
	}
}

// WithHTTPCallerOnTLSStart is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when tls handshake started. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnTLSStart(onTLSStart func(suite *TraceSuite)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onTLSStart = onTLSStart
	}
}

// WithHTTPCallerOnTLSDone is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when tls handshake ended. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnTLSDone(onTLSDone func(suite *TraceSuite, state tls.ConnectionState, err error)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onTLSDone = onTLSDone
	}
}

// WithHTTPCallerOnWroteRequest is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when request has been written. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnWroteRequest(onWroteRequest func(suite *TraceSuite)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onWroteHeaders = onWroteRequest
	}
}

// WithHTTPCallerOnFirstByteReceived is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when first response byte has been received. You can read more explanation about this parameter in HTTPCaller
// annotation.
func WithHTTPCallerOnFirstByteReceived(onGotFirstByte func(suite *TraceSuite)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onFirstByteReceived = onGotFirstByte
	}
}

// WithHTTPCallerOnReq is a functional parameter for a HTTPCaller which specifies a callback that will be
// called before the start of the http call execution. You can read more explanation about this parameter in HTTPCaller
// annotation.
func WithHTTPCallerOnReq(onReq func(suite *TraceSuite)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onReq = onReq
	}
}

// WithHTTPCallerOnResp is a functional parameter for a HTTPCaller which specifies a callback that will be
// called when response is received. You can read more explanation about this parameter in HTTPCaller annotation.
func WithHTTPCallerOnResp(onResp func(suite *TraceSuite, info *HTTPCallInfo)) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.onResp = onResp
	}
}

// WithHTTPCallerLogger is a functional parameter for a HTTPCaller which specifies a logger.
// If not specified, logs will be omitted.
func WithHTTPCallerLogger(logger Logger) HTTPCallerOption {
	return func(options *httpCallerOptions) {
		options.logger = logger
	}
}

// NewHttpCaller returns a new HTTPCaller. URL parameter is the only required one, other options might be specified via
// functional parameters, otherwise default values will be used where applicable.
func NewHttpCaller(url string, options ...HTTPCallerOption) *HTTPCaller {
	opts := httpCallerOptions{
		callFrequency:      defaultHTTPCallFrequency,
		maxConcurrentCalls: defaultHTTPMaxConcurrentCalls,
		method:             defaultHTTPMethod,
		timeout:            defaultTimeout,
		client:             &http.Client{},
	}
	for _, opt := range options {
		opt(&opts)
	}

	return &HTTPCaller{
		client: opts.client,

		callFrequency:      opts.callFrequency,
		maxConcurrentCalls: opts.maxConcurrentCalls,

		url:     url,
		host:    opts.host,
		headers: opts.headers,
		method:  opts.method,
		body:    opts.body,
		timeout: opts.timeout,

		isValidResponse: opts.isValidResponse,

		workChan: make(chan struct{}, opts.maxConcurrentCalls),
		doneChan: make(chan struct{}),

		onDNSStart:          opts.onDNSStart,
		onDNSDone:           opts.onDNSDone,
		onConnStart:         opts.onConnStart,
		onConnDone:          opts.onConnDone,
		onTLSStart:          opts.onTLSStart,
		onTLSDone:           opts.onTLSDone,
		onWroteHeaders:      opts.onWroteHeaders,
		onFirstByteReceived: opts.onFirstByteReceived,
		onReq:               opts.onReq,
		onResp:              opts.onResp,

		logger: opts.logger,
	}
}

// HTTPCaller represents a prober performing http calls and collecting relevant statistics.
type HTTPCaller struct {
	client *http.Client

	// callFrequency is a parameter which specifies how often to send a new request. You might need to increase
	// maxConcurrentCalls value to achieve required value.
	callFrequency time.Duration

	// maxConcurrentCalls is a maximum number of calls that might be performed concurrently. In other words,
	// a number of "workers" that will try to perform probing concurrently.
	// Default number is specified in defaultHTTPMaxConcurrentCalls
	maxConcurrentCalls int

	// url is an url which will be used in all probe requests, mandatory in constructor.
	url string

	// host allows to override a Host header
	host string

	// headers are headers that which will be used in all probe requests, default are none.
	headers http.Header

	// method is a http request method which will be used in all probe requests,
	// default is specified in defaultHTTPMethod
	method string

	// body is a http request body which will be used in all probe requests, default is none.
	body []byte

	// timeout is a http call timeout, default is specified in defaultTimeout.
	timeout time.Duration

	// isValidResponse is a function that will be used to validate whether a response is valid up to clients choice.
	// You can think of it as a verification that response contains data that you expected. This information will be
	// passed back in HTTPCallInfo during an onResp callback and HTTPStatistics during an onFinish callback
	// or a Statistics call.
	isValidResponse func(response *http.Response, body []byte) bool

	workChan chan struct{}
	doneChan chan struct{}
	doneWg   sync.WaitGroup

	// All callbacks except onReq and onResp are based on a httptrace callbacks, meaning they are called at the time
	// and contain signature same as you would expect in httptrace library. In addition to that each callback has a
	// TraceSuite as a first argument, which will help you to propagate data between these callbacks. You can read more
	// about it in TraceSuite annotation.

	// onDNSStart is a callback which is called when a dns lookup starts. It's based on a httptrace.DNSStart callback.
	onDNSStart func(suite *TraceSuite, info httptrace.DNSStartInfo)
	// onDNSDone is a callback which is called when a dns lookup ends. It's based on a httptrace.DNSDone callback.
	onDNSDone func(suite *TraceSuite, info httptrace.DNSDoneInfo)
	// onConnStart is a callback which is called when a connection dial starts. It's based on a httptrace.ConnectStart
	// callback.
	onConnStart func(suite *TraceSuite, network, addr string)
	// onConnDone is a callback which is called when a connection dial ends. It's based on a httptrace.ConnectDone
	// callback.
	onConnDone func(suite *TraceSuite, network, addr string, err error)
	// onTLSStart is a callback which is called when a tls handshake starts. It's based on a httptrace.TLSHandshakeStart
	// callback.
	onTLSStart func(suite *TraceSuite)
	// onTLSDone is a callback which is called when a tls handshake ends. It's based on a httptrace.TLSHandshakeDone
	// callback.
	onTLSDone func(suite *TraceSuite, state tls.ConnectionState, err error)
	// onWroteHeaders is a callback which is called when request headers where written. It's based on a
	// httptrace.WroteHeaders callback.
	onWroteHeaders func(suite *TraceSuite)
	// onFirstByteReceived is a callback which is called when first response bytes were received. It's based on a
	// httptrace.GotFirstResponseByte callback.
	onFirstByteReceived func(suite *TraceSuite)

	// onReq is a custom callback which is called before http client starts request execution.
	onReq func(suite *TraceSuite)
	// onResp is a custom callback which is called when a response is received.
	onResp func(suite *TraceSuite, info *HTTPCallInfo)

	// logger is a logger implementation, default is none.
	logger Logger
}

// Stop gracefully stops the execution of a HTTPCaller.
func (c *HTTPCaller) Stop() {
	close(c.doneChan)
	c.doneWg.Wait()
}

// Run starts execution of a probing.
func (c *HTTPCaller) Run() {
	c.run(context.Background())
}

// RunWithContext starts execution of a probing and allows providing a context.
func (c *HTTPCaller) RunWithContext(ctx context.Context) {
	c.run(ctx)
}

func (c *HTTPCaller) run(ctx context.Context) {
	c.runWorkScheduler(ctx)
	c.runCallers(ctx)
	c.doneWg.Wait()
}

func (c *HTTPCaller) runWorkScheduler(ctx context.Context) {
	c.doneWg.Add(1)
	go func() {
		defer c.doneWg.Done()

		ticker := time.NewTicker(c.callFrequency)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.workChan <- struct{}{}
			case <-ctx.Done():
				return
			case <-c.doneChan:
				return
			}
		}
	}()
}

func (c *HTTPCaller) runCallers(ctx context.Context) {
	for i := 0; i < c.maxConcurrentCalls; i++ {
		c.doneWg.Add(1)
		go func() {
			defer c.doneWg.Done()
			for {
				logger := c.logger
				if logger == nil {
					logger = NoopLogger{}
				}
				select {
				case <-c.workChan:
					if err := c.makeCall(ctx); err != nil {
						logger.Errorf("failed making a call: %v", err)
					}
				case <-ctx.Done():
					return
				case <-c.doneChan:
					return
				}
			}
		}()
	}
}

// TraceSuite is a struct that is passed to each callback. It contains a bunch of time helpers, that you can use with
// a corresponding getter. These timers are set before making a corresponding callback, meaning that when an onDNSStart
// callback will be called - TraceSuite will already have filled dnsStart field. In addition to that, it contains
// an Extra field of type any which you can use in any custom way you might need. Before each callback call, mutex
// is used, meaning all operations inside your callback are concurrent-safe.
// Keep in mind, that if your http client set up to follow redirects - timers will be overwritten.
type TraceSuite struct {
	mu sync.Mutex

	generalStart      time.Time
	generalEnd        time.Time
	dnsStart          time.Time
	dnsEnd            time.Time
	connStart         time.Time
	connEnd           time.Time
	tlsStart          time.Time
	tlsEnd            time.Time
	wroteHeaders      time.Time
	firstByteReceived time.Time

	Extra any
}

// GetGeneralStart returns a general http request execution start time.
func (s *TraceSuite) GetGeneralStart() time.Time {
	return s.generalStart
}

// GetGeneralEnd returns a general http response time.
func (s *TraceSuite) GetGeneralEnd() time.Time {
	return s.generalEnd
}

// GetDNSStart returns a time of a dns lookup start.
func (s *TraceSuite) GetDNSStart() time.Time {
	return s.dnsStart
}

// GetDNSEnd returns a time of a dns lookup send.
func (s *TraceSuite) GetDNSEnd() time.Time {
	return s.dnsEnd
}

// GetConnStart returns a time of a connection dial start.
func (s *TraceSuite) GetConnStart() time.Time {
	return s.connStart
}

// GetConnEnd returns a time of a connection dial end.
func (s *TraceSuite) GetConnEnd() time.Time {
	return s.connEnd
}

// GetTLSStart returns a time of a tls handshake start.
func (s *TraceSuite) GetTLSStart() time.Time {
	return s.tlsStart
}

// GetTLSEnd returns a time of a tls handshake end.
func (s *TraceSuite) GetTLSEnd() time.Time {
	return s.tlsEnd
}

// GetWroteHeaders returns a time when request headers were written.
func (s *TraceSuite) GetWroteHeaders() time.Time {
	return s.wroteHeaders
}

// GetFirstByteReceived returns a time when first response bytes were received.
func (s *TraceSuite) GetFirstByteReceived() time.Time {
	return s.firstByteReceived
}

func (c *HTTPCaller) getClientTrace(suite *TraceSuite) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.dnsStart = time.Now()
			if c.onDNSStart != nil {
				c.onDNSStart(suite, info)
			}
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.dnsEnd = time.Now()
			if c.onDNSDone != nil {
				c.onDNSDone(suite, info)
			}
		},
		ConnectStart: func(network, addr string) {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.connStart = time.Now()
			if c.onConnStart != nil {
				c.onConnStart(suite, network, addr)
			}
		},
		ConnectDone: func(network, addr string, err error) {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.connEnd = time.Now()
			if c.onConnDone != nil {
				c.onConnDone(suite, network, addr, err)
			}
		},
		TLSHandshakeStart: func() {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.tlsStart = time.Now()
			if c.onTLSStart != nil {
				c.onTLSStart(suite)
			}
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.tlsEnd = time.Now()
			if c.onTLSDone != nil {
				c.onTLSDone(suite, state, err)
			}
		},
		WroteHeaders: func() {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.wroteHeaders = time.Now()
			if c.onWroteHeaders != nil {
				c.onWroteHeaders(suite)
			}
		},
		GotFirstResponseByte: func() {
			suite.mu.Lock()
			defer suite.mu.Unlock()

			suite.firstByteReceived = time.Now()
			if c.onFirstByteReceived != nil {
				c.onFirstByteReceived(suite)
			}
		},
	}
}

func (c *HTTPCaller) makeCall(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	suite := TraceSuite{
		generalStart: time.Now(),
	}
	traceCtx := httptrace.WithClientTrace(ctx, c.getClientTrace(&suite))
	req, err := http.NewRequestWithContext(traceCtx, c.method, c.url, bytes.NewReader(c.body))
	if err != nil {
		return err
	}
	req.Header = c.headers
	if c.host != "" {
		req.Host = c.host
	}

	if c.onReq != nil {
		suite.mu.Lock()
		c.onReq(&suite)
		suite.mu.Unlock()
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	isValidResponse := true
	if c.isValidResponse != nil {
		isValidResponse = c.isValidResponse(resp, body)
	}
	if c.onResp != nil {
		suite.mu.Lock()
		defer suite.mu.Unlock()

		suite.generalEnd = time.Now()
		c.onResp(&suite, &HTTPCallInfo{
			StatusCode:      resp.StatusCode,
			IsValidResponse: isValidResponse,
		})
	}
	return nil
}

// HTTPCallInfo represents a data set which passed as a function argument to an onResp callback.
type HTTPCallInfo struct {
	// StatusCode is a response status code
	StatusCode int

	// IsValidResponse represents a fact of whether a response is treated as valid. You can read more about it in
	// HTTPCaller annotation.
	IsValidResponse bool
}
