package aws

import (
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// Defaults for the HTTPTransportBuilder.
var (
	DefaultHTTPTransportMaxIdleConns        = 100
	DefaultHTTPTransportMaxIdleConnsPerHost = 10

	DefaultHTTPTransportIdleConnTimeout       = 90 * time.Second
	DefaultHTTPTransportTLSHandleshakeTimeout = 10 * time.Second
	DefaultHTTPTransportExpectContinueTimeout = 1 * time.Second
)

// Timeouts for net.Dialer's network connection.
var (
	DefaultDialConnectTimeout   = 30 * time.Second
	DefaultDialKeepAliveTimeout = 30 * time.Second
)

// HTTPClient provides the interface to provide custom HTTPClients. Generally
// *http.Client is sufficient for most use cases. The HTTPClient should not
// follow redirects.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// BuildableHTTPClient provides a HTTPClient implementation with options to
// create copies of the HTTPClient when additional configuration is provided.
//
// The client's methods will not share the http.Transport value between copies
// of the BuildableHTTPClient. Only exported member values of the Transport and
// optional Dialer will be copied between copies of BuildableHTTPClient.
type BuildableHTTPClient struct {
	transport *http.Transport
	dialer    *net.Dialer

	initOnce sync.Once

	clientTimeout time.Duration
	client        *http.Client
}

// NewBuildableHTTPClient returns an initialized client for invoking HTTP
// requests.
func NewBuildableHTTPClient() *BuildableHTTPClient {
	return &BuildableHTTPClient{}
}

// Do implements the HTTPClient interface's Do method to invoke a HTTP request,
// and receive the response. Uses the BuildableHTTPClient's current
// configuration to invoke the http.Request.
//
// If connection pooling is enabled (aka HTTP KeepAlive) the client will only
// share pooled connections with its own instance. Copies of the
// BuildableHTTPClient will have their own connection pools.
//
// Redirect (3xx) responses will not be followed, the HTTP response received
// will returned instead.
func (b *BuildableHTTPClient) Do(req *http.Request) (*http.Response, error) {
	b.initOnce.Do(b.build)

	return b.client.Do(req)
}

func (b *BuildableHTTPClient) build() {
	b.client = wrapWithoutRedirect(&http.Client{
		Timeout:   b.clientTimeout,
		Transport: b.GetTransport(),
	})
}

func (b *BuildableHTTPClient) clone() *BuildableHTTPClient {
	cpy := NewBuildableHTTPClient()
	cpy.transport = b.GetTransport()
	cpy.dialer = b.GetDialer()
	cpy.clientTimeout = b.clientTimeout

	return cpy
}

// WithTransportOptions copies the BuildableHTTPClient and returns it with the
// http.Transport options applied.
//
// If a non (*http.Transport) was set as the round tripper, the round tripper
// will be replaced with a default Transport value before invoking the option
// functions.
func (b *BuildableHTTPClient) WithTransportOptions(opts ...func(*http.Transport)) HTTPClient {
	cpy := b.clone()

	tr := cpy.GetTransport()
	for _, opt := range opts {
		opt(tr)
	}
	cpy.transport = tr

	return cpy
}

// WithDialerOptions copies the BuildableHTTPClient and returns it with the
// net.Dialer options applied. Will set the client's http.Transport DialContext
// member.
func (b *BuildableHTTPClient) WithDialerOptions(opts ...func(*net.Dialer)) HTTPClient {
	cpy := b.clone()

	dialer := cpy.GetDialer()
	for _, opt := range opts {
		opt(dialer)
	}
	cpy.dialer = dialer

	tr := cpy.GetTransport()
	tr.DialContext = cpy.dialer.DialContext
	cpy.transport = tr

	return cpy
}

// WithTimeout Sets the timeout used by the client for all requests.
func (b *BuildableHTTPClient) WithTimeout(timeout time.Duration) HTTPClient {
	cpy := b.clone()
	cpy.clientTimeout = timeout
	return cpy
}

// GetTransport returns a copy of the client's HTTP Transport.
func (b *BuildableHTTPClient) GetTransport() *http.Transport {
	var tr *http.Transport
	if b.transport != nil {
		tr = b.transport.Clone()
	} else {
		tr = defaultHTTPTransport()
	}

	return tr
}

// GetDialer returns a copy of the client's network dialer.
func (b *BuildableHTTPClient) GetDialer() *net.Dialer {
	var dialer *net.Dialer
	if b.dialer != nil {
		dialer = shallowCopyStruct(b.dialer).(*net.Dialer)
	} else {
		dialer = defaultDialer()
	}

	return dialer
}

// GetTimeout returns a copy of the client's timeout to cancel requests with.
func (b *BuildableHTTPClient) GetTimeout() time.Duration {
	return b.clientTimeout
}

func defaultDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   DefaultDialConnectTimeout,
		KeepAlive: DefaultDialKeepAliveTimeout,
		DualStack: true,
	}
}

func defaultHTTPTransport() *http.Transport {
	dialer := defaultDialer()

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   DefaultHTTPTransportTLSHandleshakeTimeout,
		MaxIdleConns:          DefaultHTTPTransportMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultHTTPTransportMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultHTTPTransportIdleConnTimeout,
		ExpectContinueTimeout: DefaultHTTPTransportExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
	}

	return tr
}

// shallowCopyStruct creates a shallow copy of the passed in source struct, and
// returns that copy of the same struct type.
func shallowCopyStruct(src interface{}) interface{} {
	srcVal := reflect.ValueOf(src)
	srcValType := srcVal.Type()

	var returnAsPtr bool
	if srcValType.Kind() == reflect.Ptr {
		srcVal = srcVal.Elem()
		srcValType = srcValType.Elem()
		returnAsPtr = true
	}
	dstVal := reflect.New(srcValType).Elem()

	for i := 0; i < srcValType.NumField(); i++ {
		ft := srcValType.Field(i)
		if len(ft.PkgPath) != 0 {
			// unexported fields have a PkgPath
			continue
		}

		dstVal.Field(i).Set(srcVal.Field(i))
	}

	if returnAsPtr {
		dstVal = dstVal.Addr()
	}

	return dstVal.Interface()
}
