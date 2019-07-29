package aws

import (
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"golang.org/x/net/http2"
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

	initOnce *sync.Once
	client   *http.Client
}

//type withTransportOptions interface {
//	WithTransportOptions(...func(*http.Transport)) HTTPClient
//}
//
//type getTransport interface {
//	GetTransport() *http.Transport
//}
//
//type withDialerOptions interface {
//	WithDialerOptions(...func(*net.Dialer)) HTTPClient
//}
//
//type getDialer interface {
//	GetDialer() *net.Dialer
//}

// NewBuildableHTTPClient returns an initialized client for invoking HTTP
// requests.
func NewBuildableHTTPClient() *BuildableHTTPClient {
	return &BuildableHTTPClient{
		initOnce: new(sync.Once),
	}
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
	b.initOnce.Do(b.initClient)

	return b.client.Do(req)
}

func (b *BuildableHTTPClient) initClient() {
	b.client = b.build()
}

// BuildHTTPClient returns an initialized HTTPClient built from the options of
// the builder.
func (b BuildableHTTPClient) build() *http.Client {
	var tr *http.Transport
	if b.transport != nil {
		tr = shallowCopyStruct(b.transport).(*http.Transport)
	} else {
		tr = defaultHTTPTransport()
	}

	// TODO Any way to ensure HTTP 2 is supported without depending on
	// an unversioned experimental package?
	// Maybe only clients that depend on HTTP/2 should call this?
	http2.ConfigureTransport(tr)

	return wrapWithoutRedirect(&http.Client{
		Transport: tr,
	})
}

func (b BuildableHTTPClient) reset() BuildableHTTPClient {
	b.initOnce = new(sync.Once)
	b.client = nil
	return b
}

// WithTransportOptions copies the BuildableHTTPClient and returns it with the
// http.Transport options applied.
//
// If a non (*http.Transport) was set as the round tripper, the round tripper
// will be replaced with a default Transport value before invoking the option
// functions.
func (b BuildableHTTPClient) WithTransportOptions(opts ...func(*http.Transport)) HTTPClient {
	b = b.reset()

	tr := b.GetTransport()
	for _, opt := range opts {
		opt(tr)
	}
	b.transport = tr

	return &b
}

// WithDialerOptions copies the BuildableHTTPClient and returns it with the
// net.Dialer options applied. Will set the client's http.Transport DialContext
// member.
func (b BuildableHTTPClient) WithDialerOptions(opts ...func(*net.Dialer)) HTTPClient {
	b = b.reset()

	dialer := b.GetDialer()
	for _, opt := range opts {
		opt(dialer)
	}
	b.dialer = dialer

	tr := b.GetTransport()
	tr.DialContext = b.dialer.DialContext
	b.transport = tr

	return &b
}

// GetTransport returns a copy of the client's HTTP Transport.
func (b BuildableHTTPClient) GetTransport() *http.Transport {
	var tr *http.Transport
	if b.transport != nil {
		tr = shallowCopyStruct(b.transport).(*http.Transport)
	} else {
		tr = defaultHTTPTransport()
	}

	return tr
}

// GetDialer returns a copy of the client's network dialer.
func (b BuildableHTTPClient) GetDialer() *net.Dialer {
	var dialer *net.Dialer
	if b.dialer != nil {
		dialer = shallowCopyStruct(b.dialer).(*net.Dialer)
	} else {
		dialer = defaultDialer()
	}

	return dialer
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
