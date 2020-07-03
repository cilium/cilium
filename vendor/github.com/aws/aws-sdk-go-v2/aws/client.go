package aws

import (
	"net/http"
)

// Metadata wraps immutable data from the Client structure.
type Metadata struct {
	ServiceName string
	ServiceID   string
	EndpointsID string
	APIVersion  string

	SigningName   string
	SigningRegion string

	JSONVersion  string
	TargetPrefix string
}

// A Client implements the base client request and response handling
// used by all service clients.
type Client struct {
	Metadata         Metadata
	Config           Config
	Credentials      CredentialsProvider
	EndpointResolver EndpointResolver
	Handlers         Handlers
	Retryer          Retryer
	LogLevel         LogLevel
	Logger           Logger
	HTTPClient       HTTPClient
}

// NewClient will return a pointer to a new initialized service client.
func NewClient(cfg Config, metadata Metadata) *Client {
	svc := &Client{
		Metadata: metadata,

		// TODO remove config when request refactored
		Config: cfg,

		Credentials:      cfg.Credentials,
		EndpointResolver: cfg.EndpointResolver,
		Handlers:         cfg.Handlers.Copy(),
		Retryer:          cfg.Retryer,

		LogLevel: cfg.LogLevel,
		Logger:   cfg.Logger,
	}

	if c, ok := svc.Config.HTTPClient.(*http.Client); ok {
		svc.Config.HTTPClient = wrapWithoutRedirect(c)
	}

	svc.AddDebugHandlers()
	return svc
}

// NewRequest returns a new Request pointer for the service API
// operation and parameters.
func (c *Client) NewRequest(operation *Operation, params interface{}, data interface{}) *Request {
	return New(c.Config, c.Metadata, c.Handlers, c.Retryer, operation, params, data)
}

// AddDebugHandlers injects debug logging handlers into the service to log request
// debug information.
func (c *Client) AddDebugHandlers() {
	if !c.Config.LogLevel.AtLeast(LogDebug) {
		return
	}

	c.Handlers.Send.PushFrontNamed(NamedHandler{Name: "awssdk.client.LogRequest", Fn: logRequest})
	c.Handlers.Send.PushBackNamed(NamedHandler{Name: "awssdk.client.LogResponse", Fn: logResponse})
}

func wrapWithoutRedirect(c *http.Client) *http.Client {
	tr := c.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}

	cc := *c
	cc.CheckRedirect = limitedRedirect
	cc.Transport = stubBadHTTPRedirectTransport{
		tr: tr,
	}

	return &cc
}

func limitedRedirect(r *http.Request, via []*http.Request) error {
	// Request.Response, in CheckRedirect is the response that is triggering
	// the redirect.
	resp := r.Response
	if r.URL.String() == stubBadHTTPRedirectLocation {
		resp.Header.Del(stubBadHTTPRedirectLocation)
		return http.ErrUseLastResponse
	}

	switch resp.StatusCode {
	case 307, 308:
		// Only allow 307 and 308 redirects as they preserve the method.
		return nil
	}

	return http.ErrUseLastResponse
}

type stubBadHTTPRedirectTransport struct {
	tr http.RoundTripper
}

const stubBadHTTPRedirectLocation = `https://amazonaws.com/badhttpredirectlocation`

func (t stubBadHTTPRedirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.tr.RoundTrip(r)
	if err != nil {
		return resp, err
	}

	// TODO S3 is the only known service to return 301 without location header.
	// consider moving this to a S3 customization.
	switch resp.StatusCode {
	case 301, 302:
		if v := resp.Header.Get("Location"); len(v) == 0 {
			resp.Header.Set("Location", stubBadHTTPRedirectLocation)
		}
	}

	return resp, err
}
