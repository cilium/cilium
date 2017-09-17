// Package option contains options for Google API clients.
package option

import (
	"net/http"

	"golang.org/x/oauth2"
	"google.golang.org/api/internal"
	"google.golang.org/grpc"
)

// A ClientOption is an option for a Google API client.
type ClientOption interface {
	Apply(*internal.DialSettings)
}

// WithTokenSource returns a ClientOption that specifies an OAuth2 token
// source to be used as the basis for authentication.
func WithTokenSource(s oauth2.TokenSource) ClientOption {
	return withTokenSource{s}
}

type withTokenSource struct{ ts oauth2.TokenSource }

func (w withTokenSource) Apply(o *internal.DialSettings) {
	o.TokenSource = w.ts
}

// WithServiceAccountFile returns a ClientOption that uses a Google service
// account credentials file to authenticate.
// Use WithTokenSource with a token source created from
// golang.org/x/oauth2/google.JWTConfigFromJSON
// if reading the file from disk is not an option.
func WithServiceAccountFile(filename string) ClientOption {
	return withServiceAccountFile(filename)
}

type withServiceAccountFile string

func (w withServiceAccountFile) Apply(o *internal.DialSettings) {
	o.ServiceAccountJSONFilename = string(w)
}

// WithEndpoint returns a ClientOption that overrides the default endpoint
// to be used for a service.
func WithEndpoint(url string) ClientOption {
	return withEndpoint(url)
}

type withEndpoint string

func (w withEndpoint) Apply(o *internal.DialSettings) {
	o.Endpoint = string(w)
}

// WithScopes returns a ClientOption that overrides the default OAuth2 scopes
// to be used for a service.
func WithScopes(scope ...string) ClientOption {
	return withScopes(scope)
}

type withScopes []string

func (w withScopes) Apply(o *internal.DialSettings) {
	s := make([]string, len(w))
	copy(s, w)
	o.Scopes = s
}

// WithUserAgent returns a ClientOption that sets the User-Agent.
func WithUserAgent(ua string) ClientOption {
	return withUA(ua)
}

type withUA string

func (w withUA) Apply(o *internal.DialSettings) { o.UserAgent = string(w) }

// WithHTTPClient returns a ClientOption that specifies the HTTP client to use
// as the basis of communications. This option may only be used with services
// that support HTTP as their communication transport. When used, the
// WithHTTPClient option takes precedent over all other supplied options.
func WithHTTPClient(client *http.Client) ClientOption {
	return withHTTPClient{client}
}

type withHTTPClient struct{ client *http.Client }

func (w withHTTPClient) Apply(o *internal.DialSettings) {
	o.HTTPClient = w.client
}

// WithGRPCConn returns a ClientOption that specifies the gRPC client
// connection to use as the basis of communications. This option many only be
// used with services that support gRPC as their communication transport. When
// used, the WithGRPCConn option takes precedent over all other supplied
// options.
func WithGRPCConn(conn *grpc.ClientConn) ClientOption {
	return withGRPCConn{conn}
}

type withGRPCConn struct{ conn *grpc.ClientConn }

func (w withGRPCConn) Apply(o *internal.DialSettings) {
	o.GRPCConn = w.conn
}

// WithGRPCDialOption returns a ClientOption that appends a new grpc.DialOption
// to an underlying gRPC dial. It does not work with WithGRPCConn.
func WithGRPCDialOption(opt grpc.DialOption) ClientOption {
	return withGRPCDialOption{opt}
}

type withGRPCDialOption struct{ opt grpc.DialOption }

func (w withGRPCDialOption) Apply(o *internal.DialSettings) {
	o.GRPCDialOpts = append(o.GRPCDialOpts, w.opt)
}

// WithGRPCConnectionPool returns a ClientOption that creates a pool of gRPC
// connections that requests will be balanced between.
// This is an EXPERIMENTAL API and may be changed or removed in the future.
func WithGRPCConnectionPool(size int) ClientOption {
	return withGRPCConnectionPool(size)
}

type withGRPCConnectionPool int

func (w withGRPCConnectionPool) Apply(o *internal.DialSettings) {
	balancer := grpc.RoundRobin(internal.NewPoolResolver(int(w), o))
	o.GRPCDialOpts = append(o.GRPCDialOpts, grpc.WithBalancer(balancer))
}

// WithAPIKey returns a ClientOption that specifies an API key to be used
// as the basis for authentication.
func WithAPIKey(apiKey string) ClientOption {
	return withAPIKey(apiKey)
}

type withAPIKey string

func (w withAPIKey) Apply(o *internal.DialSettings) { o.APIKey = string(w) }
