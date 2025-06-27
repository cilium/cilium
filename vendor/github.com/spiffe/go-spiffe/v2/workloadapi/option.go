package workloadapi

import (
	"github.com/spiffe/go-spiffe/v2/logger"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
)

// ClientOption is an option used when creating a new Client.
type ClientOption interface {
	configureClient(*clientConfig)
}

// WithAddr provides an address for the Workload API. The value of the
// SPIFFE_ENDPOINT_SOCKET environment variable will be used if the option
// is unused.
func WithAddr(addr string) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.address = addr
	})
}

// WithDialOptions provides extra GRPC dialing options when dialing the
// Workload API.
func WithDialOptions(options ...grpc.DialOption) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.dialOptions = append(c.dialOptions, options...)
	})
}

// WithLogger provides a logger to the Client.
func WithLogger(logger logger.Logger) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.log = logger
	})
}

// WithBackoff provides a custom backoff strategy that replaces the
// default backoff strategy (linear backoff).
func WithBackoffStrategy(backoffStrategy BackoffStrategy) ClientOption {
	return clientOption(func(c *clientConfig) {
		c.backoffStrategy = backoffStrategy
	})
}

// SourceOption are options that are shared among all option types.
type SourceOption interface {
	configureX509Source(*x509SourceConfig)
	configureJWTSource(*jwtSourceConfig)
	configureBundleSource(*bundleSourceConfig)
}

// WithClient provides a Client for the source to use. If unset, a new Client
// will be created.
func WithClient(client *Client) SourceOption {
	return withClient{client: client}
}

// WithClientOptions controls the options used to create a new Client for the
// source. This option will be ignored if WithClient is used.
func WithClientOptions(options ...ClientOption) SourceOption {
	return withClientOptions{options: options}
}

// X509SourceOption is an option for the X509Source. A SourceOption is also an
// X509SourceOption.
type X509SourceOption interface {
	configureX509Source(*x509SourceConfig)
}

// WithDefaultJWTSVIDPicker provides a function that is used to determine the
// default JWT-SVID when more than one is provided by the Workload API. By
// default, the first JWT-SVID in the list returned by the Workload API is
// used.
func WithDefaultJWTSVIDPicker(picker func([]*jwtsvid.SVID) *jwtsvid.SVID) JWTSourceOption {
	return withDefaultJWTSVIDPicker{picker: picker}
}

// JWTSourceOption is an option for the JWTSource. A SourceOption is also a
// JWTSourceOption.
type JWTSourceOption interface {
	configureJWTSource(*jwtSourceConfig)
}

// WithDefaultX509SVIDPicker provides a function that is used to determine the
// default X509-SVID when more than one is provided by the Workload API. By
// default, the first X509-SVID in the list returned by the Workload API is
// used.
func WithDefaultX509SVIDPicker(picker func([]*x509svid.SVID) *x509svid.SVID) X509SourceOption {
	return withDefaultX509SVIDPicker{picker: picker}
}

// BundleSourceOption is an option for the BundleSource. A SourceOption is also
// a BundleSourceOption.
type BundleSourceOption interface {
	configureBundleSource(*bundleSourceConfig)
}

type clientConfig struct {
	address         string
	namedPipeName   string
	dialOptions     []grpc.DialOption
	log             logger.Logger
	backoffStrategy BackoffStrategy
}

type clientOption func(*clientConfig)

func (fn clientOption) configureClient(config *clientConfig) {
	fn(config)
}

type x509SourceConfig struct {
	watcher watcherConfig
	picker  func([]*x509svid.SVID) *x509svid.SVID
}

type jwtSourceConfig struct {
	watcher watcherConfig
	picker  func([]*jwtsvid.SVID) *jwtsvid.SVID
}

type bundleSourceConfig struct {
	watcher watcherConfig
}

type withClient struct {
	client *Client
}

func (o withClient) configureX509Source(config *x509SourceConfig) {
	config.watcher.client = o.client
}

func (o withClient) configureJWTSource(config *jwtSourceConfig) {
	config.watcher.client = o.client
}

func (o withClient) configureBundleSource(config *bundleSourceConfig) {
	config.watcher.client = o.client
}

type withClientOptions struct {
	options []ClientOption
}

func (o withClientOptions) configureX509Source(config *x509SourceConfig) {
	config.watcher.clientOptions = o.options
}

func (o withClientOptions) configureJWTSource(config *jwtSourceConfig) {
	config.watcher.clientOptions = o.options
}

func (o withClientOptions) configureBundleSource(config *bundleSourceConfig) {
	config.watcher.clientOptions = o.options
}

type withDefaultX509SVIDPicker struct {
	picker func([]*x509svid.SVID) *x509svid.SVID
}

func (o withDefaultX509SVIDPicker) configureX509Source(config *x509SourceConfig) {
	config.picker = o.picker
}

type withDefaultJWTSVIDPicker struct {
	picker func([]*jwtsvid.SVID) *jwtsvid.SVID
}

func (o withDefaultJWTSVIDPicker) configureJWTSource(config *jwtSourceConfig) {
	config.picker = o.picker
}
