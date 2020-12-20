package aws

import (
	"net/http"

	"github.com/awslabs/smithy-go/logging"
	"github.com/awslabs/smithy-go/middleware"
)

// HTTPClient provides the interface to provide custom HTTPClients. Generally
// *http.Client is sufficient for most use cases. The HTTPClient should not
// follow redirects.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// A Config provides service configuration for service clients.
type Config struct {
	// The region to send requests to. This parameter is required and must
	// be configured globally or on a per-client basis unless otherwise
	// noted. A full list of regions is found in the "Regions and Endpoints"
	// document.
	//
	// See http://docs.aws.amazon.com/general/latest/gr/rande.html for
	// information on AWS regions.
	Region string

	// The credentials object to use when signing requests. Defaults to a
	// chain of credential providers to search for credentials in environment
	// variables, shared credential file, and EC2 Instance Roles.
	Credentials CredentialsProvider

	// The HTTP Client the SDK's API clients will use to invoke HTTP requests.
	// The SDK defaults to a BuildableClient allowing API clients to create
	// copies of the HTTP Client for service specific customizations.
	//
	// Use a (*http.Client) for custom behavior. Using a custom http.Client
	// will prevent the SDK from modifying the HTTP client.
	HTTPClient HTTPClient

	// An endpoint resolver that can be used to provide or override an endpoint for the given
	// service and region Please see the `aws.EndpointResolver` documentation on usage.
	EndpointResolver EndpointResolver

	// Retryer guides how HTTP requests should be retried in case of
	// recoverable failures. When nil the API client will use a default
	// retryer.
	Retryer Retryer

	// ConfigSources are the sources that were used to construct the Config.
	// Allows for additional configuration to be loaded by clients.
	ConfigSources []interface{}

	// APIOptions provides the set of middleware mutations modify how the API
	// client requests will be handled. This is useful for adding additional
	// tracing data to a request, or changing behavior of the SDK's client.
	APIOptions []func(*middleware.Stack) error

	// The logger writer interface to write logging messages to. Defaults to
	// standard error.
	Logger logging.Logger

	// Configures the events that will be sent to the configured logger.
	// This can be used to configure the logging of signing, retries, request, and responses
	// of the SDK clients.
	//
	// See the ClientLogMode type documentation for the complete set of logging modes and available
	// configuration.
	ClientLogMode ClientLogMode
}

// NewConfig returns a new Config pointer that can be chained with builder
// methods to set multiple configuration values inline without using pointers.
func NewConfig() *Config {
	return &Config{}
}

// Copy will return a shallow copy of the Config object. If any additional
// configurations are provided they will be merged into the new config returned.
func (c Config) Copy() Config {
	cp := c
	return cp
}
