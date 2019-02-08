package aws

import (
	"net/http"
)

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

	// The resolver to use for looking up endpoints for AWS service clients
	// to use based on region.
	EndpointResolver EndpointResolver

	// The HTTP client to use when sending requests. Defaults to
	// `http.DefaultClient`.
	HTTPClient *http.Client

	// TODO document
	Handlers Handlers

	// Retryer guides how HTTP requests should be retried in case of
	// recoverable failures.
	//
	// When nil or the value does not implement the request.Retryer interface,
	// the client.DefaultRetryer will be used.
	//
	// When both Retryer and MaxRetries are non-nil, the former is used and
	// the latter ignored.
	//
	// To set the Retryer field in a type-safe manner and with chaining, use
	// the request.WithRetryer helper function:
	//
	//   cfg := request.WithRetryer(aws.NewConfig(), myRetryer)
	Retryer Retryer

	// An integer value representing the logging level. The default log level
	// is zero (LogOff), which represents no logging. To enable logging set
	// to a LogLevel Value.
	LogLevel LogLevel

	// The logger writer interface to write logging messages to. Defaults to
	// standard out.
	Logger Logger

	// EnforceShouldRetryCheck is used in the AfterRetryHandler to always call
	// ShouldRetry regardless of whether or not if request.Retryable is set.
	// This will utilize ShouldRetry method of custom retryers. If EnforceShouldRetryCheck
	// is not set, then ShouldRetry will only be called if request.Retryable is nil.
	// Proper handling of the request.Retryable field is important when setting this field.
	//
	// TODO this config field is depercated and needs removed.
	EnforceShouldRetryCheck bool

	// DisableRestProtocolURICleaning will not clean the URL path when making
	// rest protocol requests.  Will default to false. This would only be used
	// for empty directory names in s3 requests.
	//
	// Example:
	//    cfg, err := external.LoadDefaultAWSConfig()
	//    cfg.DisableRestProtocolURICleaning = true
	//
	//    svc := s3.New(cfg)
	//    out, err := svc.GetObject(&s3.GetObjectInput {
	//    	Bucket: aws.String("bucketname"),
	//    	Key: aws.String("//foo//bar//moo"),
	//    })
	//
	// TODO need better way of representing support for this concept. Not on Config.
	DisableRestProtocolURICleaning bool

	// DisableEndpointHostPrefix will disable the SDK's behavior of prefixing
	// request endpoint hosts with modeled information.
	//
	// Disabling this feature is useful when you want to use local endpoints
	// for testing that do not support the modeled host prefix pattern.
	DisableEndpointHostPrefix bool
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
	cp.Handlers = cp.Handlers.Copy()

	return cp
}
