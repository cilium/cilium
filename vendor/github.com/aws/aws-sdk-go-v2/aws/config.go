package aws

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

	// The HTTP Client the SDK's API clients will use to invoke HTTP requests.
	// The SDK defaults to a BuildableHTTPClient allowing API clients to create
	// copies of the HTTP Client for service specific customizations.
	//
	// Use a (*http.Client) for custom behavior. Using a custom http.Client
	// will prevent the SDK from modifying the HTTP client.
	HTTPClient HTTPClient

	// TODO document
	Handlers Handlers

	// Retryer guides how HTTP requests should be retried in case of
	// recoverable failures. When nil the API client will use a default
	// retryer.
	Retryer Retryer

	// An integer value representing the logging level. The default log level
	// is zero (LogOff), which represents no logging. To enable logging set
	// to a LogLevel Value.
	LogLevel LogLevel

	// The logger writer interface to write logging messages to. Defaults to
	// standard out.
	Logger Logger

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

	// EnableEndpointDiscovery will allow for endpoint discovery on operations that
	// have the definition in its model. By default, endpoint discovery is off.
	EnableEndpointDiscovery bool

	// ConfigSources are the sources that were used to construct the Config.
	// Allows for additional configuration to be loaded by clients.
	ConfigSources []interface{}
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
