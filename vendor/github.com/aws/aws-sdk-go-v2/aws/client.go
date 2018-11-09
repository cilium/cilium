package aws

import (
	"net/http"
)

// Metadata wraps immutable data from the Client structure.
type Metadata struct {
	ServiceName string
	APIVersion  string

	Endpoint      string
	SigningName   string
	SigningRegion string

	JSONVersion  string
	TargetPrefix string
}

// A Client implements the base client request and response handling
// used by all service clients.
type Client struct {
	Metadata Metadata

	Config Config

	Region           string
	Credentials      CredentialsProvider
	EndpointResolver EndpointResolver
	Handlers         Handlers
	Retryer          Retryer

	// TODO replace with value not pointer
	LogLevel LogLevel
	Logger   Logger

	HTTPClient *http.Client
}

// NewClient will return a pointer to a new initialized service client.
func NewClient(cfg Config, metadata Metadata) *Client {
	svc := &Client{
		Metadata: metadata,

		// TODO remove config when request reqfactored
		Config: cfg,

		Region:           cfg.Region,
		Credentials:      cfg.Credentials,
		EndpointResolver: cfg.EndpointResolver,
		Handlers:         cfg.Handlers.Copy(),
		Retryer:          cfg.Retryer,

		LogLevel: cfg.LogLevel,
		Logger:   cfg.Logger,
	}

	retryer := cfg.Retryer
	if retryer == nil {
		// TODO need better way of specifing default num retries
		retryer = DefaultRetryer{NumMaxRetries: 3}
	}
	svc.Retryer = retryer

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
