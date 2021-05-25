package imds

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// ServiceID provides the unique name of this API client
const ServiceID = "ec2imds"

// Client provides the API client for interacting with the Amazon EC2 Instance
// Metadata Service API.
type Client struct {
	options Options
}

// ClientEnableState provides an enumeration if the client is enabled,
// disabled, or default behavior.
type ClientEnableState uint

// Enumeration values for ClientEnableState
const (
	ClientDefaultEnableState ClientEnableState = iota // default behavior
	ClientDisabled                                    // client disabled
	ClientEnabled                                     // client enabled
)

const (
	disableClientEnvVar = "AWS_EC2_METADATA_DISABLED"

	// Client endpoint options
	endpointEnvVar  = "AWS_EC2_METADATA_SERVICE_ENDPOINT"
	defaultEndpoint = "http://169.254.169.254"
)

// New returns an initialized Client based on the functional options. Provide
// additional functional options to further configure the behavior of the client,
// such as changing the client's endpoint or adding custom middleware behavior.
func New(options Options, optFns ...func(*Options)) *Client {
	options = options.Copy()

	for _, fn := range optFns {
		fn(&options)
	}

	options.HTTPClient = resolveHTTPClient(options.HTTPClient)

	if options.Retryer == nil {
		options.Retryer = retry.NewStandard()
	}
	options.Retryer = retry.AddWithMaxBackoffDelay(options.Retryer, 1*time.Second)

	if options.ClientEnableState == ClientDefaultEnableState {
		if v := os.Getenv(disableClientEnvVar); strings.EqualFold(v, "true") {
			options.ClientEnableState = ClientDisabled
		}
	}

	if len(options.Endpoint) == 0 {
		if v := os.Getenv(endpointEnvVar); len(v) != 0 {
			options.Endpoint = v
		} else {
			options.Endpoint = defaultEndpoint
		}
	}

	client := &Client{
		options: options,
	}

	if client.options.tokenProvider == nil && !client.options.disableAPIToken {
		client.options.tokenProvider = newTokenProvider(client, defaultTokenTTL)
	}

	return client
}

// NewFromConfig returns an initialized Client based the AWS SDK config, and
// functional options. Provide additional functional options to further
// configure the behavior of the client, such as changing the client's endpoint
// or adding custom middleware behavior.
func NewFromConfig(cfg aws.Config, optFns ...func(*Options)) *Client {
	opts := Options{
		APIOptions: append([]func(*middleware.Stack) error{}, cfg.APIOptions...),
		HTTPClient: cfg.HTTPClient,
	}

	if cfg.Retryer != nil {
		opts.Retryer = cfg.Retryer()
	}

	return New(opts, optFns...)
}

// Options provides the fields for configuring the API client's behavior.
type Options struct {
	// Set of options to modify how an operation is invoked. These apply to all
	// operations invoked for this client. Use functional options on operation
	// call to modify this list for per operation behavior.
	APIOptions []func(*middleware.Stack) error

	// The endpoint the client will use to retrieve EC2 instance metadata.

	//
	// If unset, and the environment variable AWS_EC2_METADATA_SERVICE_ENDPOINT
	// has a value the client will use the value of the environment variable as
	// the endpoint for operation calls.
	//
	//    AWS_EC2_METADATA_SERVICE_ENDPOINT=http://[::1]
	Endpoint string

	// The HTTP client to invoke API calls with. Defaults to client's default
	// HTTP implementation if nil.
	HTTPClient HTTPClient

	// Retryer guides how HTTP requests should be retried in case of recoverable
	// failures. When nil the API client will use a default retryer.
	Retryer aws.Retryer

	// Changes if the EC2 Instance Metadata client is enabled or not. Client
	// will default to enabled if not set to ClientDisabled. When the client is
	// disabled it will return an error for all operation calls.
	//
	// If ClientEnableState value is ClientDefaultEnableState (default value),
	// and the environment variable "AWS_EC2_METADATA_DISABLED" is set to
	// "true", the client will be disabled.
	//
	//    AWS_EC2_METADATA_DISABLED=true
	ClientEnableState ClientEnableState

	// Configures the events that will be sent to the configured logger.
	ClientLogMode aws.ClientLogMode

	// The logger writer interface to write logging messages to.
	Logger logging.Logger

	// provides the caching of API tokens used for operation calls. If unset,
	// the API token will not be retrieved for the operation.
	tokenProvider *tokenProvider

	// option to disable the API token provider for testing.
	disableAPIToken bool
}

// HTTPClient provides the interface for a client making HTTP requests with the
// API.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Copy creates a copy of the API options.
func (o Options) Copy() Options {
	to := o
	to.APIOptions = append([]func(*middleware.Stack) error{}, o.APIOptions...)
	return to
}

// WithAPIOptions wraps the API middleware functions, as a functional option
// for the API Client Options. Use this helper to add additional functional
// options to the API client, or operation calls.
func WithAPIOptions(optFns ...func(*middleware.Stack) error) func(*Options) {
	return func(o *Options) {
		o.APIOptions = append(o.APIOptions, optFns...)
	}
}

func (c *Client) invokeOperation(
	ctx context.Context, opID string, params interface{}, optFns []func(*Options),
	stackFns ...func(*middleware.Stack, Options) error,
) (
	result interface{}, metadata middleware.Metadata, err error,
) {
	stack := middleware.NewStack(opID, smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}

	if options.ClientEnableState == ClientDisabled {
		return nil, metadata, &smithy.OperationError{
			ServiceID:     ServiceID,
			OperationName: opID,
			Err: fmt.Errorf(
				"access disabled to EC2 IMDS via client option, or %q environment variable",
				disableClientEnvVar),
		}
	}

	for _, fn := range stackFns {
		if err := fn(stack, options); err != nil {
			return nil, metadata, err
		}
	}

	for _, fn := range options.APIOptions {
		if err := fn(stack); err != nil {
			return nil, metadata, err
		}
	}

	handler := middleware.DecorateHandler(smithyhttp.NewClientHandler(options.HTTPClient), stack)
	result, metadata, err = handler.Handle(ctx, params)
	if err != nil {
		return nil, metadata, &smithy.OperationError{
			ServiceID:     ServiceID,
			OperationName: opID,
			Err:           err,
		}
	}

	return result, metadata, err
}

const (
	// HTTP client constants
	defaultDialerTimeout         = 250 * time.Millisecond
	defaultResponseHeaderTimeout = 500 * time.Millisecond
)

func resolveHTTPClient(client HTTPClient) HTTPClient {
	if client == nil {
		client = awshttp.NewBuildableClient()
	}

	if c, ok := client.(*awshttp.BuildableClient); ok {
		client = c.
			WithDialerOptions(func(d *net.Dialer) {
				// Use a custom Dial timeout for the EC2 Metadata service to account
				// for the possibility the application might not be running in an
				// environment with the service present. The client should fail fast in
				// this case.
				d.Timeout = defaultDialerTimeout
			}).
			WithTransportOptions(func(tr *http.Transport) {
				// Use a custom Transport timeout for the EC2 Metadata service to
				// account for the possibility that the application might be running in
				// a container, and EC2Metadata service drops the connection after a
				// single IP Hop. The client should fail fast in this case.
				tr.ResponseHeaderTimeout = defaultResponseHeaderTimeout
			})
	}

	return client
}
