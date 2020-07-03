// Package ec2metadata provides the client for making API calls to the
// EC2 Instance Metadata service.
//
// This package's client can be disabled completely by setting the environment
// variable "AWS_EC2_METADATA_DISABLED=true". This environment variable set to
// true instructs the SDK to disable the EC2 Metadata client. The client cannot
// be used while the environemnt variable is set to true, (case insensitive).
package ec2metadata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/defaults"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
)

const (
	// ServiceName is the name of the service.
	ServiceName          = "ec2metadata"
	disableServiceEnvVar = "AWS_EC2_METADATA_DISABLED"

	// Headers for Token and TTL
	ttlHeader   = "x-aws-ec2-metadata-token-ttl-seconds"
	tokenHeader = "x-aws-ec2-metadata-token"

	// Named Handler constants
	contextWithTimeoutHandlerName  = "ContextWithTimeoutHandler"
	cancelContextHandlerName       = "CancelContextHandler"
	fetchTokenHandlerName          = "FetchTokenHandler"
	unmarshalMetadataHandlerName   = "unmarshalMetadataHandler"
	unmarshalTokenHandlerName      = "unmarshalTokenHandler"
	enableTokenProviderHandlerName = "enableTokenProviderHandler"

	// client constants
	defaultClientContextTimeout  = 5 * time.Second
	defaultDialerTimeout         = 250 * time.Millisecond
	defaultResponseHeaderTimeout = 500 * time.Millisecond

	// TTL constants
	defaultTTL          = 21600 * time.Second
	ttlExpirationWindow = 30 * time.Second
)

// A Client is an EC2 Instance Metadata service Client.
type Client struct {
	*aws.Client
}

// New creates a new instance of the Client client with a Config.
// This client is safe to use across multiple goroutines.
//
// Example:
//     // Create a Client client from just a config.
//     svc := ec2metadata.New(cfg)
func New(config aws.Config) *Client {
	if c, ok := config.HTTPClient.(*aws.BuildableHTTPClient); ok {
		// TODO consider moving this to a client configuration via client builder
		// instead automatically being set.

		// Use a custom Dial timeout for the EC2 Metadata service to account
		// for the possibility the application might not be running in an
		// environment with the service present. The client should fail fast in
		// this case.
		config.HTTPClient = c.WithDialerOptions(func(d *net.Dialer) {
			d.Timeout = defaultDialerTimeout
		})

		// Use a custom Transport timeout for the EC2 Metadata service to account
		// for the possibility that the application might be running in a container,
		// and EC2Metadata service drops the connection after a single IP Hop. The client
		// should fail fast in this case.
		config.HTTPClient = c.WithTransportOptions(func(tr *http.Transport) {
			tr.ResponseHeaderTimeout = defaultResponseHeaderTimeout
		})
	}

	svc := &Client{
		Client: aws.NewClient(
			config,
			aws.Metadata{
				ServiceName: "EC2 Instance Metadata",
				ServiceID:   "EC2InstanceMetadata",
				EndpointsID: "ec2metadata",
				APIVersion:  "latest",
			},
		),
	}

	if config.Retryer == nil {
		svc.Retryer = retry.NewStandard()
	}
	svc.Retryer = retry.AddWithMaxBackoffDelay(svc.Retryer, 1*time.Second)

	// token provider instance
	tp := newTokenProvider(svc, defaultTTL)
	// NamedHandler for fetching token
	svc.Handlers.Sign.PushBackNamed(aws.NamedHandler{
		Name: fetchTokenHandlerName,
		Fn:   tp.fetchTokenHandler,
	})

	// The context With timeout handler function wraps a context with timeout and sets it on a request.
	// It also sets a handler on complete handler stack that cancels the context
	svc.Handlers.Send.PushFrontNamed(aws.NamedHandler{
		Name: contextWithTimeoutHandlerName,
		Fn: func(r *aws.Request) {
			ctx, cancelFn := context.WithTimeout(r.Context(), defaultClientContextTimeout)
			r.SetContext(ctx)
			r.Handlers.Complete.PushBackNamed(aws.NamedHandler{
				Name: cancelContextHandlerName,
				Fn: func(r *aws.Request) {
					cancelFn()
				},
			})
		},
	})

	// NamedHandler for enabling token provider
	svc.Handlers.Complete.PushBackNamed(aws.NamedHandler{
		Name: enableTokenProviderHandlerName,
		Fn:   tp.enableTokenProviderHandler,
	})

	svc.Handlers.Unmarshal.PushBackNamed(unmarshalHandler)
	svc.Handlers.UnmarshalError.PushBack(unmarshalError)
	svc.Handlers.Validate.Clear()
	svc.Handlers.Validate.PushBack(validateEndpointHandler)

	// Disable the EC2 Instance Metadata service if the environment variable is
	// set. This shortcirctes the service's functionality to always fail to
	// send requests.
	if strings.ToLower(os.Getenv(disableServiceEnvVar)) == "true" {
		svc.Handlers.Send.SwapNamed(aws.NamedHandler{
			Name: defaults.SendHandler.Name,
			Fn: func(r *aws.Request) {
				r.HTTPResponse = &http.Response{
					Header: http.Header{},
				}
				r.Error = &aws.RequestCanceledError{
					Err: fmt.Errorf("EC2 IMDS access disabled via " + disableServiceEnvVar + " env var"),
				}
			},
		})
	}

	return svc
}

type metadataOutput struct {
	Content string
}

type tokenOutput struct {
	Token string
	TTL   time.Duration
}

// unmarshal token handler is used to parse the response of a getToken operation
var unmarshalTokenHandler = aws.NamedHandler{
	Name: unmarshalTokenHandlerName,
	Fn: func(r *aws.Request) {
		defer r.HTTPResponse.Body.Close()
		var b bytes.Buffer
		if _, err := io.Copy(&b, r.HTTPResponse.Body); err != nil {
			r.Error = awserr.NewRequestFailure(awserr.New(aws.ErrCodeSerialization,
				"unable to unmarshal EC2 metadata response", err), r.HTTPResponse.StatusCode, r.RequestID)
			return
		}

		v := r.HTTPResponse.Header.Get(ttlHeader)
		data, ok := r.Data.(*tokenOutput)
		if !ok {
			return
		}

		data.Token = b.String()
		// TTL is in seconds
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			r.Error = awserr.NewRequestFailure(awserr.New(aws.ParamFormatErrCode,
				"unable to parse EC2 token TTL response", err), r.HTTPResponse.StatusCode, r.RequestID)
			return
		}
		t := time.Duration(i) * time.Second
		data.TTL = t
	},
}

var unmarshalHandler = aws.NamedHandler{
	Name: unmarshalMetadataHandlerName,
	Fn: func(r *aws.Request) {
		defer r.HTTPResponse.Body.Close()
		var b bytes.Buffer
		if _, err := io.Copy(&b, r.HTTPResponse.Body); err != nil {
			r.Error = awserr.NewRequestFailure(awserr.New(aws.ErrCodeSerialization,
				"unable to unmarshal EC2 metadata response", err), r.HTTPResponse.StatusCode, r.RequestID)
			return
		}

		if data, ok := r.Data.(*metadataOutput); ok {
			data.Content = b.String()
		}
	},
}

func unmarshalError(r *aws.Request) {
	defer r.HTTPResponse.Body.Close()
	var b bytes.Buffer

	if _, err := io.Copy(&b, r.HTTPResponse.Body); err != nil {
		r.Error = awserr.NewRequestFailure(
			awserr.New(aws.ErrCodeSerialization, "unable to unmarshal EC2 metadata error response", err),
			r.HTTPResponse.StatusCode, r.RequestID)
		return
	}

	// Response body format is not consistent between metadata endpoints.
	// Grab the error message as a string and include that as the source error
	r.Error = awserr.NewRequestFailure(awserr.New("EC2MetadataError", "failed to make EC2Metadata request", errors.New(b.String())),
		r.HTTPResponse.StatusCode, r.RequestID)
}

func validateEndpointHandler(r *aws.Request) {
	if len(r.Endpoint.URL) == 0 {
		r.Error = &aws.MissingEndpointError{}
	}
}
