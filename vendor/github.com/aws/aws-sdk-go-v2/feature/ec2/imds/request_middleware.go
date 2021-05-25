package imds

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func addAPIRequestMiddleware(stack *middleware.Stack,
	options Options,
	getPath func(interface{}) (string, error),
	getOutput func(*smithyhttp.Response) (interface{}, error),
) (err error) {
	err = addRequestMiddleware(stack, options, "GET", getPath, getOutput)
	if err != nil {
		return err
	}

	// Token Serializer build and state management.
	if !options.disableAPIToken {
		err = stack.Finalize.Insert(options.tokenProvider, (*retry.Attempt)(nil).ID(), middleware.After)
		if err != nil {
			return err
		}

		err = stack.Deserialize.Insert(options.tokenProvider, "OperationDeserializer", middleware.Before)
		if err != nil {
			return err
		}
	}

	return nil
}

func addRequestMiddleware(stack *middleware.Stack,
	options Options,
	method string,
	getPath func(interface{}) (string, error),
	getOutput func(*smithyhttp.Response) (interface{}, error),
) (err error) {
	err = awsmiddleware.AddSDKAgentKey(awsmiddleware.FeatureMetadata, "ec2-imds")(stack)
	if err != nil {
		return err
	}

	// Operation timeout
	err = stack.Initialize.Add(&operationTimeout{
		Timeout: defaultOperationTimeout,
	}, middleware.Before)
	if err != nil {
		return err
	}

	// Operation Serializer
	err = stack.Serialize.Add(&serializeRequest{
		GetPath: getPath,
		Method:  method,
	}, middleware.After)
	if err != nil {
		return err
	}

	// Operation endpoint resolver
	err = stack.Serialize.Insert(&resolveEndpoint{
		Endpoint: options.Endpoint,
	}, "OperationSerializer", middleware.Before)
	if err != nil {
		return err
	}

	// Operation Deserializer
	err = stack.Deserialize.Add(&deserializeResponse{
		GetOutput: getOutput,
	}, middleware.After)
	if err != nil {
		return err
	}

	// Retry support
	return retry.AddRetryMiddlewares(stack, retry.AddRetryMiddlewaresOptions{
		Retryer:          options.Retryer,
		LogRetryAttempts: options.ClientLogMode.IsRetries(),
	})
}

type serializeRequest struct {
	GetPath func(interface{}) (string, error)
	Method  string
}

func (*serializeRequest) ID() string {
	return "OperationSerializer"
}

func (m *serializeRequest) HandleSerialize(
	ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler,
) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	reqPath, err := m.GetPath(in.Parameters)
	if err != nil {
		return out, metadata, fmt.Errorf("unable to get request URL path, %w", err)
	}

	request.Request.URL.Path = reqPath
	request.Request.Method = m.Method

	return next.HandleSerialize(ctx, in)
}

type deserializeResponse struct {
	GetOutput func(*smithyhttp.Response) (interface{}, error)
}

func (*deserializeResponse) ID() string {
	return "OperationDeserializer"
}

func (m *deserializeResponse) HandleDeserialize(
	ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler,
) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	resp, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, fmt.Errorf(
			"unexpected transport response type, %T", out.RawResponse)
	}

	// Anything thats not 200 |< 300 is error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return out, metadata, &smithyhttp.ResponseError{
			Response: resp,
			Err:      fmt.Errorf("request to EC2 IMDS failed"),
		}
	}

	result, err := m.GetOutput(resp)
	if err != nil {
		return out, metadata, fmt.Errorf(
			"unable to get deserialized result for response, %w", err,
		)
	}
	out.Result = result

	return out, metadata, err
}

type resolveEndpoint struct {
	Endpoint string
}

func (*resolveEndpoint) ID() string {
	return "ResolveEndpoint"
}

func (m *resolveEndpoint) HandleSerialize(
	ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler,
) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {

	req, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, fmt.Errorf("unknown transport type %T", in.Request)
	}

	req.URL, err = url.Parse(m.Endpoint)
	if err != nil {
		return out, metadata, fmt.Errorf("failed to parse endpoint URL: %w", err)
	}

	return next.HandleSerialize(ctx, in)
}

const (
	defaultOperationTimeout = 5 * time.Second
)

type operationTimeout struct {
	Timeout time.Duration
}

func (*operationTimeout) ID() string { return "OperationTimeout" }

func (m *operationTimeout) HandleInitialize(
	ctx context.Context, input middleware.InitializeInput, next middleware.InitializeHandler,
) (
	output middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	var cancelFn func()

	ctx, cancelFn = context.WithTimeout(ctx, m.Timeout)
	defer cancelFn()

	return next.HandleInitialize(ctx, input)
}

// appendURIPath joins a URI path component to the existing path with `/`
// separators between the path components. If the path being added ends with a
// trailing `/` that slash will be maintained.
func appendURIPath(base, add string) string {
	reqPath := path.Join(base, add)
	if len(add) != 0 && add[len(add)-1] == '/' {
		reqPath += "/"
	}
	return reqPath
}
