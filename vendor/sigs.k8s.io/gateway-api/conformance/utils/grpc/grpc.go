/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package grpc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "sigs.k8s.io/gateway-api/conformance/echo-basic/grpcechoserver"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

const (
	echoServerPackage = "gateway_api_conformance.echo_basic.grpcecho"
	echoServerService = "GrpcEcho"
)

// Client is an interface used to make requests within conformance tests for grpc scenarios.
// This can be overridden with custom implementations whenever necessary.
type Client interface {
	SendRPC(t *testing.T, address string, expected ExpectedResponse, timeout time.Duration) (*Response, error)
	Close()
}

// DefaultClient is the default implementation of Client. It will
// be used if a custom implementation is not specified.
type DefaultClient struct {
	Conn *grpc.ClientConn
}

type Response struct {
	Code     codes.Code
	Headers  *metadata.MD
	Trailers *metadata.MD
	Response *pb.EchoResponse
}

type RequestMetadata struct {
	// The :authority pseudoheader to set on the outgoing request.
	Authority string

	// Outgoing metadata pairs to add to the request.
	Metadata map[string]string
}

// ExpectedResponse defines the response expected for a given request.
type ExpectedResponse struct {
	// Defines the request to make. Only one of EchoRequest and EchoTwoRequest
	// may be set.
	EchoRequest      *pb.EchoRequest
	EchoTwoRequest   *pb.EchoRequest
	EchoThreeRequest *pb.EchoRequest

	// Metadata describing the outgoing request.
	RequestMetadata *RequestMetadata

	// Response defines what response the test case
	// should receive.
	Response Response

	Backend   string
	Namespace string

	// User Given TestCase name
	TestCaseName string
}

func getMethodName(expected *ExpectedResponse) string {
	switch {
	case expected.EchoRequest != nil:
		return "Echo"
	case expected.EchoTwoRequest != nil:
		return "EchoTwo"
	default:
		return "EchoThree"
	}
}

func getFullyQualifiedMethod(expected *ExpectedResponse) string {
	return fmt.Sprintf("/%s.%s/%s", echoServerPackage, echoServerService, getMethodName(expected))
}

func getMapDeterministicStr(m map[string]string) string {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := "{"
	for i, key := range keys {
		out += key + ":" + m[key]
		if i != len(keys)-1 {
			out += ","
		}
	}
	out += "}"
	return out
}

func (er *ExpectedResponse) GetTestCaseName(i int) string {
	if er.TestCaseName != "" {
		return er.TestCaseName
	}

	headerStr := ""
	reqStr := ""

	authority := ""
	if er.RequestMetadata != nil {
		rm := er.RequestMetadata
		authority = rm.Authority
		if len(rm.Metadata) > 0 {
			headerStr = fmt.Sprintf(" with headers '%s'", getMapDeterministicStr(rm.Metadata))
		}
	}

	reqStr = fmt.Sprintf("%d request to '%s%s'%s", i, authority, getFullyQualifiedMethod(er), headerStr)

	if er.Backend != "" {
		return fmt.Sprintf("%s should go to %s", reqStr, er.Backend)
	}
	return fmt.Sprintf("%s should receive a %s (%d)", reqStr, er.Response.Code.String(), er.Response.Code)
}

func (c *DefaultClient) ensureConnection(address string, req *RequestMetadata) error {
	if c.Conn != nil {
		return nil
	}
	var err error
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if req != nil && req.Authority != "" {
		dialOpts = append(dialOpts, grpc.WithAuthority(req.Authority))
	}

	c.Conn, err = grpc.NewClient(address, dialOpts...)
	if err != nil {
		c.Conn = nil
		return err
	}
	return nil
}

func (c *DefaultClient) resetConnection() {
	if c.Conn == nil {
		return
	}
	c.Conn.Close()
	c.Conn = nil
}

// SendRPC sends a gRPC request to the given address with the expected response.
// An error will be returned if there is an error running the function but not if an HTTP error status code
// is received.
func (c *DefaultClient) SendRPC(t *testing.T, address string, expected ExpectedResponse, timeout time.Duration) (*Response, error) {
	t.Helper()
	if err := c.ensureConnection(address, expected.RequestMetadata); err != nil {
		return &Response{}, err
	}

	resp := &Response{
		Headers:  &metadata.MD{},
		Trailers: &metadata.MD{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	if expected.RequestMetadata != nil && len(expected.RequestMetadata.Metadata) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(expected.RequestMetadata.Metadata))
	}

	defer cancel()

	stub := pb.NewGrpcEchoClient(c.Conn)
	var err error
	tlog.Logf(t, "Sending RPC")

	switch {
	case expected.EchoRequest != nil:
		resp.Response, err = stub.Echo(ctx, expected.EchoRequest, grpc.Header(resp.Headers), grpc.Trailer(resp.Trailers))
	case expected.EchoTwoRequest != nil:
		resp.Response, err = stub.EchoTwo(ctx, expected.EchoTwoRequest, grpc.Header(resp.Headers), grpc.Trailer(resp.Trailers))
	case expected.EchoThreeRequest != nil:
		resp.Response, err = stub.EchoThree(ctx, expected.EchoThreeRequest, grpc.Header(resp.Headers), grpc.Trailer(resp.Trailers))
	default:
		return resp, fmt.Errorf("no request specified")
	}

	if err != nil {
		resp.Code = status.Code(err)
		tlog.Logf(t, "RPC finished with error: %v", err)
		if resp.Code == codes.Internal {
			tlog.Logf(t, "Received code Internal. Resetting connection.")
			c.resetConnection()
		}
	} else {
		tlog.Logf(t, "RPC finished with response %v", resp.Response)
		resp.Code = codes.OK
	}

	return resp, nil
}

func (c *DefaultClient) Close() {
	if c.Conn != nil {
		c.Conn.Close()
	}
}

func compareResponse(expected *ExpectedResponse, response *Response) error {
	if expected.Response.Code != response.Code {
		return fmt.Errorf("expected status code to be %s (%d), but got %s (%d)", expected.Response.Code.String(), expected.Response.Code, response.Code.String(), response.Code)
	}
	if response.Code == codes.OK {
		expectedFullyQualifiedMethod := getFullyQualifiedMethod(expected)
		if expectedFullyQualifiedMethod != response.Response.GetAssertions().GetFullyQualifiedMethod() {
			return fmt.Errorf("expected path to be %s, got %s ", expectedFullyQualifiedMethod, response.Response.GetAssertions().GetFullyQualifiedMethod())
		}

		if expected.Namespace != "" && expected.Namespace != response.Response.GetAssertions().GetContext().GetNamespace() {
			return fmt.Errorf("expected namespace to be %s, got %s", expected.Namespace, response.Response.GetAssertions().GetContext().GetNamespace())
		}

		if !strings.HasPrefix(response.Response.GetAssertions().GetContext().GetPod(), expected.Backend) {
			return fmt.Errorf("expected pod name to start with %s, got %s", expected.Backend, response.Response.GetAssertions().GetContext().GetPod())
		}
	}
	return nil
}

func validateExpectedResponse(t *testing.T, expected ExpectedResponse) {
	requestTypeCount := 0
	if expected.EchoRequest != nil {
		requestTypeCount++
	}
	if expected.EchoTwoRequest != nil {
		requestTypeCount++
	}
	if expected.EchoThreeRequest != nil {
		requestTypeCount++
	}
	require.Equal(t, 1, requestTypeCount, "expected only one request type to be set, but found %d: %v", requestTypeCount, expected)
}

func MakeRequestAndExpectEventuallyConsistentResponse(t *testing.T, c Client, timeoutConfig config.TimeoutConfig, gwAddr string, expected ExpectedResponse) {
	t.Helper()
	validateExpectedResponse(t, expected)
	if c == nil {
		c = &DefaultClient{Conn: nil}
	}
	defer c.Close()
	sendRPC := func(elapsed time.Duration) bool {
		resp, err := c.SendRPC(t, gwAddr, expected, timeoutConfig.MaxTimeToConsistency-elapsed)
		if err != nil {
			tlog.Logf(t, "Failed to send RPC, not ready yet: %v (after %v)", err, elapsed)
			return false
		}
		if err := compareResponse(&expected, resp); err != nil {
			tlog.Logf(t, "Response expectation failed for request: %v  not ready yet: %v (after %v)", expected, err, elapsed)
			return false
		}
		return true
	}
	http.AwaitConvergence(t, timeoutConfig.RequiredConsecutiveSuccesses, timeoutConfig.MaxTimeToConsistency, sendRPC)
	tlog.Logf(t, "Request passed")
}
