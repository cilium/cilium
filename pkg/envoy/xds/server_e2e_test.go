// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	// logging.ToggleDebugLogs(true)
	TestingT(t)
}

type ServerSuite struct{}

var _ = Suite(&ServerSuite{})

const (
	TestTimeout      = 10 * time.Second
	StreamTimeout    = 2 * time.Second
	CacheUpdateDelay = 250 * time.Millisecond
)

var (
	DeferredCompletion = errors.New("Deferred completion")
	nodes              = map[string]*envoy_config_core.Node{
		node0: {Id: "sidecar~10.0.0.0~node0~bar"},
		node1: {Id: "sidecar~10.0.0.1~node1~bar"},
		node2: {Id: "sidecar~10.0.0.2~node2~bar"},
	}
)

// ResponseMatchesChecker checks that a DiscoveryResponse's fields match the given
// parameters.
type ResponseMatchesChecker struct {
	*CheckerInfo
}

func (c *ResponseMatchesChecker) Check(params []interface{}, names []string) (result bool, error string) {
	response, ok := params[0].(*envoy_service_discovery.DiscoveryResponse)
	if !ok {
		return false, "response must be an *envoy_service_discovery.DiscoveryResponse"
	}
	if response == nil {
		return false, "response is nil"
	}

	versionInfo, ok := params[1].(string)
	if !ok {
		return false, "VersionInfo must be a string"
	}
	resources, ok := params[2].([]proto.Message)
	if params[2] != nil && !ok {
		return false, "Resources must be a []proto.Message"
	}
	canary, ok := params[3].(bool)
	if !ok {
		return false, "Canary must be a bool"
	}
	typeURL, ok := params[4].(string)
	if !ok {
		return false, "TypeURL must be a string"
	}

	error = ""

	result = response.VersionInfo == versionInfo &&
		len(response.Resources) == len(resources) &&
		response.Canary == canary &&
		response.TypeUrl == typeURL

	if result && len(resources) > 0 {
		// Convert the resources into Any protocol buffer messages, which is
		// the type of Resources in the response, so that we can compare them.
		resourcesAny := make([]*anypb.Any, 0, len(resources))
		for _, res := range resources {
			any, err := anypb.New(res)
			if err != nil {
				return false, fmt.Sprintf("error marshalling protocol buffer %v", res)
			}
			resourcesAny = append(resourcesAny, any)
		}
		// Sort both lists.
		sort.Slice(response.Resources, func(i, j int) bool {
			return response.Resources[i].String() < response.Resources[j].String()
		})
		sort.Slice(resourcesAny, func(i, j int) bool {
			return resourcesAny[i].String() < resourcesAny[j].String()
		})
		result = reflect.DeepEqual(response.Resources, resourcesAny)
	}

	return
}

// ResponseMatches checks that a DiscoveryResponse's fields match the given
// parameters.
var ResponseMatches Checker = &ResponseMatchesChecker{
	&CheckerInfo{Name: "ResponseMatches", Params: []string{
		"response", "VersionInfo", "Resources", "Canary", "TypeUrl"}},
}

var resources = []*envoy_config_route.RouteConfiguration{
	{Name: "resource0"},
	{Name: "resource1"},
	{Name: "resource2"},
}

func (s *ServerSuite) TestRequestAllResources(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request all resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0]}, false, typeURL)

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[0], resources[1]}, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 4 with resource 1.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	c.Assert(v, Equals, uint64(4))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "4", []proto.Message{resources[1]}, false, typeURL)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestAck(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request all resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	c.Assert(comp1, Not(IsCompleted))

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0]}, false, typeURL)

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[0], resources[1]}, false, typeURL)

	// Version 2 was ACKed by the last request.
	c.Assert(comp1, IsCompleted)
	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting no response.

	time.Sleep(CacheUpdateDelay)

	// Version 3 was ACKed by the last request.
	c.Assert(comp2, IsCompleted)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestRequestSomeResources(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request resources 1 and 2 (not 0).
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// There should be a response with no resources.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", nil, false, typeURL)

	// Create version 3 with resource 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with one resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[1]}, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 4 with resources 0, 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	c.Assert(v, Equals, uint64(4))
	c.Assert(mod, Equals, true)

	// Expecting a response with resources 1 and 2.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "4", []proto.Message{resources[1], resources[2]}, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 5 with resources 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	c.Assert(v, Equals, uint64(5))
	c.Assert(mod, Equals, true)

	// Expecting no response for version 5, since neither resources 1 and 2
	// have changed.

	// Updating resource 2 with the exact same value won't increase the version
	// number. Remain at version 5.
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	c.Assert(v, Equals, uint64(5))
	c.Assert(mod, Equals, false)

	// Create version 6 with resource 1.
	v, mod, _ = cache.Delete(typeURL, resources[1].Name)
	c.Assert(v, Equals, uint64(6))
	c.Assert(mod, Equals, true)

	// Expecting a response with resource 2.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "6", []proto.Message{resources[2]}, false, typeURL)

	// Resource 1 has been deleted; Resource 2 exists. Confirm using Lookup().
	rsrc, err := cache.Lookup(typeURL, resources[1].Name)
	c.Assert(err, IsNil)
	c.Assert(rsrc, IsNil)

	rsrc, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(rsrc, Not(IsNil))
	c.Assert(rsrc.(*envoy_config_route.RouteConfiguration), checker.DeepEquals, resources[2])

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestUpdateRequestResources(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Create version 2 with resources 0 and 1.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.tx(typeURL, map[string]proto.Message{
		resources[0].Name: resources[0],
		resources[1].Name: resources[1],
	}, nil)
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Request resource 1.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name},
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with resource 1.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[1]}, false, typeURL)

	// Request the next version of resource 1.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 3 with resource 0, 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Not expecting any response since resource 1 didn't change in version 3.

	// Send an updated request for both resource 1 and 2.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with resources 1 and 2.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[1], resources[2]}, false, typeURL)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestRequestStaleNonce(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request all resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0]}, false, typeURL)

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Request the next version of resources, with a stale nonce.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "0",
	}
	// Do not update the nonce.
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting no response from the server.

	// Resend the request with the correct nonce.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[0], resources[1]}, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 4 with resource 1.
	time.Sleep(CacheUpdateDelay)
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	c.Assert(v, Equals, uint64(4))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "4", []proto.Message{resources[1]}, false, typeURL)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestNAck(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request all resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	ackedVersion := resp.VersionInfo
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	c.Assert(comp1, Not(IsCompleted))

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0]}, false, typeURL)

	// NACK the received version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   ackedVersion, // NACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
		ErrorDetail:   &status.Status{Message: "FAILFAIL"},
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 3 with resources 0 and 1.
	time.Sleep(CacheUpdateDelay)

	// NACK cancelled the wg, create a new one
	wg = completion.NewWaitGroup(ctx)
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	c.Assert(comp2, Not(IsCompleted))

	// Version 2 was NACKed by the last request, so comp1 must NOT be completed ever.
	c.Assert(comp1, Not(IsCompleted))
	c.Assert(comp1.Err(), checker.DeepEquals, &ProxyError{Err: ErrNackReceived, Detail: "FAILFAIL"})

	// Expecting a response with both resources.
	// Note that the stream should not have a message that repeats the previous one!
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[0], resources[1]}, false, typeURL)

	c.Assert(comp1, Not(IsCompleted))
	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting no response.

	time.Sleep(CacheUpdateDelay)

	// comp2 was ACKed by the last request.
	c.Assert(comp1, Not(IsCompleted))
	c.Assert(comp2, IsCompleted)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestNAckFromTheStart(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Request all resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	c.Assert(comp1, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "", // NACK all received versions.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp.Nonce, Equals, resp.VersionInfo)
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0]}, false, typeURL)

	// NACK the received version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "", // NACK all received versions.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	time.Sleep(CacheUpdateDelay)

	// Version 2 was NACKed by the last request, so it must NOT be completed successfully.
	c.Assert(comp1, Not(IsCompleted))
	// Version 2 did not have a callback, so the completion was completed with an error
	c.Assert(comp1.Err(), Not(IsNil))
	c.Assert(comp1.Err(), checker.DeepEquals, &ProxyError{Err: ErrNackReceived})

	// NACK canceled the WaitGroup, create new one
	wg = completion.NewWaitGroup(ctx)

	// Create version 3 with resources 0 and 1.
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	c.Assert(comp2, Not(IsCompleted))

	// Expecting a response with both resources.
	// Note that the stream should not have a message that repeats the previous one!
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[0], resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting no response.

	time.Sleep(CacheUpdateDelay)

	// Version 3 was ACKed by the last request.
	c.Assert(comp2, IsCompleted)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestRequestHighVersionFromTheStart(c *C) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	var err error
	var req *envoy_service_discovery.DiscoveryRequest
	var resp *envoy_service_discovery.DiscoveryResponse

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache)

	streamCtx, closeStream := context.WithCancel(ctx)
	stream := NewMockStream(streamCtx, 1, 1, StreamTimeout, StreamTimeout)
	defer stream.Close()

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}},
		TestTimeout)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		close(streamDone)
		c.Check(err, IsNil)
	}()

	// Create version 2 with resource 0.
	time.Sleep(CacheUpdateDelay)
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	c.Assert(comp1, Not(IsCompleted))

	// Request all resources, with a version higher than the version currently
	// in Cilium's cache. This happens after the server restarts but the
	// xDS client survives and continues to request the same version.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "64",
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "64",
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting a response with that resource, and an updated version.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "65", []proto.Message{resources[0]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}
