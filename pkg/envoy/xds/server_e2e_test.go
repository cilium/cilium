// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	. "gopkg.in/check.v1"
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

// ResponseMatchesChecker checks that a DiscoveryResponse's fields match the given
// parameters.
type ResponseMatchesChecker struct {
	*CheckerInfo
}

func (c *ResponseMatchesChecker) Check(params []interface{}, names []string) (result bool, error string) {
	response, ok := params[0].(*envoy_api_v2.DiscoveryResponse)
	if !ok {
		return false, "response must be an *envoy_api_v2.DiscoveryResponse"
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
		resourcesAny := make([]*any.Any, 0, len(resources))
		for _, res := range resources {
			data, err := proto.Marshal(res)
			if err != nil {
				return false, fmt.Sprintf("error marshalling protocol buffer %v", res)
			}
			resourcesAny = append(resourcesAny,
				&any.Any{
					TypeUrl: typeURL,
					Value:   data,
				})
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

var resources = []*envoy_api_v2.RouteConfiguration{
	{Name: "resource0"},
	{Name: "resource1"},
	{Name: "resource2"},
}

func (s *ServerSuite) TestRequestAllResources(c *C) {
	typeURL := "type.googleapis.com/envoy.api.v2.DummyConfiguration"

	var err error
	var req *envoy_api_v2.DiscoveryRequest
	var resp *envoy_api_v2.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache, IstioNodeToIP)

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
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "0", nil, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 1 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Upsert(typeURL, resources[0].Name, resources[0], false)
	c.Assert(v, Equals, uint64(1))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "1", []proto.Message{resources[0]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Create version 2 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod = cache.Upsert(typeURL, resources[1].Name, resources[1], false)
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0], resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 3 with resource 1.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Delete(typeURL, resources[0].Name, false)
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestAck(c *C) {
	typeURL := "type.googleapis.com/envoy.api.v2.DummyConfiguration"

	var err error
	var req *envoy_api_v2.DiscoveryRequest
	var resp *envoy_api_v2.DiscoveryResponse

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache, IstioNodeToIP)

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
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "0", nil, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 1 with resource 0.
	time.Sleep(CacheUpdateDelay)
	comp1 := wg.AddCompletion()
	defer comp1.Complete()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, comp1)
	c.Assert(comp1, Not(IsCompleted))

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "1", []proto.Message{resources[0]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Create version 2 with resources 0 and 1.
	// This time, update the cache before sending the request.
	comp2 := wg.AddCompletion()
	defer comp2.Complete()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, comp2)
	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0], resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Version 1 was ACKed by the last request.
	c.Assert(comp1, IsCompleted)
	c.Assert(comp2, Not(IsCompleted))

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
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

	// Version 2 was ACKed by the last request.
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
	typeURL := "type.googleapis.com/envoy.api.v2.DummyConfiguration"

	var err error
	var req *envoy_api_v2.DiscoveryRequest
	var resp *envoy_api_v2.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache, IstioNodeToIP)

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
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "0", nil, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 1 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Upsert(typeURL, resources[0].Name, resources[0], false)
	c.Assert(v, Equals, uint64(1))
	c.Assert(mod, Equals, true)

	// There should be a response with no resources.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "1", nil, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Create version 2 with resource 0 and 1.
	// This time, update the cache before sending the request.
	v, mod = cache.Upsert(typeURL, resources[1].Name, resources[1], false)
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 3 with resources 0, 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Upsert(typeURL, resources[2].Name, resources[2], false)
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Expecting a response with resources 1 and 2.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[1], resources[2]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 4 with resources 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Delete(typeURL, resources[0].Name, false)
	c.Assert(v, Equals, uint64(4))
	c.Assert(mod, Equals, true)

	// Expecting no response for version 4, since neither resources 1 and 2
	// have changed.

	// Updating resource 2 with the exact same value won't increase the version
	// number. Remain at version 4.
	v, mod = cache.Upsert(typeURL, resources[2].Name, resources[2], false)
	c.Assert(v, Equals, uint64(4))
	c.Assert(mod, Equals, false)

	// Create version 5 with resource 1.
	v, mod = cache.Delete(typeURL, resources[1].Name, false)
	c.Assert(v, Equals, uint64(5))
	c.Assert(mod, Equals, true)

	// Expecting a response with resource 2.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "5", []proto.Message{resources[2]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestUpdateRequestResources(c *C) {
	typeURL := "type.googleapis.com/envoy.api.v2.DummyConfiguration"

	var err error
	var req *envoy_api_v2.DiscoveryRequest
	var resp *envoy_api_v2.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache, IstioNodeToIP)

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

	// Create version 1 with resources 0 and 1.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.tx(typeURL, map[string]proto.Message{
		resources[0].Name: resources[0],
		resources[1].Name: resources[1],
	}, nil, false)
	c.Assert(v, Equals, uint64(1))
	c.Assert(mod, Equals, true)

	// Request resource 1.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "1", []proto.Message{resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resource 1.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 2 with resource 0, 1 and 2.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Upsert(typeURL, resources[2].Name, resources[2], false)
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Not expecting any response since resource 1 didn't change in version 2.

	// Send an updated request for both resource 1 and 2.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[1], resources[2]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func (s *ServerSuite) TestRequestStaleNonce(c *C) {
	typeURL := "type.googleapis.com/envoy.api.v2.DummyConfiguration"

	var err error
	var req *envoy_api_v2.DiscoveryRequest
	var resp *envoy_api_v2.DiscoveryResponse
	var v uint64
	var mod bool

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	cache := NewCache()
	mutator := NewAckingResourceMutatorWrapper(cache, IstioNodeToIP)

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
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "0", nil, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 1 with resource 0.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Upsert(typeURL, resources[0].Name, resources[0], false)
	c.Assert(v, Equals, uint64(1))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "1", []proto.Message{resources[0]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Create version 2 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod = cache.Upsert(typeURL, resources[1].Name, resources[1], false)
	c.Assert(v, Equals, uint64(2))
	c.Assert(mod, Equals, true)

	// Request the next version of resources, with a stale nonce.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: "stale-nonce",
	}
	// Do not update the nonce.
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Expecting no response from the server.

	// Resend the request with the correct nonce.
	req = &envoy_api_v2.DiscoveryRequest{
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
	c.Assert(resp, ResponseMatches, "2", []proto.Message{resources[0], resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Request the next version of resources.
	req = &envoy_api_v2.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	c.Assert(err, IsNil)

	// Create version 3 with resource 1.
	time.Sleep(CacheUpdateDelay)
	v, mod = cache.Delete(typeURL, resources[0].Name, false)
	c.Assert(v, Equals, uint64(3))
	c.Assert(mod, Equals, true)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	c.Assert(err, IsNil)
	c.Assert(resp, ResponseMatches, "3", []proto.Message{resources[1]}, false, typeURL)
	c.Assert(resp.Nonce, Not(Equals), "")

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		c.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}
