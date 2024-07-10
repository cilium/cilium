// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/completion"
)

const (
	TestTimeout   = 10 * time.Second
	StreamTimeout = 4 * time.Second
)

var (
	nodes = map[string]*envoy_config_core.Node{
		node0: {Id: "node0~10.0.0.0~node0~bar"},
		node1: {Id: "node1~10.0.0.1~node1~bar"},
		node2: {Id: "node2~10.0.0.2~node2~bar"},
	}
)

var resources = []*envoy_config_route.RouteConfiguration{
	{Name: "resource0"},
	{Name: "resource1"},
	{Name: "resource2"},
}

func responseCheck(response *envoy_service_discovery.DiscoveryResponse,
	versionInfo string, resources []proto.Message, canary bool, typeURL string) assert.Comparison {
	return func() bool {
		result := response.VersionInfo == versionInfo &&
			len(response.Resources) == len(resources) &&
			response.Canary == canary &&
			response.TypeUrl == typeURL

		if result && len(resources) > 0 {
			// Convert the resources into Any protocol buffer messages, which is
			// the type of Resources in the response, so that we can compare them.
			resourcesAny := make([]*anypb.Any, 0, len(resources))
			for _, res := range resources {
				a, err := anypb.New(res)
				if err != nil {
					return false
				}
				resourcesAny = append(resourcesAny, a)
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

		return result
	}
}

func TestRequestAllResources(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))
	require.Equal(t, resp.VersionInfo, resp.Nonce)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 2 with resource 0.
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.Equal(t, uint64(2), v)
	require.Equal(t, true, mod)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[0]}, false, typeURL))

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	require.Equal(t, uint64(3), v)
	require.Equal(t, true, mod)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[0], resources[1]}, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 4 with resource 1.
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	require.Equal(t, uint64(4), v)
	require.Equal(t, true, mod)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "4", []proto.Message{resources[1]}, false, typeURL))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestAck(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 2 with resource 0.
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	require.Condition(t, isNotCompletedComparison(comp1))

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[0]}, false, typeURL))

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	require.Condition(t, isNotCompletedComparison(comp2))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[0], resources[1]}, false, typeURL))

	// Version 2 was ACKed by the last request.
	require.Condition(t, completedComparison(comp1))
	require.Condition(t, isNotCompletedComparison(comp2))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Version 3 was ACKed by the last request.
	require.Condition(t, completedComparison(comp2))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestRequestSomeResources(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 2 with resource 0.
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.Equal(t, uint64(2), v)
	require.Equal(t, true, mod)

	// There should be a response with no resources.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", nil, false, typeURL))

	// Create version 3 with resource 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	require.Equal(t, uint64(3), v)
	require.Equal(t, true, mod)

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Expecting a response with one resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[1]}, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 4 with resources 0, 1 and 2.
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	require.Equal(t, uint64(4), v)
	require.Equal(t, true, mod)

	// Expecting a response with resources 1 and 2.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "4", []proto.Message{resources[1], resources[2]}, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name, resources[2].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 5 with resources 1 and 2.
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	require.Equal(t, uint64(5), v)
	require.Equal(t, true, mod)

	// Expecting no response for version 5, since neither resources 1 and 2
	// have changed.

	// Updating resource 2 with the exact same value won't increase the version
	// number. Remain at version 5.
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	require.Equal(t, uint64(5), v)
	require.Equal(t, false, mod)

	// Create version 6 with resource 1.
	v, mod, _ = cache.Delete(typeURL, resources[1].Name)
	require.Equal(t, uint64(6), v)
	require.Equal(t, true, mod)

	// Expecting a response with resource 2.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "6", []proto.Message{resources[2]}, false, typeURL))

	// Resource 1 has been deleted; Resource 2 exists. Confirm using Lookup().
	rsrc, err := cache.Lookup(typeURL, resources[1].Name)
	require.NoError(t, err)
	require.Nil(t, rsrc)

	rsrc, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.NotNil(t, rsrc)
	require.EqualValues(t, resources[2], rsrc.(*envoy_config_route.RouteConfiguration))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestUpdateRequestResources(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
	}()

	// Create version 2 with resources 0 and 1.
	v, mod, _ = cache.tx(typeURL, map[string]proto.Message{
		resources[0].Name: resources[0],
		resources[1].Name: resources[1],
	}, nil)
	require.Equal(t, uint64(2), v)
	require.Equal(t, true, mod)

	// Request resource 1.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "",
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name},
		ResponseNonce: "",
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Expecting a response with resource 1.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[1]}, false, typeURL))

	// Request the next version of resource 1.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: []string{resources[1].Name},
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 3 with resource 0, 1 and 2.
	v, mod, _ = cache.Upsert(typeURL, resources[2].Name, resources[2])
	require.Equal(t, uint64(3), v)
	require.Equal(t, true, mod)

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
	require.NoError(t, err)

	// Expecting a response with resources 1 and 2.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[1], resources[2]}, false, typeURL))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestRequestStaleNonce(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 2 with resource 0.
	v, mod, _ = cache.Upsert(typeURL, resources[0].Name, resources[0])
	require.Equal(t, uint64(2), v)
	require.Equal(t, true, mod)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[0]}, false, typeURL))

	// Create version 3 with resources 0 and 1.
	// This time, update the cache before sending the request.
	v, mod, _ = cache.Upsert(typeURL, resources[1].Name, resources[1])
	require.Equal(t, uint64(3), v)
	require.Equal(t, true, mod)

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
	require.NoError(t, err)

	// Server correctly detects 0 nonce and resets it to the correct value.

	// Expecting a response with both resources.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[0], resources[1]}, false, typeURL))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 4 with resource 1.
	v, mod, _ = cache.Delete(typeURL, resources[0].Name)
	require.Equal(t, uint64(4), v)
	require.Equal(t, true, mod)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "4", []proto.Message{resources[1]}, false, typeURL))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestNAck(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))

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
	require.NoError(t, err)

	// Create version 2 with resource 0.
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	require.Condition(t, isNotCompletedComparison(comp1))

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[0]}, false, typeURL))

	// NACK the received version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   ackedVersion, // NACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
		ErrorDetail:   &status.Status{Message: "NACKNACK"},
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Create version 3 with resources 0 and 1.
	// NACK cancelled the wg, create a new one
	wg = completion.NewWaitGroup(ctx)
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	require.Condition(t, isNotCompletedComparison(comp2))

	// Version 2 was NACKed by the last request, so comp1 must NOT be completedInTime ever.
	require.Condition(t, isNotCompletedComparison(comp1))
	require.EqualValues(t, &ProxyError{Err: ErrNackReceived, Detail: "NACKNACK"}, comp1.Err())

	// Expecting a response with both resources.
	// Note that the stream should not have a message that repeats the previous one!
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[0], resources[1]}, false, typeURL))

	require.Condition(t, isNotCompletedComparison(comp1))
	require.Condition(t, isNotCompletedComparison(comp2))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	require.Condition(t, isNotCompletedComparison(comp1))
	require.Condition(t, completedComparison(comp2))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestNAckFromTheStart(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
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
	require.NoError(t, err)

	// Expecting an empty response.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "1", nil, false, typeURL))

	// Create version 2 with resource 0.
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	require.Condition(t, isNotCompletedComparison(comp1))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "", // NACK all received versions.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Expecting a response with that resource.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Equal(t, resp.VersionInfo, resp.Nonce)
	require.Condition(t, responseCheck(resp, "2", []proto.Message{resources[0]}, false, typeURL))

	// NACK the received version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   "", // NACK all received versions.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Version 2 was NACKed by the last request, so it must NOT be completedInTime successfully.
	require.Condition(t, isNotCompletedComparison(comp1))

	// Version 2 did not have a callback, so the completion was completedInTime with an error
	require.NotNil(t, comp1.Err())
	require.EqualValues(t, &ProxyError{Err: ErrNackReceived}, comp1.Err())

	// NACK canceled the WaitGroup, create new one
	wg = completion.NewWaitGroup(ctx)

	// Create version 3 with resources 0 and 1.
	callback2, comp2 := newCompCallback()
	mutator.Upsert(typeURL, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	require.Condition(t, isNotCompletedComparison(comp2))

	// Expecting a response with both resources.
	// Note that the stream should not have a message that repeats the previous one!
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Condition(t, responseCheck(resp, "3", []proto.Message{resources[0], resources[1]}, false, typeURL))
	require.NotEqual(t, "", resp.Nonce)

	require.Condition(t, isNotCompletedComparison(comp2))

	// Request the next version of resources.
	req = &envoy_service_discovery.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.VersionInfo, // ACK the received version.
		Node:          nodes[node0],
		ResourceNames: nil,
		ResponseNonce: resp.Nonce,
	}
	err = stream.SendRequest(req)
	require.NoError(t, err)

	// Version 3 was ACKed by the last request.
	require.Condition(t, completedComparison(comp2))

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}

func TestRequestHighVersionFromTheStart(t *testing.T) {
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

	server := NewServer(map[string]*ResourceTypeConfiguration{typeURL: {Source: cache, AckObserver: mutator}}, nil)

	streamDone := make(chan struct{})

	// Run the server's stream handler concurrently.
	go func() {
		defer close(streamDone)
		err := server.HandleRequestStream(ctx, stream, AnyTypeURL)
		require.NoError(t, err)
	}()

	// Create version 2 with resource 0.
	callback1, comp1 := newCompCallback()
	mutator.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	require.Condition(t, isNotCompletedComparison(comp1))

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
	require.NoError(t, err)

	// Expecting a response with that resource, and an updated version.
	resp, err = stream.RecvResponse()
	require.NoError(t, err)
	require.Condition(t, responseCheck(resp, "65", []proto.Message{resources[0]}, false, typeURL))
	require.NotEqual(t, "", resp.Nonce)

	// Close the stream.
	closeStream()

	select {
	case <-ctx.Done():
		t.Errorf("HandleRequestStream(%v, %v, %v) took too long to return after stream was closed", "ctx", "stream", AnyTypeURL)
	case <-streamDone:
	}
}
