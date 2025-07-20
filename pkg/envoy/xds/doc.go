// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package xds is an implementation of Envoy's xDS (Discovery Service)
// protocol.
//
// Server is the base implementation of any gRPC server which supports the xDS
// protocol. All xDS bi-directional gRPC streams from Stream* calls must be
// handled by calling Server.HandleRequestStream.
// For example, to implement the ADS protocol:
//
//	func (s *myGRPCServer) StreamAggregatedResources(stream api.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
//	    return s.xdsServer.HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
//	}
//
// Server is parameterized by a map of supported resource type URLs to resource
// sets, e.g. to support the LDS and RDS protocols:
//
//	ldsCache := xds.NewCache()
//	lds := xds.NewAckingResourceMutatorWrapper(ldsCache)
//	rdsCache := xds.NewCache()
//	rds := xds.NewAckingResourceMutatorWrapper(rdsCache)
//
//	resTypes := map[string]xds.ResourceTypeConfiguration{
//	    "type.googleapis.com/envoy.config.listener.v3.Listener": {ldsCache, lds},
//	    "type.googleapis.com/envoy.config.route.v3.RouteConfiguration": {rdsCache, rds},
//	}
//
//	server := xds.NewServer(resTypes, 5*time.Seconds)
//
// It is recommended to use a distinct resource set for each resource type to
// minimize the volume of messages sent and received by xDS clients.
//
// Resource sets must implement the ResourceSource interface to provide read
// access to resources of one or multiple resource types:
//
//	type ResourceSource interface {
//	    GetResources(ctx context.Context, typeURL string, lastVersion *uint64,
//	        nodeIP string, resourceNames []string) (*VersionedResources, error)
//	}
//
// Resource sets should implement the ResourceSet interface to provide
// read-write access. It provides an API to atomically update the resources in
// the set: Upsert inserts or updates a single resource in the set, and
// Delete deletes a single resource from the set.
//
// Cache is an efficient, ready-to-use implementation of ResourceSet:
//
//	typeURL := "type.googleapis.com/envoy.config.listener.v3.Listener"
//	ldsCache := xds.NewCache()
//	ldsCache.Upsert(typeURL, "listener123", listenerA, false)
//	ldsCache.Delete(typeURL, "listener456", false)
//
// In order to wait for acknowledgements of updates by Envoy nodes,
// each resource set should be wrapped into an AckingResourceMutatorWrapper,
// which should then be passed to NewServer().
// AckingResourceMutatorWrapper provides an extended API which accepts
// Completions to notify of ACKs.
//
//	typeURL := "type.googleapis.com/envoy.config.listener.v3.Listener"
//	ldsCache := xds.NewCache()
//	lds := xds.NewAckingResourceMutatorWrapper(ldsCache)
//
//	ctx, cancel := context.WithTimeout(..., 5*time.Second)
//	wg := completion.NewWaitGroup(ctx)
//	nodes := []string{"10.0.0.1"} // Nodes to wait an ACK from.
//	lds.Upsert(typeURL, "listener123", listenerA, nodes, wg.AddCompletion())
//	lds.Delete(typeURL, "listener456", nodes, wg.AddCompletion())
//	wg.Wait()
//	cancel()
package xds
