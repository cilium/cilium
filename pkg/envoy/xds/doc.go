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

// Package xds is an implementation of Envoy's xDS (Discovery Service)
// protocol.
//
// Server is the base implementation of any gRPC server which supports the xDS
// protocol. All xDS bi-directional gRPC streams from Stream* calls must be
// handled by calling Server.HandleRequestStream.
// For example, to implement the ADS protocol:
//
//    func (s *myGRPCServer) StreamAggregatedResources(stream api.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
//        return s.xdsServer.HandleRequestStream(stream.Context(), stream, xds.AnyTypeURL)
//    }
//
// Server is parameterized by a map of supported resource type URLs to resource
// sets, e.g. to support the LDS and RDS protocols:
//
//    ldsCache := xds.NewCache()
//    rdsCache := xds.NewCache()
//    sets := map[string]xds.ObservableResourceSource{
//        "type.googleapis.com/envoy.api.v2.Listener": ldsCache,
//        "type.googleapis.com/envoy.api.v2.RouteConfiguration": rdsCache,
//    }
//    server := xds.NewServer(sets, 5*time.Seconds)
//
// It is recommended to use a distinct resource set for each resource type to
// minimize the volume of messages sent and received by xDS clients.
//
// Resource sets must implement the ResourceSource interface to provide read
// access to resources of one or multiple resource types:
//
//    type ResourceSource interface {
//        GetResources(ctx context.Context, typeURL string, lastVersion *uint64,
//            node *api.Node, resourceNames []string) (*VersionedResources, error)
//    }
//
// Resource sets should implement the ResourceSet interface to provide
// read-write access. It provides an API to atomically update the resources in
// the set: Upsert inserts or updates a single resource in the set, and
// Delete deletes a single resource from the set.
//
// Cache is an efficient, ready-to-use implementation of ResourceSet:
//
//    typeURL := "type.googleapis.com/envoy.api.v2.Listener"
//    ldsCache := xds.NewCache()
//    ldsCache.Upsert(typeURL, "listener123", listenerA)
//    ldsCache.Delete(typeURL, "listener456")
package xds
