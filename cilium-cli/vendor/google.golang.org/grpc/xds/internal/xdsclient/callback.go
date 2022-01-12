/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package xdsclient

import (
	"google.golang.org/grpc/xds/internal/xdsclient/xdsresource"
)

// NewListeners is called by the underlying xdsAPIClient when it receives an
// xDS response.
//
// A response can contain multiple resources. They will be parsed and put in a
// map from resource name to the resource content.
func (c *clientImpl) NewListeners(updates map[string]xdsresource.ListenerUpdateErrTuple, metadata xdsresource.UpdateMetadata) {
	c.pubsub.NewListeners(updates, metadata)
}

// NewRouteConfigs is called by the underlying xdsAPIClient when it receives an
// xDS response.
//
// A response can contain multiple resources. They will be parsed and put in a
// map from resource name to the resource content.
func (c *clientImpl) NewRouteConfigs(updates map[string]xdsresource.RouteConfigUpdateErrTuple, metadata xdsresource.UpdateMetadata) {
	c.pubsub.NewRouteConfigs(updates, metadata)
}

// NewClusters is called by the underlying xdsAPIClient when it receives an xDS
// response.
//
// A response can contain multiple resources. They will be parsed and put in a
// map from resource name to the resource content.
func (c *clientImpl) NewClusters(updates map[string]xdsresource.ClusterUpdateErrTuple, metadata xdsresource.UpdateMetadata) {
	c.pubsub.NewClusters(updates, metadata)
}

// NewEndpoints is called by the underlying xdsAPIClient when it receives an
// xDS response.
//
// A response can contain multiple resources. They will be parsed and put in a
// map from resource name to the resource content.
func (c *clientImpl) NewEndpoints(updates map[string]xdsresource.EndpointsUpdateErrTuple, metadata xdsresource.UpdateMetadata) {
	c.pubsub.NewEndpoints(updates, metadata)
}

// NewConnectionError is called by the underlying xdsAPIClient when it receives
// a connection error. The error will be forwarded to all the resource watchers.
func (c *clientImpl) NewConnectionError(err error) {
	c.pubsub.NewConnectionError(err)
}
