// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// BGPRouterManager provides a declarative API for defining
// BGP peers.
type BGPRouterManager interface {
	// ReconcileInstances evaluates the provided CiliumBGPNodeConfig
	// and the implementation will configure itself to apply this configuration.
	ReconcileInstances(ctx context.Context, bgpnc *v2.CiliumBGPNodeConfig, ciliumNode *v2.CiliumNode) error

	// GetPeers fetches peer states for all BGP instances managed by this
	// manager. It returns a mapping of instance name to its peer states.
	GetPeers(ctx context.Context, req *GetPeersRequest) (*GetPeersResponse, error)

	// GetPeersLegacy fetches BGP peering state from underlying routing
	// daemon.
	//
	// List of all peers will be returned and if there are multiple
	// instances of BGP daemon running locally, then peers can be
	// differentiated based on local AS number.
	//
	// Deprecated: This is a legacy method used by the REST API and will be removed in the future.
	GetPeersLegacy(ctx context.Context) ([]*models.BgpPeer, error)

	// GetRoutesLegacy fetches BGP routes from underlying routing daemon's RIBs.
	//
	// Deprecated: This is a legacy method used by the REST API and will be removed in the future.
	GetRoutesLegacy(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error)

	// GetRoutes fetches BGP routes from underlying routing daemon's RIBs.
	GetRoutes(ctx context.Context, req *GetRoutesRequest) (*GetRoutesResponse, error)

	// GetRoutePolicies fetches BGP routing policies from underlying routing daemon.
	GetRoutePolicies(ctx context.Context, params *GetRoutePoliciesRequest) (*GetRoutePoliciesResponse, error)

	// GetRoutePoliciesLegacy fetches BGP routing policies from underlying routing daemon.
	//
	// Deprecated: This is a legacy method used by the REST API and will be removed in the future.
	GetRoutePoliciesLegacy(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error)

	// Stop will stop all BGP instances and clean up local state.
	Stop(ctx cell.HookContext) error
}

// GetPeersRequest is a request for GetPeers method.
type GetPeersRequest struct{}

// GetPeersResponse is the response type for GetPeers method.
type GetPeersResponse struct {
	Instances []InstancePeerStates
}

// InstancePeerStates holds peer states for a specific BGP instance.
type InstancePeerStates struct {
	Name  string            `json:"name,omitempty"`
	Peers []types.PeerState `json:"peers,omitempty"`
}

// GetRoutesRequest is a request for GetRoutes method.
type GetRoutesRequest struct {
	TableType types.TableType
	Family    types.Family
}

// GetRoutesResponse is the response type for GetRoutes method.
type GetRoutesResponse struct {
	Instances []InstanceRoutes
}

// GetRoutePoliciesRequest is a request for GetRoutePolicies method.
type GetRoutePoliciesRequest struct {
	InstanceName string
}

// GetRoutePoliciesResponse is the response type for GetRoutePolicies method.
type GetRoutePoliciesResponse struct {
	Instances []InstanceRoutePolicies
}

// InstanceRoutePolicies holds route policies for a specific BGP instance.
type InstanceRoutePolicies struct {
	Name          string
	RoutePolicies []*types.RoutePolicy
}

// InstanceRoutes holds routes for a specific BGP instance.
type InstanceRoutes struct {
	InstanceName string
	NeighborName string
	Routes       []*types.Route
}
