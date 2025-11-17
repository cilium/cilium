// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// BGPRouterManager provides a declarative API for defining
// BGP peers.
type BGPRouterManager interface {
	// ReconcileInstances evaluates the provided CiliumBGPNodeConfig
	// and the implementation will configure itself to apply this configuration.
	ReconcileInstances(ctx context.Context, bgpnc *v2.CiliumBGPNodeConfig, ciliumNode *v2.CiliumNode) error

	// GetPeers fetches BGP peering state from underlying routing daemon.
	//
	// List of all peers will be returned and if there are multiple instances of
	// BGP daemon running locally, then peers can be differentiated based on
	// local AS number.
	GetPeers(ctx context.Context) ([]*models.BgpPeer, error)

	// GetRoutes fetches BGP routes from underlying routing daemon's RIBs.
	GetRoutes(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error)

	// GetRoutePolicies fetches BGP routing policies from underlying routing daemon.
	GetRoutePolicies(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error)

	// Stop will stop all BGP instances and clean up local state.
	Stop(ctx cell.HookContext) error
}
