// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv1

import (
	"time"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sutils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"

	"k8s.io/client-go/util/workqueue"
)

var Cell = cell.Module(
	"bgp-cp",
	"BGP Control Plane",

	// The Controller which is the entry point of the module
	cell.Provide(agent.NewController),
	cell.ProvidePrivate(
		// Signaler is used by all cells that observe resources to signal the controller to start reconciliation.
		agent.NewSignaler,
		// Local Node Store Specer provides the module with information about the current node.
		agent.NewLocalNodeStoreSpecer,
		// BGP Peering Policy resource provides the module with a stream of events for the BGPPeeringPolicy resource.
		newBGPPeeringPolicyResource,
		// goBGP is currently the only supported RouterManager, if more are
		// implemented, provide the manager via a Cell that pics implementation based on configuration.
		gobgp.NewBGPRouterManager,
		// Create a slim service resource
		newSlimServiceResource,
		// Create a slim service DiffStore
		gobgp.NewDiffStore[*slim_core_v1.Service],
	),
	// Provides the reconcilers used by the route manager to update the config
	gobgp.ConfigReconcilers,
)

func newBGPPeeringPolicyResource(lc hive.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy] {
	// Do not create this resource if the BGP Control Plane is disabled
	if !dc.BGPControlPlaneEnabled() {
		return nil
	}

	if !c.IsEnabled() {
		return nil
	}

	return resource.New[*v2alpha1api.CiliumBGPPeeringPolicy](
		lc, utils.ListerWatcherFromTyped[*v2alpha1api.CiliumBGPPeeringPolicyList](
			c.CiliumV2alpha1().CiliumBGPPeeringPolicies(),
		))
}

// Constructs a slim service resource with perpetual retries at a exponential backoff
func newSlimServiceResource(lc hive.Lifecycle, c k8sClient.Clientset, dc *option.DaemonConfig) (resource.Resource[*slim_core_v1.Service], error) {
	// Do not create this resource if the BGP Control Plane is disabled
	if !dc.BGPControlPlaneEnabled() {
		return nil, nil
	}

	if !c.IsEnabled() {
		return nil, nil
	}

	optsModifier, err := k8sutils.GetServiceListOptionsModifier(option.Config)
	if err != nil {
		return nil, err
	}
	return resource.New[*slim_core_v1.Service](
		lc,
		k8sutils.ListerWatcherWithModifier(
			k8sutils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](c.Slim().CoreV1().Services("")),
			optsModifier),
		resource.WithErrorHandler(resource.AlwaysRetry),
		resource.WithRateLimiter(newErrorRateLimiter),
	), nil
}

func newErrorRateLimiter() workqueue.RateLimiter {
	// This rate limiter will retry in the following pattern
	// 250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 32s, .... max 5m
	return workqueue.NewItemExponentialFailureRateLimiter(250*time.Millisecond, 5*time.Minute)
}
