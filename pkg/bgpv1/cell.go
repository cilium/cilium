// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv1

import (
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/manager"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipam_option "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

var Cell = cell.Module(
	"bgp-cp",
	"BGP Control Plane",

	// The Controller which is the entry point of the module
	cell.Provide(agent.NewController, signaler.NewBGPCPSignaler),
	cell.ProvidePrivate(
		// BGP Peering Policy resource provides the module with a stream of events for the BGPPeeringPolicy resource.
		newBGPPeeringPolicyResource,
		// Secret resource provides secrets in the BGP secret namepsace
		newSecretResource,
		// CiliumLoadBalancerIPPool resource is used by the BGP CP to realize configured LB IP pools.
		newLoadBalancerIPPoolResource,
		// Provides the module with a stream of events for the CiliumPodIPPool resource.
		newCiliumPodIPPoolResource,
	),
	cell.Provide(
		// Create a slim Secret store for BGP secrets, which signals the BGP CP upon each resource event.
		store.NewBGPCPResourceStore[*slim_core_v1.Secret],
		// goBGP is currently the only supported RouterManager, if more are
		// implemented, provide the manager via a Cell that pics implementation based on configuration.
		manager.NewBGPRouterManager,
		// Create a slim service DiffStore
		store.NewDiffStore[*slim_core_v1.Service],
		// Create a endpoints DiffStore
		store.NewDiffStore[*k8s.Endpoints],
		// Create a CiliumLoadBalancerIPPool store which signals the BGP CP upon each resource event.
		store.NewBGPCPResourceStore[*v2alpha1api.CiliumLoadBalancerIPPool],
		// Create a CiliumPodIPPool store which signals the BGP CP upon each resource event.
		store.NewBGPCPResourceStore[*v2alpha1api.CiliumPodIPPool],
	),
	// BGP Rest API handlers
	cell.Provide(
		api.NewGetPeerHandler,
		api.NewGetRoutesHandler,
		api.NewGetRoutePoliciesHandler,
	),
	// Provides the reconcilers used by the route manager to update the config
	reconciler.ConfigReconcilers,

	// Invoke bgp controller to trigger the constructor.
	cell.Invoke(func(*agent.Controller) {}),
)

func newBGPPeeringPolicyResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy] {
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
		), resource.WithMetric("CiliumBGPPeeringPolicy"))
}

func newLoadBalancerIPPoolResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1api.CiliumLoadBalancerIPPool] {
	if !dc.BGPControlPlaneEnabled() {
		return nil
	}
	if !c.IsEnabled() {
		return nil
	}
	return resource.New[*v2alpha1api.CiliumLoadBalancerIPPool](
		lc, utils.ListerWatcherFromTyped[*v2alpha1api.CiliumLoadBalancerIPPoolList](
			c.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
		), resource.WithMetric("CiliumLoadBalancerIPPool"))
}

func newCiliumPodIPPoolResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*v2alpha1api.CiliumPodIPPool] {
	// Do not create this resource if:
	//   1. The BGP Control Plane is disabled.
	//   2. Kubernetes support is disabled and the clientset cannot be used.
	//   3. Multi-pool IPAM is disabled.
	if !dc.BGPControlPlaneEnabled() || !c.IsEnabled() || dc.IPAM != ipam_option.IPAMMultiPool {
		return nil
	}

	return resource.New[*v2alpha1api.CiliumPodIPPool](
		lc, utils.ListerWatcherFromTyped[*v2alpha1api.CiliumPodIPPoolList](
			c.CiliumV2alpha1().CiliumPodIPPools(),
		), resource.WithMetric("CiliumPodIPPool"))
}

func newSecretResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*slim_core_v1.Secret] {
	// Do not create this resource if the BGP Control Plane is disabled
	if !dc.BGPControlPlaneEnabled() {
		return nil
	}

	if !c.IsEnabled() {
		return nil
	}

	// Do not create this resource if the BGP namespace is not set
	if dc.BGPSecretsNamespace == "" {
		log.Warn("bgp-secrets-namespace not set, will not be able to use BGP control plane auth secrets")
		return nil
	}

	return resource.New[*slim_core_v1.Secret](
		lc, utils.ListerWatcherFromTyped[*slim_core_v1.SecretList](
			c.Slim().CoreV1().Secrets(dc.BGPSecretsNamespace),
		))
}
