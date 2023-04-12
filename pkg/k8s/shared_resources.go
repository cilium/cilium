// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// SharedResourceCell provides a set of shared handles to Kubernetes resources used throughout the
	// Cilium agent. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	SharedResourcesCell = cell.Module(
		"k8s-shared-resources",
		"Shared Kubernetes resources",

		cell.Provide(
			serviceResource,
			localNodeResource,
			localCiliumNodeResource,
			namespaceResource,
			lbIPPoolsResource,
			ciliumIdentityResource,
			ciliumNetworkPolicy,
			ciliumClusterwideNetworkPolicy,
			ciliumCIDRGroup,
		),
	)
)

type SharedResources struct {
	cell.In
	LocalNode                        LocalNodeResource
	LocalCiliumNode                  LocalCiliumNodeResource
	Services                         resource.Resource[*slim_corev1.Service]
	Namespaces                       resource.Resource[*slim_corev1.Namespace]
	LBIPPools                        resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	Identities                       resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumNetworkPolicies            resource.Resource[*cilium_api_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy]
	CIDRGroups                       resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup]
}

func serviceResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*slim_corev1.Service], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
	if err != nil {
		return nil, err
	}
	lw := utils.ListerWatcherFromTyped[*slim_corev1.ServiceList](cs.Slim().CoreV1().Services(""))
	lw = utils.ListerWatcherWithModifier(lw, optsModifier)
	return resource.New[*slim_corev1.Service](lc, lw), nil
}

// LocalNodeResource is a resource.Resource[*corev1.Node] but one which will only stream updates for the node object
// associated with the node we are currently running on.
type LocalNodeResource resource.Resource[*corev1.Node]

func localNodeResource(lc hive.Lifecycle, cs client.Clientset) (LocalNodeResource, error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return LocalNodeResource(resource.New[*corev1.Node](lc, lw)), nil
}

// LocalCiliumNodeResource is a resource.Resource[*cilium_api_v2.Node] but one which will only stream updates for the
// CiliumNode object associated with the node we are currently running on.
type LocalCiliumNodeResource resource.Resource[*cilium_api_v2.CiliumNode]

func localCiliumNodeResource(lc hive.Lifecycle, cs client.Clientset) (LocalCiliumNodeResource, error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return LocalCiliumNodeResource(resource.New[*cilium_api_v2.CiliumNode](lc, lw)), nil
}

func namespaceResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*slim_corev1.Namespace], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*slim_corev1.NamespaceList](cs.Slim().CoreV1().Namespaces())
	return resource.New[*slim_corev1.Namespace](lc, lw), nil
}

func lbIPPoolsResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](
		cs.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
	)
	return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](lc, lw), nil
}

func ciliumIdentityResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2.CiliumIdentity], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumIdentityList](
		cs.CiliumV2().CiliumIdentities(),
	)
	return resource.New[*cilium_api_v2.CiliumIdentity](lc, lw), nil
}

func ciliumNetworkPolicy(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2.CiliumNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNetworkPolicyList](cs.CiliumV2().CiliumNetworkPolicies(""))
	return resource.New[*cilium_api_v2.CiliumNetworkPolicy](lc, lw), nil
}

func ciliumClusterwideNetworkPolicy(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumClusterwideNetworkPolicyList](cs.CiliumV2().CiliumClusterwideNetworkPolicies())
	return resource.New[*cilium_api_v2.CiliumClusterwideNetworkPolicy](lc, lw), nil
}

func ciliumCIDRGroup(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumCIDRGroupList](cs.CiliumV2alpha1().CiliumCIDRGroups())
	return resource.New[*cilium_api_v2alpha1.CiliumCIDRGroup](lc, lw), nil
}
