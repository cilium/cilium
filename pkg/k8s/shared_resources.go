// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
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
			namespaceResource,
			lbIPPoolsResource,
		),
	)
)

type SharedResources struct {
	cell.In
	LocalNode  resource.Resource[*corev1.Node]
	Services   resource.Resource[*slim_corev1.Service]
	Namespaces resource.Resource[*slim_corev1.Namespace]
	LBIPPools  resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
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

func localNodeResource(lc hive.Lifecycle, cs client.Clientset) (resource.Resource[*corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
	lw = utils.ListerWatcherWithFields(lw, fields.ParseSelectorOrDie("metadata.name="+nodeTypes.GetName()))
	return resource.New[*corev1.Node](lc, lw), nil
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
