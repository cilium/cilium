// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// agent. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	ResourcesCell = cell.Module(
		"k8s-resources",
		"Agent Kubernetes resources",

		cell.Config(k8s.DefaultConfig),
		LocalNodeCell,
		cell.Provide(
			k8s.ServiceResource,
			k8s.EndpointsResource,
			k8s.NamespaceResource,
			k8s.NetworkPolicyResource,
			k8s.CiliumNetworkPolicyResource,
			k8s.CiliumClusterwideNetworkPolicyResource,
			k8s.CiliumCIDRGroupResource,
			k8s.CiliumNodeResource,
			k8s.CiliumSlimEndpointResource,
			k8s.CiliumEndpointSliceResource,
		),
	)

	LocalNodeCell = cell.Module(
		"k8s-local-node-resources",
		"Agent Kubernetes local node resources",

		cell.Provide(
			func(lc cell.Lifecycle, cs client.Clientset) (LocalNodeResource, error) {
				return k8s.NodeResource(
					lc, cs,
					func(opts *metav1.ListOptions) {
						opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
					},
				)
			},
			func(lc cell.Lifecycle, cs client.Clientset) (LocalCiliumNodeResource, error) {
				return k8s.CiliumNodeResource(
					lc, cs,
					func(opts *metav1.ListOptions) {
						opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
					},
				)
			},
			func(lc cell.Lifecycle, cs client.Clientset) (LocalPodResource, error) {
				return k8s.PodResource(
					lc, cs,
					func(opts *metav1.ListOptions) {
						opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodeTypes.GetName()).String()
					},
				)
			},
		),
	)
)

// LocalNodeResource is a resource.Resource[*slim_corev1.Node] but one which will only stream updates for the node object
// associated with the node we are currently running on.
type LocalNodeResource resource.Resource[*slim_corev1.Node]

// LocalCiliumNodeResource is a resource.Resource[*cilium_api_v2.CiliumNode] but one which will only stream updates for the
// CiliumNode object associated with the node we are currently running on.
type LocalCiliumNodeResource resource.Resource[*cilium_api_v2.CiliumNode]

// LocalPodResource is a resource.Resource[*slim_corev1.Pod] but one which will only stream updates for pod
// objects scheduled on the node we are currently running on.
type LocalPodResource resource.Resource[*slim_corev1.Pod]

// Resources is a convenience struct to group all the agent k8s resources as cell constructor parameters.
type Resources struct {
	cell.In

	Services                         resource.Resource[*slim_corev1.Service]
	Endpoints                        resource.Resource[*k8s.Endpoints]
	LocalNode                        LocalNodeResource
	LocalCiliumNode                  LocalCiliumNodeResource
	LocalPods                        LocalPodResource
	Namespaces                       resource.Resource[*slim_corev1.Namespace]
	NetworkPolicies                  resource.Resource[*slim_networkingv1.NetworkPolicy]
	CiliumNetworkPolicies            resource.Resource[*cilium_api_v2.CiliumNetworkPolicy]
	CiliumClusterwideNetworkPolicies resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy]
	CiliumCIDRGroups                 resource.Resource[*cilium_api_v2alpha1.CiliumCIDRGroup]
	CiliumSlimEndpoint               resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSlice              resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice]
}

// LocalNodeResources is a convenience struct to group CiliumNode and Node resources as cell constructor parameters.
type LocalNodeResources struct {
	cell.In

	LocalNode       LocalNodeResource
	LocalCiliumNode LocalCiliumNodeResource
}
