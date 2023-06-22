// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// operator. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	ResourcesCell = cell.Module(
		"k8s-resources",
		"Operator Kubernetes resources",

		cell.Provide(
			k8s.ServiceResource,
			k8s.PodResource,
			k8s.EndpointsResource,
			k8s.LBIPPoolsResource,
			k8s.CiliumIdentityResource,
			k8s.CiliumPodIPPoolResource,

			func(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEndpoint], error) {
				return k8s.CiliumEndpointResource[*cilium_api_v2.CiliumEndpoint](
					lc, cs,
					func() runtime.Object {
						return &cilium_api_v2.CiliumEndpoint{}
					},
					transformToCiliumEndpoint,
					cache.Indexers{
						cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
						identityIndex:        identityIndexFunc,
					},
					opts...,
				)
			},
			func(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
				return k8s.CiliumNodeResource(lc, cs, func() runtime.Object { return &cilium_api_v2.CiliumNode{} }, nil, opts...)
			},
		),
	)
)

// Resources is a convenience struct to group all the operator k8s resources as cell constructor parameters.
type Resources struct {
	cell.In

	Services         resource.Resource[*slim_corev1.Service]
	Pods             resource.Resource[*slim_corev1.Pod]
	Endpoints        resource.Resource[*k8s.Endpoints]
	LBIPPools        resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	Identities       resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumPodIPPools resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool]
	CiliumEndpoints  resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumNodes      resource.Resource[*cilium_api_v2.CiliumNode]
}
