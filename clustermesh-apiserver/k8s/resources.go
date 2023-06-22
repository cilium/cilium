// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// clustermesh-apiserver. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	ResourcesCell = cell.Module(
		"k8s-resources",
		"Clustermesh-apiserver Kubernetes resources",

		cell.Provide(
			k8s.ServiceResource,
			k8s.EndpointsResource,
			func(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
				return k8s.CiliumNodeResource(lc, cs, func() runtime.Object { return &cilium_api_v2.CiliumNode{} }, nil, opts...)
			},
			k8s.CiliumIdentityResource,

			func(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*types.CiliumEndpoint], error) {
				return k8s.CiliumEndpointResource[*types.CiliumEndpoint](
					lc, cs,
					func() runtime.Object {
						return &types.CiliumEndpoint{}
					},
					k8s.TransformToCiliumEndpoint,
					nil,
					opts...,
				)
			},
		),
	)
)

// Resources is a convenience struct to group all the agent k8s resources as cell constructor parameters.
type Resources struct {
	cell.In

	Services            resource.Resource[*slim_corev1.Service]
	Endpoints           resource.Resource[*k8s.Endpoints]
	CiliumNodes         resource.Resource[*cilium_api_v2.CiliumNode]
	CiliumIdentities    resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumSlimEndpoints resource.Resource[*types.CiliumEndpoint]
}
