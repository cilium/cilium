// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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

		cell.Config(k8s.DefaultConfig),
		cell.Provide(
			k8s.ServiceResource,
			mcsapi.ServiceExportResource,
			k8s.EndpointsResource,
			CiliumNodeResource,
			k8s.CiliumIdentityResource,
			// The CiliumSlimEndpoint resource constructor in the agent depends on the
			// LocalNodeStore to index its cache. In the clustermesh-apiserver, there is no
			// cell providing LocalNodeStore, so we provide the resource with a separate
			// constructor.
			CiliumSlimEndpointResource,
			k8s.CiliumExternalWorkloads,
		),
	)
)

// Resources is a convenience struct to group all the agent k8s resources as cell constructor parameters.
type Resources struct {
	cell.In

	Services            resource.Resource[*slim_corev1.Service]
	ServiceExports      resource.Resource[*mcsapiv1alpha1.ServiceExport]
	Endpoints           resource.Resource[*k8s.Endpoints]
	CiliumNodes         resource.Resource[*cilium_api_v2.CiliumNode]
	CiliumIdentities    resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumSlimEndpoints resource.Resource[*types.CiliumEndpoint]
}
