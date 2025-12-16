// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	"github.com/cilium/cilium/pkg/k8s"
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
		cell.Provide(k8s.DefaultServiceWatchConfig),
		cell.Config(DefaultCiliumEndpointSliceConfig),

		cell.Provide(
			k8s.ServiceResource,
			mcsapi.ServiceExportResource,
			operatorK8s.EndpointsResource,
			CiliumNodeResource,
			CiliumIdentityResource,
			// The CiliumSlimEndpoint and CiliumEndpointSlice resource constructors in the agent depend
			// on the LocalNodeStore to index its cache. In the clustermesh-apiserver, there is no
			// cell providing LocalNodeStore, so we provide the resources with separate
			// constructors.
			CiliumSlimEndpointResource,
			CiliumEndpointSliceResource,
			k8s.NamespaceResource,
		),
	)
)
