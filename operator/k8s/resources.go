// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

const (
	CiliumEndpointIndexIdentity = "identity"
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

		cell.Config(k8s.DefaultConfig),
		cell.Provide(
			k8s.ServiceResource,
			mcsapi.ServiceExportResource,
			k8s.EndpointsResource,
			k8s.LBIPPoolsResource,
			k8s.CiliumIdentityResource,
			k8s.CiliumPodIPPoolResource,
			k8s.CiliumBGPPeeringPolicyResource,
			CiliumBGPClusterConfigResource,
			k8s.CiliumBGPAdvertisementResource,
			k8s.CiliumBGPPeerConfigResource,
			k8s.CiliumBGPNodeConfigResource,
			CiliumBGPNodeConfigOverrideResource,
			CiliumEndpointResource,
			CiliumEndpointSliceResource,
			CiliumNodeResource,
			PodResource,
			k8s.NamespaceResource,
			k8s.CiliumNetworkPolicyResource,
			k8s.CiliumClusterwideNetworkPolicyResource,
		),
	)
)

// Resources is a convenience struct to group all the operator k8s resources as cell constructor parameters.
type Resources struct {
	cell.In

	Services             resource.Resource[*slim_corev1.Service]
	ServiceExports       resource.Resource[*mcsapiv1alpha1.ServiceExport]
	Endpoints            resource.Resource[*k8s.Endpoints]
	LBIPPools            resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	Identities           resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumPodIPPools     resource.Resource[*cilium_api_v2alpha1.CiliumPodIPPool]
	CiliumEndpoints      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumEndpointSlices resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice]
	CiliumNodes          resource.Resource[*cilium_api_v2.CiliumNode]
	Pods                 resource.Resource[*slim_corev1.Pod]
	Namespaces           resource.Resource[*slim_corev1.Namespace]
}

// HasCEWithIdentity returns true or false if the Cilium Endpoint store has
// the given identity.
func HasCEWithIdentity(cepStore resource.Store[*cilium_api_v2.CiliumEndpoint], identity string) bool {
	if cepStore == nil {
		return false
	}
	ces, _ := cepStore.IndexKeys(CiliumEndpointIndexIdentity, identity)

	return len(ces) != 0
}
