// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.CustomResourceDefinitionGroup

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2alpha1"

	// Cilium Endpoint Slice (CES)

	// CESSingularName is the singular name of Cilium Endpoint Slice
	CESSingularName = "ciliumendpointslice"

	// CESPluralName is the plural name of Cilium Endpoint Slice
	CESPluralName = "ciliumendpointslices"

	// CESKindDefinition is the kind name of Cilium Endpoint Slice
	CESKindDefinition = "CiliumEndpointSlice"

	// CESName is the full name of Cilium Endpoint Slice
	CESName = CESPluralName + "." + CustomResourceDefinitionGroup

	// Cilium BGP Peering Policy (BGPP)

	// BGPPSingularName is the singular name of Cilium BGP Peering Policy
	BGPPSingularName = "ciliumbgppeeringpolicy"

	// BGPPPluralName is the plural name of Cilium BGP Peering Policy
	BGPPPluralName = "ciliumbgppeeringpolicies"

	// BGPPKindDefinition is the kind name of Cilium BGP Peering Policy
	BGPPKindDefinition = "CiliumBGPPeeringPolicy"

	// BGPPName is the full name of Cilium BGP Peering Policy
	BGPPName = BGPPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Load Balancer IP Pool (IPPool)

	// PoolSingularName is the singular name of Cilium Load Balancer IP Pool
	PoolSingularName = "ciliumloadbalancerippool"

	// PoolPluralName is the plural name of Cilium Load Balancer IP Pool
	PoolPluralName = "ciliumloadbalancerippools"

	// PoolKindDefinition is the kind name of Cilium Peering Policy
	PoolKindDefinition = "CiliumLoadBalancerIPPool"

	// LBIPPoolName is the full name of Cilium Load Balancer IP Pool
	LBIPPoolName = PoolPluralName + "." + CustomResourceDefinitionGroup

	// CiliumNodeConfig (CNC)
	CNCPluralName     = "ciliumnodeconfigs"
	CNCKindDefinition = "CiliumNodeConfig"
	CNCName           = CNCPluralName + "." + CustomResourceDefinitionGroup
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CiliumEndpointSlice{},
		&CiliumEndpointSliceList{},
		&CiliumBGPPeeringPolicy{},
		&CiliumBGPPeeringPolicyList{},
		&CiliumLoadBalancerIPPool{},
		&CiliumLoadBalancerIPPoolList{},
		&CiliumNodeConfig{},
		&CiliumNodeConfigList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
