// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

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
	CustomResourceDefinitionVersion = "v2"

	// Cilium Network Policy (CNP)

	// CNPPluralName is the plural name of Cilium Network Policy
	CNPPluralName = "ciliumnetworkpolicies"

	// CNPKindDefinition is the kind name for Cilium Network Policy
	CNPKindDefinition = "CiliumNetworkPolicy"

	// CNPName is the full name of Cilium Network Policy
	CNPName = CNPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Cluster wide Network Policy (CCNP)

	// CCNPPluralName is the plural name of Cilium Cluster wide Network Policy
	CCNPPluralName = "ciliumclusterwidenetworkpolicies"

	// CCNPKindDefinition is the kind name for Cilium Cluster wide Network Policy
	CCNPKindDefinition = "CiliumClusterwideNetworkPolicy"

	// CCNPName is the full name of Cilium Cluster wide Network Policy
	CCNPName = CCNPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Egress Gateway Policy (CEGP)

	// CEGPPluralName is the plural name of Cilium Egress Gateway Policy
	CEGPPluralName = "ciliumegressgatewaypolicies"

	// CEGPKindDefinition is the kind name of Cilium Egress Gateway Policy
	CEGPKindDefinition = "CiliumEgressGatewayPolicy"

	// CEGPName is the full name of Cilium Egress Gateway Policy
	CEGPName = CEGPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Endpoint (CEP)

	// CEPluralName is the plural name of Cilium Endpoint
	CEPPluralName = "ciliumendpoints"

	// CEKindDefinition is the kind name for Cilium Endpoint
	CEPKindDefinition = "CiliumEndpoint"

	// CEPName is the full name of Cilium Endpoint
	CEPName = CEPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Node (CN)

	// CNPluralName is the plural name of Cilium Node
	CNPluralName = "ciliumnodes"

	// CNKindDefinition is the kind name for Cilium Node
	CNKindDefinition = "CiliumNode"

	// CNName is the full name of Cilium Node
	CNName = CNPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Identity

	// CIDPluralName is the plural name of Cilium Identity
	CIDPluralName = "ciliumidentities"

	// CIDKindDefinition is the kind name for Cilium Identity
	CIDKindDefinition = "CiliumIdentity"

	// CIDName is the full name of Cilium Identity
	CIDName = CIDPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Local Redirect Policy (CLRP)

	// CLRPPluralName is the plural name of Local Redirect Policy
	CLRPPluralName = "ciliumlocalredirectpolicies"

	// CLRPKindDefinition is the kind name for Local Redirect Policy
	CLRPKindDefinition = "CiliumLocalRedirectPolicy"

	// CLRPName is the full name of Local Redirect Policy
	CLRPName = CLRPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium External Workload (CEW)

	// CEWPluralName is the plural name of Cilium External Workload
	CEWPluralName = "ciliumexternalworkloads"

	// CEWKindDefinition is the kind name for Cilium External Workload
	CEWKindDefinition = "CiliumExternalWorkload"

	// CEWName is the full name of Cilium External Workload
	CEWName = CEWPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Cluster Envoy Config (CCEC)

	// CCECPluralName is the plural name of Cilium Clusterwide Envoy Config
	CCECPluralName = "ciliumclusterwideenvoyconfigs"

	// CCECKindDefinition is the kind name of Cilium Clusterwide Envoy Config
	CCECKindDefinition = "CiliumClusterwideEnvoyConfig"

	// CCECName is the full name of Cilium Clusterwide Envoy Config
	CCECName = CCECPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Envoy Config (CEC)

	// CECPluralName is the plural name of Cilium Envoy Config
	CECPluralName = "ciliumenvoyconfigs"

	// CECKindDefinition is the kind name of Cilium Envoy Config
	CECKindDefinition = "CiliumEnvoyConfig"

	// CECName is the full name of Cilium Envoy Config
	CECName = CECPluralName + "." + CustomResourceDefinitionGroup

	// CiliumNodeConfig (CNC)

	// CNCPluralName is the plural name of Cilium Node Config
	CNCPluralName = "ciliumnodeconfigs"

	// CNCKindDefinition is the kind name of Cilium Node Config
	CNCKindDefinition = "CiliumNodeConfig"

	// CNCName is the full name of Cilium Node Config
	CNCName = CNCPluralName + "." + CustomResourceDefinitionGroup
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
		&CiliumNetworkPolicy{},
		&CiliumNetworkPolicyList{},
		&CiliumClusterwideNetworkPolicy{},
		&CiliumClusterwideNetworkPolicyList{},
		&CiliumEgressGatewayPolicy{},
		&CiliumEgressGatewayPolicyList{},
		&CiliumEndpoint{},
		&CiliumEndpointList{},
		&CiliumNode{},
		&CiliumNodeList{},
		&CiliumNodeConfig{},
		&CiliumNodeConfigList{},
		&CiliumExternalWorkload{},
		&CiliumExternalWorkloadList{},
		&CiliumIdentity{},
		&CiliumIdentityList{},
		&CiliumLocalRedirectPolicy{},
		&CiliumLocalRedirectPolicyList{},
		&CiliumEnvoyConfig{},
		&CiliumEnvoyConfigList{},
		&CiliumClusterwideEnvoyConfig{},
		&CiliumClusterwideEnvoyConfigList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
