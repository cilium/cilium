// Copyright 2017-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.CustomResourceDefinitionGroup

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	//
	// Maintainers: Run ./Documentation/check-crd-compat-table.sh for each release
	// Developers: Bump patch for each change in the CRD schema.
	CustomResourceDefinitionSchemaVersion = "1.22.4"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "io.cilium.k8s.crd.schema.version"

	// Cilium Network Policy (CNP)

	// CNPSingularName is the singular name of Cilium Network Policy
	CNPSingularName = "ciliumnetworkpolicy"

	// CNPPluralName is the plural name of Cilium Network Policy
	CNPPluralName = "ciliumnetworkpolicies"

	// CNPKindDefinition is the kind name for Cilium Network Policy
	CNPKindDefinition = "CiliumNetworkPolicy"

	// CNPName is the full name of Cilium Network Policy
	CNPName = CNPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Cluster wide Network Policy (CCNP)

	// CCNPSingularName is the singular name of Cilium Cluster wide Network Policy
	CCNPSingularName = "ciliumclusterwidenetworkpolicy"

	// CCNPPluralName is the plural name of Cilium Cluster wide Network Policy
	CCNPPluralName = "ciliumclusterwidenetworkpolicies"

	// CCNPKindDefinition is the kind name for Cilium Cluster wide Network Policy
	CCNPKindDefinition = "CiliumClusterwideNetworkPolicy"

	// CCNPName is the full name of Cilium Cluster wide Network Policy
	CCNPName = CCNPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Endpoint (CEP)

	// CESingularName is the singular name of Cilium Endpoint
	CEPSingularName = "ciliumendpoint"

	// CEPluralName is the plural name of Cilium Endpoint
	CEPPluralName = "ciliumendpoints"

	// CEKindDefinition is the kind name for Cilium Endpoint
	CEPKindDefinition = "CiliumEndpoint"

	// CEPName is the full name of Cilium Endpoint
	CEPName = CEPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Node (CN)

	// CNSingularName is the singular name of Cilium Node
	CNSingularName = "ciliumnode"

	// CNPluralName is the plural name of Cilium Node
	CNPluralName = "ciliumnodes"

	// CNKindDefinition is the kind name for Cilium Node
	CNKindDefinition = "CiliumNode"

	// CNName is the full name of Cilium Node
	CNName = CNPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Identity

	// CIDSingularName is the singular name of Cilium Identity
	CIDSingularName = "ciliumidentity"

	// CIDPluralName is the plural name of Cilium Identity
	CIDPluralName = "ciliumidentities"

	// CIDKindDefinition is the kind name for Cilium Identity
	CIDKindDefinition = "CiliumIdentity"

	// CIDName is the full name of Cilium Identity
	CIDName = CIDPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Local Redirect Policy (CLRP)

	// CLRPSingularName is the singular name of Local Redirect Policy
	CLRPSingularName = "ciliumlocalredirectpolicy"

	// CLRPPluralName is the plural name of Local Redirect Policy
	CLRPPluralName = "ciliumlocalredirectpolicies"

	// CLRPKindDefinition is the kind name for Local Redirect Policy
	CLRPKindDefinition = "CiliumLocalRedirectPolicy"

	// CLRPName is the full name of Local Redirect Policy
	CLRPName = CLRPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium External Workload (CEW)

	// CEWSingularName is the singular name of Cilium External Workload
	CEWSingularName = "ciliumexternalworkload"

	// CEWPluralName is the plural name of Cilium External Workload
	CEWPluralName = "ciliumexternalworkloads"

	// CEWKindDefinition is the kind name for Cilium External Workload
	CEWKindDefinition = "CiliumExternalWorkload"

	// CEWName is the full name of Cilium External Workload
	CEWName = CEWPluralName + "." + CustomResourceDefinitionGroup
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
	//     clientsetscheme "k8s.io/client-go/kuberentes/scheme"
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
		&CiliumEndpoint{},
		&CiliumEndpointList{},
		&CiliumNode{},
		&CiliumNodeList{},
		&CiliumExternalWorkload{},
		&CiliumExternalWorkloadList{},
		&CiliumIdentity{},
		&CiliumIdentityList{},
		&CiliumLocalRedirectPolicy{},
		&CiliumLocalRedirectPolicyList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
