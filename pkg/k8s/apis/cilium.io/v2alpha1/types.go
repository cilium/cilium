// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +kubebuilder:validation:Format=cidr
type IPv4orIPv6CIDR string

type EgressRule struct {
	// Selects Namespaces using cluster-scoped labels. This field follows standard label
	// selector semantics; if present but empty, it selects all namespaces.
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`

	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}

// CoreCiliumEndpoint is slim version of status of CiliumEndpoint.
type CoreCiliumEndpoint struct {
	// Name indicate as CiliumEndpoint name.
	Name string `json:"name,omitempty"`
	// IdentityID is the numeric identity of the endpoint
	IdentityID int64 `json:"id,omitempty"`
	// Networking is the networking properties of the endpoint.

	// +kubebuilder:validation:Optional
	Networking *cilium_v2.EndpointNetworking `json:"networking,omitempty"`
	// Encryption is the encryption configuration of the node

	// +kubebuilder:validation:Optional
	Encryption cilium_v2.EncryptionSpec `json:"encryption,omitempty"`
	NamedPorts models.NamedPorts        `json:"named-ports,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumendpointslice",path="ciliumendpointslices",scope="Cluster",shortName={ces}
// +kubebuilder:storageversion

// CiliumEndpointSlice contains a group of CoreCiliumendpoints.
type CiliumEndpointSlice struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Namespace indicate as CiliumEndpointSlice namespace.
	// All the CiliumEndpoints within the same namespace are put together
	// in CiliumEndpointSlice.
	Namespace string `json:"namespace,omitempty"`

	// Endpoints is a list of coreCEPs packed in a CiliumEndpointSlice
	Endpoints []CoreCiliumEndpoint `json:"endpoints"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumEndpointSliceList is a list of CiliumEndpointSlice objects.
type CiliumEndpointSliceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEndpointSlice.
	Items []CiliumEndpointSlice `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumworldcidrset",path="ciliumworldcidrsets",scope="Cluster",shortName={cwcidr}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

type CiliumWorldCIDRSet struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumWorldCIDRSetSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumWorldCIDRSetList is a list of CiliumWorldCIDRSet objects.
type CiliumWorldCIDRSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEgressNATPolicy.
	Items []CiliumWorldCIDRSet `json:"items"`
}

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
type CIDR string

type CiliumWorldCIDRSetSpec struct {
	// WorldCIDRs is a list of IPv4 CIDRs that will be considered outside the
	// "high-scale ipcache domain" (typically outside the clustermesh) and for
	// which traffic won't be encapsulated.
	WorldCIDRs []CIDR `json:"worldCIDRs"`
}
