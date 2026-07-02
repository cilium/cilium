// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumvtepconfig",path="ciliumvtepconfigs",scope="Cluster",shortName={cvtep}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumVTEPConfig is a cluster-scoped Kubernetes custom resource which declares
// VXLAN Tunnel Endpoint (VTEP) configurations and optionally targets a subset of
// nodes via nodeSelector. It enables dynamic configuration of VTEP endpoints
// without requiring Cilium agent restarts.
//
// The Cilium operator evaluates the nodeSelector of every CiliumVTEPConfig against
// each node and writes the resolved set of VTEP endpoints into that node's
// CiliumVTEPNodeConfig. CiliumVTEPConfig itself carries no status: per-node sync
// state is reported on the per-node CiliumVTEPNodeConfig. This mirrors the
// CiliumBGPClusterConfig -> CiliumBGPNodeConfig pattern.
type CiliumVTEPConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired VTEP configuration.
	//
	// +kubebuilder:validation:Required
	Spec CiliumVTEPConfigSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumVTEPConfigList is a list of CiliumVTEPConfig objects.
type CiliumVTEPConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumVTEPConfig resources.
	Items []CiliumVTEPConfig `json:"items"`
}

// +deepequal-gen=true

// CiliumVTEPConfigSpec defines the desired state of VTEP configuration.
type CiliumVTEPConfigSpec struct {
	// NodeSelector selects the nodes to which this VTEP configuration applies.
	// If nil or empty, the configuration applies to all nodes. The selector is
	// evaluated by the Cilium operator, not the agent.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// VTEPEndpoints is the list of VTEP endpoint configurations.
	// Maximum 8 endpoints are supported due to BPF map size constraints; the real
	// limit is per node across all matching configs, enforced by the operator.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	VTEPEndpoints []VTEPEndpoint `json:"vtepEndpoints"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumvtepnodeconfig",path="ciliumvtepnodeconfigs",scope="Cluster",shortName={cvtepnode}
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumVTEPNodeConfig is node-local VTEP configuration for the Cilium agent.
// Name of the object should be the node name.
// This resource will be created by the Cilium operator and is read-only for the
// users. The operator resolves the VTEP endpoints that apply to the node (by
// evaluating each CiliumVTEPConfig's nodeSelector) and writes them into the Spec.
// The agent running on that node is the sole writer of the Status subresource,
// which it updates only after its local BPF map sync completes.
type CiliumVTEPNodeConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec contains the VTEP endpoints resolved for this node by the operator.
	//
	// +kubebuilder:validation:Required
	Spec CiliumVTEPNodeConfigSpec `json:"spec"`

	// Status is the most recently observed status of the CiliumVTEPNodeConfig,
	// written exclusively by the agent on this node.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumVTEPNodeConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumVTEPNodeConfigList is a list of CiliumVTEPNodeConfig objects.
type CiliumVTEPNodeConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumVTEPNodeConfig resources.
	Items []CiliumVTEPNodeConfig `json:"items"`
}

// +deepequal-gen=true

// CiliumVTEPNodeConfigSpec defines the VTEP endpoints resolved for a node.
type CiliumVTEPNodeConfigSpec struct {
	// VTEPEndpoints is the list of VTEP endpoints the operator resolved for this
	// node from all matching CiliumVTEPConfig objects (after CIDR-conflict
	// resolution). It may be empty if every endpoint that would apply to the node
	// is in conflict.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	VTEPEndpoints []VTEPEndpoint `json:"vtepEndpoints,omitempty"`
}

// +deepequal-gen=true

// VTEPEndpoint defines a single VTEP endpoint configuration.
type VTEPEndpoint struct {
	// Name is a unique identifier for this VTEP endpoint within the configuration.
	// Used for tracking status and managing updates.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// TunnelEndpoint is the IPv4 address of the remote VTEP device.
	// Traffic destined for the CIDR will be encapsulated and sent to this address.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	TunnelEndpoint string `json:"tunnelEndpoint"`

	// CIDR is the destination network prefix that will be routed via this VTEP.
	// Traffic with destinations matching this CIDR will be encapsulated and
	// sent to the TunnelEndpoint.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$`
	CIDR string `json:"cidr"`

	// MAC is the destination MAC address to use when encapsulating traffic
	// destined for this VTEP endpoint.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`
	MAC string `json:"mac"`
}

// +deepequal-gen=false

// CiliumVTEPNodeConfigStatus contains the agent-observed state of the node's VTEP
// configuration.
type CiliumVTEPNodeConfigStatus struct {
	// EndpointCount is the number of VTEP endpoints currently programmed on the node.
	//
	// +kubebuilder:validation:Optional
	EndpointCount int32 `json:"endpointCount,omitempty"`

	// Conditions describe the current state of the node's VTEP configuration.
	//
	// +kubebuilder:validation:Optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// VTEPEndpointStatuses contains per-endpoint sync state for this node.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	VTEPEndpointStatuses []VTEPEndpointStatus `json:"vtepEndpointStatuses,omitempty"`
}

// +deepequal-gen=false

// VTEPEndpointStatus contains the status of a single VTEP endpoint on a node.
type VTEPEndpointStatus struct {
	// Name is the name of the VTEP endpoint.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Synced indicates whether this endpoint is successfully synced to the BPF map.
	//
	// +kubebuilder:validation:Optional
	Synced bool `json:"synced"`

	// LastSyncTime is the last time this endpoint was successfully synced.
	//
	// +kubebuilder:validation:Optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Error contains any error message from the last sync attempt.
	// Empty when the endpoint is successfully synced.
	//
	// +kubebuilder:validation:Optional
	Error string `json:"error,omitempty"`
}

// VTEP condition types
const (
	// VTEPConditionReady indicates all endpoints are successfully synced.
	VTEPConditionReady = "Ready"
)
