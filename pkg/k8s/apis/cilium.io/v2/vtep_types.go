// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumvtepconfig",path="ciliumvtepconfigs",scope="Cluster",shortName={cvtep}
// +kubebuilder:printcolumn:JSONPath=".status.endpointCount",name="Endpoints",type=integer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumVTEPConfig is a Kubernetes custom resource which defines
// VXLAN Tunnel Endpoint (VTEP) configurations for the cluster.
// It enables dynamic configuration of VTEP endpoints without
// requiring Cilium agent restarts.
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

	// Status contains the observed state of the VTEP configuration.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumVTEPConfigStatus `json:"status,omitempty"`
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
	// Endpoints is the list of VTEP endpoint configurations.
	// Maximum 8 endpoints are supported due to BPF map size constraints.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	Endpoints []VTEPEndpoint `json:"endpoints"`

	// CIDRMask is the network mask used for VTEP CIDR lookups in the BPF map.
	// This mask is applied to destination IPs to determine which VTEP endpoint
	// should handle the traffic. Defaults to "255.255.255.0" if not specified.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	// +kubebuilder:default="255.255.255.0"
	CIDRMask string `json:"cidrMask,omitempty"`
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

// CiliumVTEPConfigStatus contains the observed state of VTEP configuration.
type CiliumVTEPConfigStatus struct {
	// EndpointCount is the number of VTEP endpoints currently configured.
	//
	// +kubebuilder:validation:Optional
	EndpointCount int `json:"endpointCount,omitempty"`

	// Conditions describe the current state of the VTEP configuration.
	//
	// +kubebuilder:validation:Optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// EndpointStatuses contains per-endpoint status information.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	EndpointStatuses []VTEPEndpointStatus `json:"endpointStatuses,omitempty"`
}

// +deepequal-gen=false

// VTEPEndpointStatus contains the status of a single VTEP endpoint.
type VTEPEndpointStatus struct {
	// Name is the name of the VTEP endpoint.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Synced indicates whether this endpoint is successfully synced to the BPF map.
	//
	// +kubebuilder:validation:Optional
	Synced bool `json:"synced,omitempty"`

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

	// VTEPConditionEndpointsValid indicates all endpoint configurations are valid.
	VTEPConditionEndpointsValid = "EndpointsValid"

	// VTEPConditionBPFMapSynced indicates BPF map entries match desired state.
	VTEPConditionBPFMapSynced = "BPFMapSynced"

	// VTEPConditionRoutesConfigured indicates Linux routes for VTEPs are configured.
	VTEPConditionRoutesConfigured = "RoutesConfigured"
)
