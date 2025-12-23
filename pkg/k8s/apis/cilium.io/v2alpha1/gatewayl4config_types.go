// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumgatewayl4config",path="ciliumgatewayl4configs",scope="Namespaced",shortName={cgl4}
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.spec.gatewayRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumGatewayL4Config is a Kubernetes third-party resource which carries
// L4 Gateway listener frontends and weighted backends for LB map programming.
type CiliumGatewayL4Config struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines desired state for L4 Gateway listeners.
	//
	// +kubebuilder:validation:Required
	Spec CiliumGatewayL4ConfigSpec `json:"spec"`

	// Status is the status of the configuration.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumGatewayL4ConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumGatewayL4ConfigList is a list of CiliumGatewayL4Config objects.
type CiliumGatewayL4ConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumGatewayL4Configs.
	Items []CiliumGatewayL4Config `json:"items"`
}

// +deepequal-gen=true

// L4ProtocolType identifies supported L4 protocols for Gateway listeners.
type L4ProtocolType string

const (
	// L4ProtocolTCP identifies TCP listeners.
	L4ProtocolTCP L4ProtocolType = "TCP"
	// L4ProtocolUDP identifies UDP listeners.
	L4ProtocolUDP L4ProtocolType = "UDP"
)

// CiliumGatewayL4ConfigSpec specifies the configuration for L4 Gateway listeners.
type CiliumGatewayL4ConfigSpec struct {
	// GatewayRef references the Gateway that produced this config.
	//
	// +kubebuilder:validation:Required
	GatewayRef CiliumGatewayReference `json:"gatewayRef"`

	// Listeners defines L4 listeners with ports and weighted backends.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Listeners []CiliumGatewayL4Listener `json:"listeners,omitempty"`
}

// CiliumGatewayReference identifies a Gateway by name and namespace.
type CiliumGatewayReference struct {
	// Name is the Gateway name.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the Gateway namespace. If omitted, the namespace of the
	// CiliumGatewayL4Config is used.
	//
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// CiliumGatewayL4Listener defines a single L4 listener and its backends.
type CiliumGatewayL4Listener struct {
	// Name is the Gateway listener name.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Protocol is the listener protocol.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol L4ProtocolType `json:"protocol"`

	// Port is the listener port.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Addresses are IPs assigned to the Gateway for this listener.
	//
	// +kubebuilder:validation:Optional
	// +listType=atomic
	Addresses []string `json:"addresses,omitempty"`

	// Backends is the list of weighted Service backends.
	//
	// +kubebuilder:validation:Optional
	// +listType=atomic
	Backends []CiliumGatewayL4Backend `json:"backends,omitempty"`
}

// CiliumGatewayL4Backend is a weighted backend Service.
type CiliumGatewayL4Backend struct {
	// Name is the Service name.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the Service namespace. If omitted, the Gateway namespace is used.
	//
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// Port is the Service port number.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// Weight defines the relative load-balancing weight.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000000
	Weight *int32 `json:"weight,omitempty"`
}

// +deepequal-gen=false

// CiliumGatewayL4ConfigStatus contains the status of a CiliumGatewayL4Config.
type CiliumGatewayL4ConfigStatus struct {
	// Current status conditions for the config.
	//
	// +kubebuilder:validation:Optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}
