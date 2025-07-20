// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumgatewayclassconfig",path="ciliumgatewayclassconfigs",scope="Namespaced",shortName={cgcc}
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`,priority=1
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumGatewayClassConfig is a Kubernetes third-party resource which
// is used to configure Gateways owned by GatewayClass.
type CiliumGatewayClassConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human-readable of a GatewayClass configuration.
	//
	// +kubebuilder:validation:Optional
	Spec CiliumGatewayClassConfigSpec `json:"spec,omitempty"`

	// Status is the status of the policy.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumGatewayClassConfigStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumGatewayClassConfigList is a list of
// CiliumGatewayClassConfig objects.
type CiliumGatewayClassConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumGatewayClassConfigs.
	Items []CiliumGatewayClassConfig `json:"items"`
}

// +deepequal-gen=true

type LoadBalancerSourceRangesPolicyType string

const (
	// LoadBalancerSourceRangesPolicyAllow allows traffic for the given source ranges.
	LoadBalancerSourceRangesPolicyAllow LoadBalancerSourceRangesPolicyType = "Allow"

	// LoadBalancerSourceRangesPolicyDeny denies traffic for the given source ranges.
	LoadBalancerSourceRangesPolicyDeny LoadBalancerSourceRangesPolicyType = "Deny"
)

type ServiceConfig struct {
	// Sets the Service.Spec.Type in generated Service objects to the given value.
	// Only LoadBalancer and NodePort are supported.
	//
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort
	// +kubebuilder:default="LoadBalancer"
	Type corev1.ServiceType `json:"type,omitempty"`

	// Sets the Service.Spec.ExternalTrafficPolicy in generated Service objects to the given value.
	//
	// +optional
	// +kubebuilder:default="Cluster"
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`

	// Sets the Service.Spec.LoadBalancerClass in generated Service objects to the given value.
	//
	// +optional
	LoadBalancerClass *string `json:"loadBalancerClass,omitempty"`

	// Sets the Service.Spec.IPFamilies in generated Service objects to the given value.
	//
	// +listType=atomic
	// +optional
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`

	// Sets the Service.Spec.IPFamilyPolicy in generated Service objects to the given value.
	//
	// +optional
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitempty"`

	// Sets the Service.Spec.AllocateLoadBalancerNodePorts in generated Service objects to the given value.
	//
	// +optional
	AllocateLoadBalancerNodePorts *bool `json:"allocateLoadBalancerNodePorts,omitempty"`

	// Sets the Service.Spec.LoadBalancerSourceRanges in generated Service objects to the given value.
	//
	// +optional
	// +listType=atomic
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// LoadBalancerSourceRangesPolicy defines the policy for the LoadBalancerSourceRanges if the incoming traffic
	// is allowed or denied.
	//
	// +optional
	// +kubebuilder:validation:Enum=Allow;Deny
	// +kubebuilder:default="Allow"
	LoadBalancerSourceRangesPolicy LoadBalancerSourceRangesPolicyType `json:"loadBalancerSourceRangesPolicy,omitempty"`

	// Sets the Service.Spec.TrafficDistribution in generated Service objects to the given value.
	//
	// +optional
	TrafficDistribution *string `json:"trafficDistribution,omitempty"`
}

// CiliumGatewayClassConfigSpec specifies all the configuration options for a
// Cilium managed GatewayClass.
type CiliumGatewayClassConfigSpec struct {
	// Description helps describe a GatewayClass configuration with more details.
	//
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty"`

	// Service specifies the configuration for the generated Service.
	// Note that not all fields from upstream Service.Spec are supported
	//
	// +kubebuilder:validation:Optional
	Service *ServiceConfig `json:"service,omitempty"`
}

// +deepequal-gen=false

// CiliumGatewayClassConfigStatus contains the status of a CiliumGatewayClassConfig.
type CiliumGatewayClassConfigStatus struct {
	// Current service state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}
