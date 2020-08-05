/*
 * // Copyright 2020 Authors of Cilium
 * //
 * // Licensed under the Apache License, Version 2.0 (the "License");
 * // you may not use this file except in compliance with the License.
 * // You may obtain a copy of the License at
 * //
 * //     http://www.apache.org/licenses/LICENSE-2.0
 * //
 * // Unless required by applicable law or agreed to in writing, software
 * // distributed under the License is distributed on an "AS IS" BASIS,
 * // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * // See the License for the specific language governing permissions and
 * // limitations under the License.
 */

package v2

import (
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="localredirectpolicy",path="localredirectpolicies",scope="Namespaced",shortName={lrp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date

// LocalRedirectPolicy is a Kubernetes Custom Resource that contains a
// specification to redirect traffic locally within a node.
type LocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Specification of the desired behavior of the local redirect policy
	Spec LocalRedirectPolicySpec `json:"spec,omitempty"`

	// Most recent status of the local redirect policy
	// Read-only
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status LocalRedirectPolicyStatus `json:"status"`
}

type L3L4Info struct {
	// ToIP is a destination IP address for traffic to be redirected.
	//
	// Example:
	// Any traffic destined to '169.254.169.254' is redirected.
	//
	// +kubebuilder:validation:Optional
	ToIP string `json:"toIP,omitempty"`

	// ToPort is a destination port for traffic to be redirected.
	//
	// Example:
	// Any traffic destined to port '53' is redirected.
	//
	// +kubebuilder:validation:Optional
	ToPort string `json:"toPort,omitempty"`

	// L4Proto is layer 4 protocol number for traffic to be redirected.
	//
	// +kubebuilder:validation:Enum=TCP;UDP
	L4Proto api.L4Proto `json:"L4Proto,omitempty"`
}

// RedirectFrom is a frontend configuration that determines traffic that needs to be redirected.
// The configuration must be specified using an L3L4 tuple or a Kubernetes service.
type RedirectFrom struct {
	// ToL3L4Info is a destination tuple {IP, port, protocol} that identifies traffic
	// to be redirected.
	//
	// +kubebuilder:validation:Optional
	ToL3L4 L3L4Info `json:"L3L4Info,omitempty"`

	// ToService is a destination Kubernetes service that identifies traffic
	// to be redirected. The service namespace must match the namespace of the
	// parent Local Redirect Policy.
	//
	// Example:
	// When this field is populated with 'serviceName:myService', all the traffic
	// destined to the cluster IP of this service at the service port will be redirected.
	//
	// +kubebuilder:validation:Optional
	ToService api.Service `json:"toService,omitempty"`
}

// RedirectTo is a backend configuration that determines where traffic needs to be redirected to.
type RedirectTo struct {
	// LocalEndpointSelector selects a node local endpoint where traffic is redirected to.
	// Only one backend endpoint can be selected.
	//
	// +kubebuilder:validation:Required
	LocalEndpointSelector api.EndpointSelector `json:"localEndpointSelector,omitempty"`
}

// LocalRedirectPolicySpec specifies the configurations for redirecting traffic
// within a node.
// Both RedirectFrom and RedirectTo configurations need to be specified for a policy
// to take effect.
//
// +kubebuilder:validation:Type=object
type LocalRedirectPolicySpec struct {
	// RedirectFrom specifies frontend configuration to redirect traffic from.
	// It can not be empty.
	//
	// +kubebuilder:validation:Required
	RedirectFrom RedirectFrom `json:"redirectFrom,omitempty"`

	// RedirectTo specifies backend configuration to redirect traffic to.
	// It can not be empty.
	//
	// +kubebuilder:validation:Required
	RedirectTo RedirectTo `json:"redirectTo,omitempty"`

	// Description can be used by the creator of the policy to describe the
	// purpose of this policy.
	//
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
}

// LocalRedirectPolicyStatus is the status of a Local Redirect Policy.
type LocalRedirectPolicyStatus struct {
	// TODO Define status(aditi)
	//
	// +kubebuilder:validation:Type=object
	OK bool `json:"ok,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// LocalRedirectPolicyList is a list of LocalRedirectPolicy objects.
type LocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of LocalRedirectPolicy
	Items []LocalRedirectPolicy `json:"items"`
}
