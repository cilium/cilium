//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgploadbalancerippool",path="ciliumbgploadbalancerippools",scope="Cluster",shortName={bgppools}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumBGPLoadBalancerIPPool is a Kubernetes third-party resource which
// instructs the BGP control plane to allocate and advertise IPs for Services
// of type LoadBalancer.
type CiliumBGPLoadBalancerIPPool struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is a human readable description for a BGP load balancer
	// ip pool.
	//
	// +kubebuilder:validation:Optional
	Spec CiliumBGPLoadBalancerIPPoolSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPPeeringPolicyLlist is a list of
// CiliumBGPPeeringPolicy objects.
type CiliumBGPLoadBalancerIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeeringPolicies.
	Items []CiliumBGPLoadBalancerIPPool `json:"items"`
}

// CiliumBGPLoadBalancerIPPoolSpec is a human readable description for
// a BGP load balancer ip pool.
type CiliumBGPLoadBalancerIPPoolSpec struct {
	// NodeSelector selects a group of nodes which will advertise
	// the presence of any LoadBalancers allocated from this IP pool.
	//
	// If nil all nodes will advertise the presence of any LoadBalancer
	// allocated an IP from this pool.
	//
	// +kubebuilder:validation:Optional
	// +deepequal-gen=true
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector"`
	// The CIDR block of IPs to allocate from.
	//
	// +kubebuilder:validation:Format=cidr
	// +kubebuilder:validation:Required
	Prefix string `json:"prefix"`
	// LBSelector will determine if a created LoadBalancer is
	// allocated an IP from this pool.
	//
	// +kubebuilder:validation:Optional
	LBSelector *slimv1.LabelSelector `json:"lbSelector"`
	// Default determines if this is the default IP pool for
	// allocating from when LBSelector is nil or empty.
	//
	// +kubebuilder:validation:Optional
	Default bool `json:"default"`
}
