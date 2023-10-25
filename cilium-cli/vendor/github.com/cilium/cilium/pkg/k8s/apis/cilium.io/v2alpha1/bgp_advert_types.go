// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// BGPAdvertisementType defines type of advertisement.
//
// Note list of supported advertisements is not exhaustive and can be extended in the future.
// Consumer of this API should be able to handle unknown values.
//
// +kubebuilder:validation:Enum=PodCIDR;CiliumPodIPPool;CiliumLoadBalancerIP
type BGPAdvertisementType string

const (
	// PodCIDRAdvert when configured, Cilium will advertise pod CIDRs to BGP peers.
	PodCIDRAdvert BGPAdvertisementType = "PodCIDR"

	// CiliumPodIPPoolAdvert when configured, Cilium will advertise prefixes from CiliumPodIPPools to BGP peers.
	CiliumPodIPPoolAdvert BGPAdvertisementType = "CiliumPodIPPool"

	// CiliumLoadBalancerIPAdvert when configured, Cilium will advertise load balancer services IPs to BGP peers.
	// The loadBalancerClass for a service must be nil or specify a class supported by Cilium,
	// e.g. "io.cilium/bgp-control-plane".
	//
	// Refer to the following document for additional details regarding load balancer
	// classes: https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class
	CiliumLoadBalancerIPAdvert BGPAdvertisementType = "CiliumLoadBalancerIP"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgpadvertisement",path="ciliumbgpadvertisements",scope="Cluster",shortName={cbgpadvert}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:storageversion

// CiliumBGPAdvertisement is the Schema for the ciliumbgpadvertisements API
type CiliumBGPAdvertisement struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Spec CiliumBGPAdvertisementSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPAdvertisementList contains a list of CiliumBGPAdvertisement
type CiliumBGPAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPAdvertisement.
	Items []CiliumBGPAdvertisement `json:"items"`
}

type CiliumBGPAdvertisementSpec struct {
	// Advertisements is a list of BGP advertisements.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Advertisements []Advertisement `json:"advertisements"`
}

// Advertisement defines which routes Cilium should advertise to BGP peers. Optionally, additional attributes can be
// set to the advertised routes.
type Advertisement struct {
	// AdvertisementType defines type of advertisement which has to be advertised.
	//
	// +kubebuilder:validation:Required
	AdvertisementType BGPAdvertisementType `json:"advertisementType"`

	// Selector is a label selector to select objects of the type specified by AdvertisementType.
	// If not specified, all objects of the type specified by AdvertisementType are selected for advertisement.
	//
	// +kubebuilder:validation:Optional
	Selector *slimv1.LabelSelector `json:"selector,omitempty"`

	// Attributes defines additional attributes to set to the advertised routes.
	// If not specified, no additional attributes are set.
	//
	// +kubebuilder:validation:Optional
	Attributes *CiliumBGPAttributes `json:"attributes,omitempty"`
}

// CiliumBGPAttributes defines additional attributes to set to the advertised NLRIs.
type CiliumBGPAttributes struct {
	// Community sets the community attribute in the route.
	// If not specified, no community attribute is set.
	//
	// +kubebuilder:validation:Optional
	Community *BGPCommunities `json:"community,omitempty"`

	// LocalPreference sets the local preference attribute in the route.
	// If not specified, no local preference attribute is set.
	//
	// +kubebuilder:validation:Optional
	LocalPreference *int64 `json:"localPreference,omitempty"`
}
