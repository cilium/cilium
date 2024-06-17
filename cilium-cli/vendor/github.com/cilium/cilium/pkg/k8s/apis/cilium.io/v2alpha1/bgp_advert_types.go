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
// +kubebuilder:validation:Enum=PodCIDR;CiliumPodIPPool;Service
type BGPAdvertisementType string

const (
	// BGPPodCIDRAdvert when configured, Cilium will advertise pod CIDRs to BGP peers.
	BGPPodCIDRAdvert BGPAdvertisementType = "PodCIDR"

	// BGPCiliumPodIPPoolAdvert when configured, Cilium will advertise prefixes from CiliumPodIPPools to BGP peers.
	BGPCiliumPodIPPoolAdvert BGPAdvertisementType = "CiliumPodIPPool"

	// BGPServiceAdvert when configured, Cilium will advertise service related routes to BGP peers.
	//
	BGPServiceAdvert BGPAdvertisementType = "Service"
)

// BGPServiceAddressType defines type of service address to be advertised.
//
// Note list of supported service addresses is not exhaustive and can be extended in the future.
// Consumer of this API should be able to handle unknown values.
//
// +kubebuilder:validation:Enum=LoadBalancerIP;ClusterIP;ExternalIP
type BGPServiceAddressType string

const (
	// BGPLoadBalancerIPAddr when configured, Cilium will advertise load balancer services IPs to BGP peers.
	// The loadBalancerClass for a service must be nil or specify a class supported by Cilium,
	// e.g. "io.cilium/bgp-control-plane".
	//
	// Refer to the following document for additional details regarding load balancer
	// classes: https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class
	BGPLoadBalancerIPAddr BGPServiceAddressType = "LoadBalancerIP"

	// BGPClusterIPAddr when configured, Cilium will advertise cluster IP prefix of a service to BGP peers.
	// Cluster IP for a service is defined here
	// https://kubernetes.io/docs/concepts/services-networking/service/#type-clusterip
	BGPClusterIPAddr BGPServiceAddressType = "ClusterIP"

	// BGPExternalIPAddr when configured, Cilium will advertise external IP prefix of a service to BGP peers.
	// External IP for a service is defined here
	// https://kubernetes.io/docs/concepts/services-networking/service/#external-ips
	BGPExternalIPAddr BGPServiceAddressType = "ExternalIP"
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
	Advertisements []BGPAdvertisement `json:"advertisements"`
}

// BGPAdvertisement defines which routes Cilium should advertise to BGP peers. Optionally, additional attributes can be
// set to the advertised routes.
type BGPAdvertisement struct {
	// AdvertisementType defines type of advertisement which has to be advertised.
	//
	// +kubebuilder:validation:Required
	AdvertisementType BGPAdvertisementType `json:"advertisementType"`

	// Service defines configuration options for advertisementType service.
	//
	// +kubebuilder:validation:Optional
	Service *BGPServiceOptions `json:"service,omitempty"`

	// Selector is a label selector to select objects of the type specified by AdvertisementType.
	// If not specified, all objects of the type specified by AdvertisementType are selected for advertisement.
	//
	// +kubebuilder:validation:Optional
	Selector *slimv1.LabelSelector `json:"selector,omitempty"`

	// Attributes defines additional attributes to set to the advertised routes.
	// If not specified, no additional attributes are set.
	//
	// +kubebuilder:validation:Optional
	Attributes *BGPAttributes `json:"attributes,omitempty"`
}

// BGPServiceOptions defines the configuration for Service advertisement type.
type BGPServiceOptions struct {
	// Addresses is a list of service address types which needs to be advertised via BGP.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Addresses []BGPServiceAddressType `json:"addresses,omitempty"`
}

// BGPAttributes defines additional attributes to set to the advertised NLRIs.
type BGPAttributes struct {
	// Communities sets the community attributes in the route.
	// If not specified, no community attribute is set.
	//
	// +kubebuilder:validation:Optional
	Communities *BGPCommunities `json:"communities,omitempty"`

	// LocalPreference sets the local preference attribute in the route.
	// If not specified, no local preference attribute is set.
	//
	// +kubebuilder:validation:Optional
	LocalPreference *int64 `json:"localPreference,omitempty"`
}
