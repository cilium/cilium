// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// BGPAutoDiscoveryMode defines type of mode to discovery bgp peers
//
// Note list of supported auto discovery modes is not exhaustive and can be extended in the future.
//
// +kubebuilder:validation:Enum=DefaultGateway;Unnumbered
type BGPAutoDiscoveryMode string

const (
	// BGPDefaultGatewayMode when configured, Cilium will discover bgp peers using default gateway
	BGPDefaultGatewayMode BGPAutoDiscoveryMode = "DefaultGateway"

	// BGPUnnumberedMode when configured, Cilium peers over an interface without a
	// configured peer address (BGP unnumbered). gobgp discovers the peer's IPv6
	// link-local address on that interface via IPv6 ND. The interface is either
	// named explicitly, or discovered as the one the default route egresses.
	BGPUnnumberedMode BGPAutoDiscoveryMode = "Unnumbered"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgpclusterconfig",path="ciliumbgpclusterconfigs",scope="Cluster",shortName={cbgpcluster}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumBGPClusterConfig is the Schema for the CiliumBGPClusterConfig API
type CiliumBGPClusterConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired cluster configuration of the BGP control plane.
	//
	// +kubebuilder:validation:Required
	Spec CiliumBGPClusterConfigSpec `json:"spec"`

	// Status is a running status of the cluster configuration
	//
	// +kubebuilder:validation:Optional
	Status CiliumBGPClusterConfigStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPClusterConfigList is a list of CiliumBGPClusterConfig objects.
type CiliumBGPClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPClusterConfig.
	Items []CiliumBGPClusterConfig `json:"items"`
}

type CiliumBGPClusterConfigSpec struct {
	// NodeSelector selects a group of nodes where this BGP Cluster
	// config applies.
	// If empty / nil this config applies to all nodes.
	//
	// +kubebuilder:validation:Optional
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// A list of CiliumBGPInstance(s) which instructs
	// the BGP control plane how to instantiate virtual BGP routers.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	BGPInstances []CiliumBGPInstance `json:"bgpInstances"`
}

type CiliumBGPInstance struct {
	// Name is the name of the BGP instance. It is a unique identifier for the BGP instance
	// within the cluster configuration.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// LocalASN is the ASN of this BGP instance.
	// Supports extended 32bit ASNs.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	LocalASN *int64 `json:"localASN,omitempty"`

	// LocalPort is the port on which the BGP daemon listens for incoming connections.
	//
	// If not specified, BGP instance will not listen for incoming connections.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	LocalPort *int32 `json:"localPort,omitempty"`

	// Peers is a list of neighboring BGP peers for this virtual router
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=name
	Peers []CiliumBGPPeer `json:"peers,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!has(self.peerInterface) || !has(self.peerAddress) || self.peerAddress.startsWith('fe80:') || self.peerAddress.startsWith('FE80:')",message="peerAddress must be an IPv6 link-local address (fe80::/10) when peerInterface is set"
// +kubebuilder:validation:XValidation:rule="has(self.peerAddress) || has(self.autoDiscovery)",message="one of peerAddress or autoDiscovery must be set"
type CiliumBGPPeer struct {
	// Name is the name of the BGP peer. It is a unique identifier for the peer within the BGP instance.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// PeerAddress is the IP address of the neighbor.
	// Supports IPv4 and IPv6 addresses.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern=`((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))`
	PeerAddress *string `json:"peerAddress,omitempty"`

	// PeerASN is the ASN of the peer BGP router.
	// Supports extended 32bit ASNs.
	//
	// If peerASN is 0, the BGP OPEN message validation of ASN will be disabled and
	// ASN will be determined based on peer's OPEN message.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:default=0
	PeerASN *int64 `json:"peerASN,omitempty"`

	// AutoDiscovery is the configuration for auto-discovery of the peer address.
	//
	// +kubebuilder:validation:Optional
	AutoDiscovery *BGPAutoDiscovery `json:"autoDiscovery,omitempty"`

	// PeerInterface is the name of the local network interface used to reach
	// the peer. It must be set together with an IPv6 link-local peerAddress
	// (fe80::/10): the BGP session is established to that address over the named
	// interface (the interface is encoded as an IPv6 zone identifier).
	//
	// For BGP unnumbered peering (an interface with no configured peer address),
	// use autoDiscovery with mode Unnumbered instead of peerInterface.
	//
	// Interface naming may differ across nodes in a heterogeneous fleet; in that
	// case use CiliumBGPNodeConfigOverride to set peerInterface per node.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	PeerInterface *string `json:"peerInterface,omitempty"`

	// PeerConfigRef is a reference to a peer configuration resource.
	// If not specified, the default BGP configuration is used for this peer.
	//
	// +kubebuilder:validation:Optional
	PeerConfigRef *PeerConfigReference `json:"peerConfigRef,omitempty"`
}

// AutoDiscovery is the configuration for auto-discovery of the peer address.
//
// +kubebuilder:validation:XValidation:rule="self.mode != 'DefaultGateway' || has(self.defaultGateway)",message="defaultGateway must be set when mode is DefaultGateway"
// +kubebuilder:validation:XValidation:rule="self.mode != 'Unnumbered' || (has(self.unnumbered) != has(self.defaultGateway))",message="exactly one of unnumbered or defaultGateway must be set when mode is Unnumbered"
type BGPAutoDiscovery struct {
	// mode is the mode of the auto-discovery.
	//
	// +kubebuilder:validation:Required
	Mode BGPAutoDiscoveryMode `json:"mode"`

	// defaultGateway is the configuration for discovery based on the default
	// route of an address family.
	//
	// With mode DefaultGateway, the gateway address of that default route is
	// used as the peer address. With mode Unnumbered, only the interface the
	// default route egresses is used - see DefaultGateway.
	//
	// +kubebuilder:validation:Optional
	DefaultGateway *DefaultGateway `json:"defaultGateway,omitempty"`

	// unnumbered is the configuration for BGP unnumbered peering over an
	// explicitly named interface with no configured peer address. Only valid
	// with mode Unnumbered, where it is an alternative to defaultGateway.
	//
	// +kubebuilder:validation:Optional
	Unnumbered *BGPUnnumbered `json:"unnumbered,omitempty"`
}

// DefaultGateway is the configuration for discovery based on the default route
// of an address family.
type DefaultGateway struct {
	// addressFamily is the address family whose default route is followed. If
	// the node has more than one default route in that family, the one with the
	// lowest metric is used.
	//
	// With mode Unnumbered this selects which routing table to consult, not the
	// address family the BGP session is established over: only the interface the
	// default route egresses is taken from the route, and the peer is then
	// reached over that interface at the IPv6 link-local address discovered via
	// IPv6 ND. Following the IPv4 default route to establish an unnumbered
	// (IPv6 link-local) session is therefore a valid configuration.
	//
	// +kubebuilder:validation:Enum=ipv4;ipv6
	// +kubebuilder:validation:Required
	AddressFamily string `json:"addressFamily"`
}

// BGPUnnumbered is the configuration for BGP unnumbered peering over an
// explicitly named interface. The peer's IPv6 link-local address is discovered
// on that interface via IPv6 ND, so no peer address is configured.
//
// Interface naming may differ across nodes in a heterogeneous fleet. In that
// case, use autoDiscovery mode Unnumbered with defaultGateway instead, which
// discovers the interface on each node from its default route.
type BGPUnnumbered struct {
	// interface is the name of the local network interface used to reach the
	// peer.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Interface string `json:"interface"`
}

// PeerConfigReference is a reference to a peer configuration resource.
type PeerConfigReference struct {
	// Name is the name of the peer config resource.
	// Name refers to the name of a Kubernetes object (typically a CiliumBGPPeerConfig).
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

type CiliumBGPClusterConfigStatus struct {
	// The current conditions of the CiliumBGPClusterConfig
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for CiliumBGPClusterConfig. When you add a new condition, don't
// forget to update the AllBGPClusterConfigConditions list as well.
const (
	// Node selector selects nothing
	BGPClusterConfigConditionNoMatchingNode = "cilium.io/NoMatchingNode"
	// Referenced peer configs are missing
	BGPClusterConfigConditionMissingPeerConfigs = "cilium.io/MissingPeerConfigs"
	// ClusterConfig with conflicting nodeSelector present
	BGPClusterConfigConditionConflictingClusterConfigs = "cilium.io/ConflictingClusterConfig"
)

var AllBGPClusterConfigConditions = []string{
	BGPClusterConfigConditionNoMatchingNode,
	BGPClusterConfigConditionMissingPeerConfigs,
	BGPClusterConfigConditionConflictingClusterConfigs,
}
