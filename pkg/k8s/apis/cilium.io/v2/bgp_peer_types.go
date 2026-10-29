// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	// DefaultBGPPeerPort defines the TCP port number of a CiliumBGPNeighbor when PeerPort is unspecified.
	DefaultBGPPeerPort = 179
	// DefaultBGPEBGPMultihopTTL defines the default value for the TTL value used in BGP packets sent to the eBGP neighbors.
	DefaultBGPEBGPMultihopTTL = 1
	// DefaultBGPConnectRetryTimeSeconds defines the default initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	DefaultBGPConnectRetryTimeSeconds = 120
	// DefaultBGPHoldTimeSeconds defines the default initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	DefaultBGPHoldTimeSeconds = 90
	// DefaultBGPKeepAliveTimeSeconds defines the default initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	DefaultBGPKeepAliveTimeSeconds = 30
	// DefaultBGPGRRestartTimeSeconds defines default Restart Time for graceful restart (RFC 4724, section 4.2)
	DefaultBGPGRRestartTimeSeconds = 120
	// DefaultBGPTCPAOAlgorithm defines the default TCP-AO MAC algorithm used when a key does not specify one.
	DefaultBGPTCPAOAlgorithm = BGPTCPAOAlgorithmHMACSHA1_96
	// DefaultBGPTCPAOSecretKeyPrefix is the prefix of the default Secret data key holding the master key
	// of a TCP-AO key. The default Secret data key is "<prefix><sendID>", e.g. "key-1".
	DefaultBGPTCPAOSecretKeyPrefix = "key-"
)

// BGPTCPAOAlgorithm is the Message Authentication Code (MAC) algorithm of a TCP-AO key.
//
// +kubebuilder:validation:Enum=hmac-sha-1-96;aes-128-cmac-96;hmac-sha-256-96;hmac-sha-256-128
type BGPTCPAOAlgorithm string

const (
	// BGPTCPAOAlgorithmHMACSHA1_96 is the HMAC-SHA-1-96 algorithm (RFC 5926, mandatory to implement).
	BGPTCPAOAlgorithmHMACSHA1_96 BGPTCPAOAlgorithm = "hmac-sha-1-96"
	// BGPTCPAOAlgorithmAES128CMAC_96 is the AES-128-CMAC-96 algorithm (RFC 5926, mandatory to implement).
	BGPTCPAOAlgorithmAES128CMAC_96 BGPTCPAOAlgorithm = "aes-128-cmac-96"
	// BGPTCPAOAlgorithmHMACSHA256_96 is the HMAC-SHA-256 algorithm truncated to a 96-bit MAC.
	BGPTCPAOAlgorithmHMACSHA256_96 BGPTCPAOAlgorithm = "hmac-sha-256-96"
	// BGPTCPAOAlgorithmHMACSHA256_128 is the HMAC-SHA-256 algorithm truncated to a 128-bit MAC.
	BGPTCPAOAlgorithmHMACSHA256_128 BGPTCPAOAlgorithm = "hmac-sha-256-128"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumBGPPeerConfigList is a list of CiliumBGPPeer objects.
type CiliumBGPPeerConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumBGPPeer.
	Items []CiliumBGPPeerConfig `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgppeerconfig",path="ciliumbgppeerconfigs",scope="Cluster",shortName={cbgppeer}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

type CiliumBGPPeerConfig struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the specification of the desired behavior of the CiliumBGPPeerConfig.
	// +kubebuilder:validation:Required
	Spec CiliumBGPPeerConfigSpec `json:"spec"`

	// Status is the running status of the CiliumBGPPeerConfig
	//
	// +kubebuilder:validation:Optional
	Status CiliumBGPPeerConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!(has(self.authSecretRef) && has(self.tcpAO))", message="authSecretRef (TCP MD5) and tcpAO (TCP-AO) are mutually exclusive"
type CiliumBGPPeerConfigSpec struct {
	// Transport defines the BGP transport parameters for the peer.
	//
	// If not specified, the default transport parameters are used.
	//
	// +kubebuilder:validation:Optional
	Transport *CiliumBGPTransport `json:"transport,omitempty"`

	// Timers defines the BGP timers for the peer.
	//
	// If not specified, the default timers are used.
	//
	// +kubebuilder:validation:Optional
	Timers *CiliumBGPTimers `json:"timers,omitempty"`

	// AuthSecretRef is the name of the secret to use to fetch a TCP
	// authentication password for this peer.
	//
	// If not specified, no authentication is used.
	//
	// +kubebuilder:validation:Optional
	AuthSecretRef *string `json:"authSecretRef,omitempty"`

	// TCPAO defines the TCP Authentication Option (RFC 5925) configuration
	// for the sessions with the peers which reference this configuration.
	// TCP-AO is mutually exclusive with the TCP MD5 password (AuthSecretRef).
	//
	// If not specified, TCP-AO is not used.
	//
	// +kubebuilder:validation:Optional
	TCPAO *CiliumBGPTCPAO `json:"tcpAO,omitempty"`

	// GracefulRestart defines graceful restart parameters which are negotiated
	// with this peer.
	//
	// If not specified, the graceful restart capability is disabled.
	//
	// +kubebuilder:validation:Optional
	GracefulRestart *CiliumBGPNeighborGracefulRestart `json:"gracefulRestart,omitempty"`

	// EBGPMultihopTTL controls the multi-hop feature for eBGP peers.
	// Its value defines the Time To Live (TTL) value used in BGP
	// packets sent to the peer.
	//
	// If not specified, EBGP multihop is disabled. This field is ignored for iBGP neighbors.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:default=1
	EBGPMultihop *int32 `json:"ebgpMultihop,omitempty"`

	// Families, if provided, defines a set of AFI/SAFIs the speaker will
	// negotiate with it's peer.
	//
	// If not specified, the default families of IPv6/unicast and IPv4/unicast will be created.
	//
	// +kubebuilder:validation:Optional
	Families []CiliumBGPFamilyWithAdverts `json:"families,omitempty"`
}

type CiliumBGPPeerConfigStatus struct {
	// The current conditions of the CiliumBGPPeerConfig
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions for CiliumBGPPeerConfig. When you add a new condition, don't
// forget to update the below AllBGPPeerConfigConditions list as well.
const (
	// Referenced auth secret is missing
	BGPPeerConfigConditionMissingAuthSecret = "cilium.io/MissingAuthSecret"
)

var AllBGPPeerConfigConditions = []string{
	BGPPeerConfigConditionMissingAuthSecret,
}

// CiliumBGPFamily represents a AFI/SAFI address family pair.
type CiliumBGPFamily struct {
	// Afi is the Address Family Identifier (AFI) of the family.
	//
	// +kubebuilder:validation:Enum=ipv4;ipv6;l2vpn;ls;opaque
	// +kubebuilder:validation:Required
	Afi string `json:"afi"`

	// Safi is the Subsequent Address Family Identifier (SAFI) of the family.
	//
	// +kubebuilder:validation:Enum=unicast;multicast;mpls_label;encapsulation;vpls;evpn;ls;sr_policy;mup;mpls_vpn;mpls_vpn_multicast;route_target_constraints;flowspec_unicast;flowspec_vpn;key_value
	// +kubebuilder:validation:Required
	Safi string `json:"safi"`
}

// CiliumBGPFamilyWithAdverts represents a AFI/SAFI address family pair along with reference to BGP Advertisements.
type CiliumBGPFamilyWithAdverts struct {
	CiliumBGPFamily `json:",inline"`

	// Advertisements selects group of BGP Advertisement(s) to advertise for this family.
	//
	// If not specified, no advertisements are sent for this family.
	//
	// +kubebuilder:validation:Optional
	Advertisements *slimv1.LabelSelector `json:"advertisements,omitempty"`
}

// CiliumBGPTransport defines the BGP transport parameters for the peer.
type CiliumBGPTransport struct {
	// PeerPort is the peer port to be used for the BGP session.
	//
	// If not specified, defaults to TCP port 179.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=179
	PeerPort *int32 `json:"peerPort,omitempty"`

	// SourceInterface is the name of a local interface, which IP address will be used
	// as the source IP address for the BGP session. The interface must not have more than one
	// non-loopback, non-multicast and non-link-local-IPv6 address per address family.
	//
	// If not specified, or if the provided interface is not found or missing a usable IP address,
	// the source IP address will be auto-detected based on the egress interface.
	//
	// +kubebuilder:validation:Optional
	SourceInterface *string `json:"sourceInterface,omitempty"`
}

func (t *CiliumBGPTransport) SetDefaults() {
	if t.PeerPort == nil || *t.PeerPort == 0 {
		t.PeerPort = ptr.To[int32](DefaultBGPPeerPort)
	}
}

// CiliumBGPTimers defines timers configuration for a BGP peer.
//
// +kubebuilder:validation:XValidation:rule="self.keepAliveTimeSeconds <= self.holdTimeSeconds", message="keepAliveTimeSeconds can not be larger than holdTimeSeconds"
type CiliumBGPTimers struct {
	// ConnectRetryTimeSeconds defines the initial value for the BGP ConnectRetryTimer (RFC 4271, Section 8).
	//
	// If not specified, defaults to 120 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default=120
	ConnectRetryTimeSeconds *int32 `json:"connectRetryTimeSeconds,omitempty"`

	// HoldTimeSeconds defines the initial value for the BGP HoldTimer (RFC 4271, Section 4.2).
	// Updating this value will cause a session reset.
	//
	// If not specified, defaults to 90 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=3
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=90
	HoldTimeSeconds *int32 `json:"holdTimeSeconds,omitempty"`

	// KeepaliveTimeSeconds defines the initial value for the BGP KeepaliveTimer (RFC 4271, Section 8).
	// It can not be larger than HoldTimeSeconds. Updating this value will cause a session reset.
	//
	// If not specified, defaults to 30 seconds.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=30
	KeepAliveTimeSeconds *int32 `json:"keepAliveTimeSeconds,omitempty"`
}

func (t *CiliumBGPTimers) SetDefaults() {
	if t.ConnectRetryTimeSeconds == nil || *t.ConnectRetryTimeSeconds == 0 {
		t.ConnectRetryTimeSeconds = ptr.To[int32](DefaultBGPConnectRetryTimeSeconds)
	}

	if t.HoldTimeSeconds == nil || *t.HoldTimeSeconds == 0 {
		t.HoldTimeSeconds = ptr.To[int32](DefaultBGPHoldTimeSeconds)
	}

	if t.KeepAliveTimeSeconds == nil || *t.KeepAliveTimeSeconds == 0 {
		t.KeepAliveTimeSeconds = ptr.To[int32](DefaultBGPKeepAliveTimeSeconds)
	}
}

type CiliumBGPNeighborGracefulRestart struct {
	// Enabled flag, when set enables graceful restart capability.
	//
	// +kubebuilder:validation:Required
	Enabled bool `json:"enabled"`

	// RestartTimeSeconds is the estimated time it will take for the BGP
	// session to be re-established with peer after a restart.
	// After this period, peer will remove stale routes. This is
	// described RFC 4724 section 4.2.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4095
	// +kubebuilder:default=120
	RestartTimeSeconds *int32 `json:"restartTimeSeconds,omitempty"`
}

func (gr *CiliumBGPNeighborGracefulRestart) SetDefaults() {
	if gr.RestartTimeSeconds == nil || *gr.RestartTimeSeconds == 0 {
		gr.RestartTimeSeconds = ptr.To[int32](DefaultBGPGRRestartTimeSeconds)
	}
}

// CiliumBGPTCPAO defines the TCP Authentication Option (RFC 5925) keychain
// used to authenticate the BGP sessions with the peer.
//
// The non-sensitive parameters of the keys (key identifiers, algorithm) are
// defined here, while the master keys themselves are read from a Kubernetes
// Secret in the BGP secrets namespace.
//
// +kubebuilder:validation:XValidation:rule="!has(self.sendKeyID) || self.keys.exists(k, k.sendID == self.sendKeyID)", message="sendKeyID must match the sendID of one of the keys"
// +kubebuilder:validation:XValidation:rule="self.keys.all(k, self.keys.exists_one(o, o.receiveID == k.receiveID))", message="receiveID must be unique across the keys"
type CiliumBGPTCPAO struct {
	// SecretRef is the name of the Secret in the BGP secrets namespace which
	// holds the master keys of the keychain. Each key of the keychain reads
	// its master key from the Secret data entry named by its SecretKey field.
	//
	// If the Secret or any of the referenced data entries does not exist,
	// the peer is not configured until they become available.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SecretRef string `json:"secretRef"`

	// SendKeyID selects the preferred key (by its SendID) used to
	// authenticate the segments sent to the peer. New sessions are
	// established using this key. On an established session, changing this
	// field to another key of the keychain requests the peer to switch to
	// the new key (via the RNextKeyID of the TCP-AO option) without resetting
	// the BGP session; the segments sent to the peer are authenticated with
	// the new key once the peer requests it in turn, as defined by RFC 5925.
	//
	// If not specified, the key with the lowest SendID is used.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	SendKeyID *int32 `json:"sendKeyID,omitempty"`

	// Keys is the list of the keys of the keychain. All keys are installed
	// on the session, so the peer can use any of them to authenticate the
	// segments it sends. Keys can be added to and removed from the keychain
	// without resetting the BGP session, as long as the keys in use on the
	// session (the key selected by SendKeyID, and the keys currently used by
	// either side to authenticate the segments it sends) stay unchanged.
	// Changing the master key or any other parameter of a key in use, or
	// removing it, resets the BGP session.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=sendID
	Keys []CiliumBGPTCPAOKey `json:"keys"`
}

// CiliumBGPTCPAOKey defines a single key of a TCP-AO keychain.
type CiliumBGPTCPAOKey struct {
	// SendID is the KeyID carried in the TCP-AO option of the segments
	// authenticated with this key. It must match the ReceiveID of the
	// corresponding key configured on the peer.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	SendID int32 `json:"sendID"`

	// ReceiveID is the KeyID expected in the TCP-AO option of the segments
	// received from the peer that are authenticated with this key. It must
	// match the SendID of the corresponding key configured on the peer.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	ReceiveID int32 `json:"receiveID"`

	// Algorithm is the Message Authentication Code (MAC) algorithm of the key.
	//
	// If not specified, defaults to hmac-sha-1-96.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=hmac-sha-1-96
	Algorithm BGPTCPAOAlgorithm `json:"algorithm,omitempty"`

	// ExcludeTCPOptions, when set, excludes the TCP options from the data
	// covered by the MAC (RFC 5925, section 3.1). It must match the
	// configuration of the corresponding key on the peer.
	//
	// If not specified, defaults to false.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	ExcludeTCPOptions bool `json:"excludeTCPOptions,omitempty"`

	// SecretKey is the name of the data entry in the Secret referenced by
	// SecretRef that holds the master key of this key. The master key must
	// be 1 to 80 bytes long.
	//
	// If not specified, defaults to "key-<sendID>", e.g. "key-1".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinLength=1
	SecretKey string `json:"secretKey,omitempty"`
}

func (t *CiliumBGPTCPAO) SetDefaults() {
	for i := range t.Keys {
		t.Keys[i].SetDefaults()
	}
	if t.SendKeyID == nil && len(t.Keys) > 0 {
		lowest := t.Keys[0].SendID
		for _, k := range t.Keys[1:] {
			lowest = min(lowest, k.SendID)
		}
		t.SendKeyID = ptr.To(lowest)
	}
}

func (k *CiliumBGPTCPAOKey) SetDefaults() {
	if k.Algorithm == "" {
		k.Algorithm = DefaultBGPTCPAOAlgorithm
	}
	if k.SecretKey == "" {
		k.SecretKey = DefaultBGPTCPAOSecretKeyPrefix + strconv.Itoa(int(k.SendID))
	}
}

func (p *CiliumBGPPeerConfigSpec) SetDefaults() {
	if p == nil {
		return
	}

	if p.Transport == nil {
		p.Transport = &CiliumBGPTransport{}
	}
	p.Transport.SetDefaults()

	if p.Timers == nil {
		p.Timers = &CiliumBGPTimers{}
	}
	p.Timers.SetDefaults()

	if p.EBGPMultihop == nil {
		p.EBGPMultihop = ptr.To[int32](DefaultBGPEBGPMultihopTTL)
	}

	if p.GracefulRestart == nil {
		p.GracefulRestart = &CiliumBGPNeighborGracefulRestart{}
	}
	p.GracefulRestart.SetDefaults()

	if p.TCPAO != nil {
		p.TCPAO.SetDefaults()
	}

	if len(p.Families) == 0 {
		p.Families = []CiliumBGPFamilyWithAdverts{
			{
				CiliumBGPFamily: CiliumBGPFamily{
					Afi:  "ipv6",
					Safi: "unicast",
				},
			},
			{
				CiliumBGPFamily: CiliumBGPFamily{
					Afi:  "ipv4",
					Safi: "unicast",
				},
			},
		}
	}
}
