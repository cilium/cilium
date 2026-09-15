// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// Identity represents the node identity of a node.
type Identity struct {
	Name    string
	Cluster string
}

// String returns the string representation on NodeIdentity.
func (nn Identity) String() string {
	return GetKeyNodeName(nn.Cluster, nn.Name)
}

// Node contains the nodes name, the list of addresses to this address
//
// +k8s:deepcopy-gen=true
// +deepequal-gen=true
type Node struct {
	// Name is the name of the node. This is typically the hostname of the node.
	Name string

	// Cluster is the name of the cluster the node is associated with
	Cluster string

	IPAddresses []Address

	// IPv4AllocCIDR if set, is the IPv4 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv4AllocCIDR Prefix

	// IPv4SecondaryAllocCIDRs contains additional IPv4 CIDRs from which this
	// node allocates IPs for its local endpoints from
	IPv4SecondaryAllocCIDRs []Prefix

	// IPv6AllocCIDR if set, is the IPv6 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv6AllocCIDR Prefix

	// IPv6SecondaryAllocCIDRs contains additional IPv6 CIDRs from which this
	// node allocates IPs for its local endpoints from
	IPv6SecondaryAllocCIDRs []Prefix

	// IPv4HealthIP if set, this is the IPv4 address of the
	// cilium-health endpoint located on the node.
	IPv4HealthIP iputil.Addr

	// IPv6HealthIP if set, this is the IPv6 address of the
	// cilium-health endpoint located on the node.
	IPv6HealthIP iputil.Addr

	// IPv4IngressIP if set, this is the IPv4 address of the
	// Ingress listener on the node.
	IPv4IngressIP iputil.Addr

	// IPv6IngressIP if set, this is the IPv6 address of the
	// Ingress listener located on the node.
	IPv6IngressIP iputil.Addr

	// ClusterID is the unique identifier of the cluster
	ClusterID uint32

	// Source is the source where the node configuration was generated / created.
	Source source.Source

	// Key index used for transparent encryption or 0 for no encryption
	EncryptionKey uint8

	// Node labels
	Labels map[string]string

	// Node annotations
	Annotations map[string]string

	// WireguardPubKey is the WireGuard public key of this node
	WireguardPubKey string

	// BootID is a unique node identifier generated on boot
	BootID string
}

// Fullname returns the node's full name including the cluster name if a
// cluster name value other than the default value has been specified
func (n *Node) Fullname() string {
	if n.Cluster != defaults.ClusterName {
		return n.GetKeyName()
	}

	return n.Name
}

// Address is a node address which contains an IP and the address type.
//
// IP is always stored unmapped, i.e. an IPv4 address is held as a 4-byte
// [netip.Addr] and never as its IPv4-mapped IPv6 form. Build addresses with
// [NewAddress], which enforces this, rather than with a struct literal: the
// readers of IPAddresses compare addresses with == and derive prefixes from
// their bit length, so a mapped value would silently compare unequal to every
// other copy of the same address and yield a /128 prefix for an IPv4 address.
//
// +k8s:deepcopy-gen=true
type Address struct {
	Type addressing.AddressType
	IP   iputil.Addr
}

// NewAddress returns a node address of the given type, normalizing addr so
// that the invariant documented on [Address] holds.
func NewAddress(typ addressing.AddressType, addr netip.Addr) Address {
	return Address{Type: typ, IP: iputil.AddrFrom(addr.Unmap())}
}

func (a *Address) DeepEqual(other *Address) bool {
	return a.Type == other.Type && a.IP == other.IP
}

func (a Address) ToString() string {
	return a.IP.String()
}

func (a Address) AddrType() addressing.AddressType {
	return a.Type
}

// Addr returns the address, implementing [addressing.Address].
func (a Address) Addr() netip.Addr {
	return a.IP.Addr
}

// IsNodeIP determines if addr is one of the node's IP addresses,
// and returns which type of address it is. "" is returned if addr
// is not one of the node's IP addresses.
func (n *Node) IsNodeIP(addr netip.Addr) addressing.AddressType {
	for _, a := range n.IPAddresses {
		if a.IP.Addr == addr {
			return a.Type
		}
	}

	return ""
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
// The zero value is returned if GetNodeIP fails to extract an IP from the Node
// based on the provided address family.
func (n *Node) GetNodeIP(ipv6 bool) netip.Addr {
	return addressing.ExtractNodeIP[Address](n.IPAddresses, ipv6)
}

// GetK8sNodeIP returns k8s Node IP (either InternalIP or ExternalIP or the
// zero value, the former is preferred).
func (n *Node) GetK8sNodeIP() netip.Addr {
	var externalIP netip.Addr

	for _, addr := range n.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			return addr.IP.Addr
		} else if addr.Type == addressing.NodeExternalIP {
			externalIP = addr.IP.Addr
		}
	}

	return externalIP
}

// GetNodeExternalIPv4 returns the IPv4 ExternalIP of the k8s Node, or the zero
// value if the node holds no such address.
func (n *Node) GetNodeExternalIPv4() netip.Addr {
	return n.getAddress(addressing.NodeExternalIP, false)
}

// GetNodeExternalIPv6 returns the IPv6 ExternalIP of the k8s Node, or the zero
// value if the node holds no such address.
func (n *Node) GetNodeExternalIPv6() netip.Addr {
	return n.getAddress(addressing.NodeExternalIP, true)
}

// GetNodeInternalIPv4 returns the InternalIPv4 of the k8s Node or the zero value.
func (n *Node) GetNodeInternalIPv4() netip.Addr {
	return n.getAddress(addressing.NodeInternalIP, false)
}

// GetNodeInternalIPv6 returns the InternalIPv6 of the k8s Node or the zero value.
func (n *Node) GetNodeInternalIPv6() netip.Addr {
	return n.getAddress(addressing.NodeInternalIP, true)
}

// GetCiliumInternalIPv4 returns the IPv4 CiliumInternalIP e.g. the IP
// associated with cilium_host on the node.
func (n *Node) GetCiliumInternalIPv4() netip.Addr {
	return n.getAddress(addressing.NodeCiliumInternalIP, false)
}

// GetCiliumInternalIPv6 returns the IPv6 CiliumInternalIP e.g. the IP
// associated with cilium_host on the node.
func (n *Node) GetCiliumInternalIPv6() netip.Addr {
	return n.getAddress(addressing.NodeCiliumInternalIP, true)
}

// SetCiliumInternalIP sets the CiliumInternalIP e.g. the IP associated
// with cilium_host on the node.
// This must not be conflated with k8s internal IP as this IP address is only relevant within the
// Cilium-managed network (this means within the node for direct routing mode and on the overlay
// for tunnel mode).
func (n *Node) SetCiliumInternalIP(newAddr netip.Addr) {
	n.setAddress(addressing.NodeCiliumInternalIP, newAddr)
}

// SetNodeExternalIP sets the NodeExternalIP.
func (n *Node) SetNodeExternalIP(newAddr netip.Addr) {
	n.setAddress(addressing.NodeExternalIP, newAddr)
}

// SetNodeInternalIP sets the NodeInternalIP.
func (n *Node) SetNodeInternalIP(newAddr netip.Addr) {
	n.setAddress(addressing.NodeInternalIP, newAddr)
}

// getAddress returns the node address of the given type for the given address
// family, or the zero value if the node holds no such address.
//
// Unlike GetNodeIP and GetK8sNodeIP, which fall back to other address types
// when the preferred one is missing, this is a plain lookup: it only ever
// returns an address of type typ.
func (n *Node) getAddress(typ addressing.AddressType, ipv6 bool) netip.Addr {
	for _, addr := range n.IPAddresses {
		if addr.Type != typ {
			continue
		}
		if ipv6 != addr.IP.Is4() {
			return addr.IP.Addr
		}
	}
	return netip.Addr{}
}

// setAddress sets the node address of the given type, replacing the address of
// the same type and address family if the node already holds one. An invalid
// newIP removes every address of that type instead, for both address families.
//
// The address family is derived from newIP, which is why the exported setters,
// unlike the getters, take no address family argument.
func (n *Node) setAddress(typ addressing.AddressType, newIP netip.Addr) {
	newAddr := NewAddress(typ, newIP)

	if !newAddr.IP.IsValid() {
		n.removeAddresses(typ)
		return
	}

	// Create a copy of the slice, so that we don't modify the
	// current one, which may be captured by any of the observers.
	n.IPAddresses = slices.Clone(n.IPAddresses)

	ipv6 := !newAddr.IP.Is4()
	// Try first to replace an existing address with same type
	for i, addr := range n.IPAddresses {
		if addr.Type != typ {
			continue
		}
		if ipv6 == addr.IP.Is4() {
			// Don't replace if address family is different.
			continue
		}
		n.IPAddresses[i] = newAddr
		return
	}
	n.IPAddresses = append(n.IPAddresses, newAddr)
}

// removeAddresses removes all the node addresses of the given type, for both
// address families.
func (n *Node) removeAddresses(typ addressing.AddressType) {
	newAddresses := []Address{}
	for _, addr := range n.IPAddresses {
		if addr.Type != typ {
			newAddresses = append(newAddresses, addr)
		}
	}
	n.IPAddresses = newAddresses
}

func (n *Node) getPrimaryAddress() *models.NodeAddressing {
	v4 := n.GetNodeIP(false)
	v6 := n.GetNodeIP(true)

	var ipv4AllocStr, ipv6AllocStr string
	if n.IPv4AllocCIDR.IsValid() {
		ipv4AllocStr = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR.IsValid() {
		ipv6AllocStr = n.IPv6AllocCIDR.String()
	}

	var v4Str, v6Str string
	if v4.IsValid() {
		v4Str = v4.String()
	}
	if v6.IsValid() {
		v6Str = v6.String()
	}

	return &models.NodeAddressing{
		IPv4: &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv4,
			IP:         v4Str,
			AllocRange: ipv4AllocStr,
		},
		IPv6: &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv6,
			IP:         v6Str,
			AllocRange: ipv6AllocStr,
		},
	}
}

func (n *Node) isPrimaryAddress(addr Address, ipv4 bool) bool {
	return addr.IP.Addr == n.GetNodeIP(!ipv4)
}

func (n *Node) getSecondaryAddresses() []*models.NodeAddressingElement {
	result := []*models.NodeAddressingElement{}

	for _, addr := range n.IPAddresses {
		ipv4 := addr.IP.Is4()
		if !n.isPrimaryAddress(addr, ipv4) {
			result = append(result, &models.NodeAddressingElement{
				IP: addr.IP.String(),
			})
		}
	}

	return result
}

func (n *Node) getHealthAddresses() *models.NodeAddressing {
	if !n.IPv4HealthIP.IsValid() && !n.IPv6HealthIP.IsValid() {
		return nil
	}

	var v4Str, v6Str string
	if n.IPv4HealthIP.IsValid() {
		v4Str = n.IPv4HealthIP.String()
	}
	if n.IPv6HealthIP.IsValid() {
		v6Str = n.IPv6HealthIP.String()
	}

	return &models.NodeAddressing{
		IPv4: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv4,
			IP:      v4Str,
		},
		IPv6: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv6,
			IP:      v6Str,
		},
	}
}

func (n *Node) getIngressAddresses() *models.NodeAddressing {
	if !n.IPv4IngressIP.IsValid() && !n.IPv6IngressIP.IsValid() {
		return nil
	}

	var v4Str, v6Str string
	if n.IPv4IngressIP.IsValid() {
		v4Str = n.IPv4IngressIP.String()
	}
	if n.IPv6IngressIP.IsValid() {
		v6Str = n.IPv6IngressIP.String()
	}

	return &models.NodeAddressing{
		IPv4: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv4,
			IP:      v4Str,
		},
		IPv6: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv6,
			IP:      v6Str,
		},
	}
}

// GetModel returns the API model representation of a node.
func (n *Node) GetModel() *models.NodeElement {
	return &models.NodeElement{
		Name:                  n.Fullname(),
		PrimaryAddress:        n.getPrimaryAddress(),
		SecondaryAddresses:    n.getSecondaryAddresses(),
		HealthEndpointAddress: n.getHealthAddresses(),
		IngressAddress:        n.getIngressAddresses(),
		Source:                string(n.Source),
	}
}

// Identity returns the identity of the node
func (n *Node) Identity() Identity {
	return Identity{
		Name:    n.Name,
		Cluster: n.Cluster,
	}
}

func getCluster() string {
	return option.Config.ClusterName
}

// IsLocal returns true if this is the node on which the agent itself is
// running on
func (n *Node) IsLocal() bool {
	return n != nil && n.Name == GetName() && n.Cluster == getCluster()
}

func (n *Node) GetIPv4AllocCIDRs() []netip.Prefix {
	result := make([]netip.Prefix, 0, len(n.IPv4SecondaryAllocCIDRs)+1)
	if n.IPv4AllocCIDR.IsValid() {
		result = append(result, n.IPv4AllocCIDR.Prefix.Prefix)
	}
	for _, c := range n.IPv4SecondaryAllocCIDRs {
		if c.IsValid() {
			result = append(result, c.Prefix.Prefix)
		}
	}
	return result
}

func (n *Node) GetIPv6AllocCIDRs() []netip.Prefix {
	result := make([]netip.Prefix, 0, len(n.IPv6SecondaryAllocCIDRs)+1)
	if n.IPv6AllocCIDR.IsValid() {
		result = append(result, n.IPv6AllocCIDR.Prefix.Prefix)
	}
	for _, c := range n.IPv6SecondaryAllocCIDRs {
		if c.IsValid() {
			result = append(result, c.Prefix.Prefix)
		}
	}
	return result
}

// GetKeyNodeName constructs the API name for the given cluster and node name.
func GetKeyNodeName(cluster, node string) string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility. Open-coded, instead of using [kvstore.JoinKey]
	// to avoid introducing an unnecessary dependency on the kvstore package.
	return strings.Trim(cluster+"/"+node, "/")
}

// GetKeyName returns the kvstore key to be used for the node
func (n *Node) GetKeyName() string {
	return GetKeyNodeName(n.Cluster, n.Name)
}

// Marshal returns the node object as JSON byte slice
func (n *Node) Marshal() ([]byte, error) {
	return json.Marshal(n)
}

// Unmarshal parses the JSON byte slice and updates the node receiver
func (n *Node) Unmarshal(key string, data []byte) error {
	newNode := Node{}
	if err := json.Unmarshal(data, &newNode); err != nil {
		return err
	}

	if err := newNode.validate(); err != nil {
		return err
	}

	// Normalize the decoded addresses: encoding/json hands netip.Addr the
	// textual form verbatim, so a peer that wrote an IPv4-mapped IPv6 form
	// would otherwise break the invariant documented on Address.
	for i, addr := range newNode.IPAddresses {
		newNode.IPAddresses[i] = NewAddress(addr.Type, addr.IP.Addr)
	}

	*n = newNode

	return nil
}

// LogRepr returns a representation of the node to be used for logging
func (n *Node) LogRepr() string {
	b, err := n.Marshal()
	if err != nil {
		return fmt.Sprintf("%#v", n)
	}
	return string(b)
}

func (n *Node) validate() error {
	switch {
	case n.Cluster == "":
		return errors.New("cluster is unset")
	case n.Name == "":
		return errors.New("name is unset")
	}

	return nil
}
