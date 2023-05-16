// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"net"
	"net/netip"
	"path"
	"strings"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/kvstore/store"
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
	return path.Join(nn.Cluster, nn.Name)
}

// appendAllocCDIR sets or appends the given podCIDR to the node.
// If the IPv4/IPv6AllocCIDR is already set, we add the podCIDR as a secondary
// alloc CIDR.
func (n *Node) appendAllocCDIR(podCIDR *cidr.CIDR) {
	if podCIDR.IP.To4() != nil {
		if n.IPv4AllocCIDR == nil {
			n.IPv4AllocCIDR = podCIDR
		} else {
			n.IPv4SecondaryAllocCIDRs = append(n.IPv4SecondaryAllocCIDRs, podCIDR)
		}
	} else {
		if n.IPv6AllocCIDR == nil {
			n.IPv6AllocCIDR = podCIDR
		} else {
			n.IPv6SecondaryAllocCIDRs = append(n.IPv6SecondaryAllocCIDRs, podCIDR)
		}
	}
}

// ParseCiliumNode parses a CiliumNode custom resource and returns a Node
// instance. Invalid IP and CIDRs are silently ignored
func ParseCiliumNode(n *ciliumv2.CiliumNode) (node Node) {
	wireguardPubKey, _ := annotation.Get(n, annotation.WireguardPubKey, annotation.WireguardPubKeyAlias)
	node = Node{
		Name:            n.Name,
		EncryptionKey:   uint8(n.Spec.Encryption.Key),
		Cluster:         option.Config.ClusterName,
		ClusterID:       option.Config.ClusterID,
		Source:          source.CustomResource,
		Labels:          n.ObjectMeta.Labels,
		Annotations:     n.ObjectMeta.Annotations,
		NodeIdentity:    uint32(n.Spec.NodeIdentity),
		WireguardPubKey: wireguardPubKey,
	}

	for _, cidrString := range n.Spec.IPAM.PodCIDRs {
		ipnet, err := cidr.ParseCIDR(cidrString)
		if err == nil {
			node.appendAllocCDIR(ipnet)
		}
	}

	for _, pool := range n.Spec.IPAM.Pools.Allocated {
		for _, podCIDR := range pool.CIDRs {
			ipnet, err := cidr.ParseCIDR(string(podCIDR))
			if err == nil {
				node.appendAllocCDIR(ipnet)
			}
		}
	}

	if ip := ToV4Addr(n.Spec.HealthAddressing.IPv4); ip != nil {
		node.IPv4HealthIP = ip
	}
	if ip := ToV6Addr(n.Spec.HealthAddressing.IPv6); ip != nil {
		node.IPv6HealthIP = ip
	}
	if ip := ToV4Addr(n.Spec.IngressAddressing.IPV4); ip != nil {
		node.IPv4IngressIP = ip
	}
	if ip := ToV6Addr(n.Spec.IngressAddressing.IPV6); ip != nil {
		node.IPv6IngressIP = ip
	}

	for _, address := range n.Spec.Addresses {
		if addr := toAddr(address.IP); addr != nil {
			node.IPAddresses = append(node.IPAddresses, Address{Type: address.Type, IP: addr.IP})
		}
	}

	return
}

// GetCiliumAnnotations returns the node annotations that should be set on the CiliumNode
func (n *Node) GetCiliumAnnotations() map[string]string {
	annotations := map[string]string{}
	if n.WireguardPubKey != "" {
		annotations[annotation.WireguardPubKey] = n.WireguardPubKey
	}

	// if we use a cilium node instead of a node, we also need the BGP Control Plane annotations in the cilium node instead of the main node
	for k, a := range n.Annotations {
		if strings.HasPrefix(k, annotation.BGPVRouterAnnoPrefix) {
			annotations[k] = a
		}
	}

	return annotations
}

// ToCiliumNode converts the node to a CiliumNode
func (n *Node) ToCiliumNode() *ciliumv2.CiliumNode {
	var (
		podCIDRs                 []string
		ipAddrs                  []ciliumv2.NodeAddress
		healthIPv4, healthIPv6   *Address
		ingressIPv4, ingressIPv6 *Address
	)

	if n.IPv4AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv4AllocCIDR.String())
	}
	if n.IPv6AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv6AllocCIDR.String())
	}
	for _, ipv4AllocCIDR := range n.IPv4SecondaryAllocCIDRs {
		podCIDRs = append(podCIDRs, ipv4AllocCIDR.String())
	}
	for _, ipv6AllocCIDR := range n.IPv6SecondaryAllocCIDRs {
		podCIDRs = append(podCIDRs, ipv6AllocCIDR.String())
	}
	if n.IPv4HealthIP != nil {
		healthIPv4 = n.IPv4HealthIP
	}
	if n.IPv6HealthIP != nil {
		healthIPv6 = n.IPv6HealthIP
	}
	if n.IPv4IngressIP != nil {
		ingressIPv4 = n.IPv4IngressIP
	}
	if n.IPv6IngressIP != nil {
		ingressIPv6 = n.IPv6IngressIP
	}

	for _, address := range n.IPAddresses {
		ipAddrs = append(ipAddrs, ciliumv2.NodeAddress{
			Type: address.Type,
			IP:   address.IP.String(),
		})
	}

	return &ciliumv2.CiliumNode{
		ObjectMeta: v1.ObjectMeta{
			Name:        n.Name,
			Labels:      n.Labels,
			Annotations: n.GetCiliumAnnotations(),
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: ipAddrs,
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: healthIPv4.IP.String(),
				IPv6: healthIPv6.IP.String(),
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: ingressIPv4.IP.String(),
				IPV6: ingressIPv6.IP.String(),
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: int(n.EncryptionKey),
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: podCIDRs,
			},
			NodeIdentity: uint64(n.NodeIdentity),
		},
	}
}

// RegisterNode overloads GetKeyName to ignore the cluster name, as cluster name may not be stable during node registration.
//
// +k8s:deepcopy-gen=true
type RegisterNode struct {
	Node
}

// GetKeyName Overloaded key name w/o cluster name
func (n *RegisterNode) GetKeyName() string {
	return n.Name
}

// DeepKeyCopy creates a deep copy of the LocalKey
func (n *RegisterNode) DeepKeyCopy() store.LocalKey {
	return n.DeepCopy()
}

// Node contains the nodes name, the list of addresses to this address
//
// +k8s:deepcopy-gen=true
type Node struct {
	// Name is the name of the node. This is typically the hostname of the node.
	Name string

	// Cluster is the name of the cluster the node is associated with
	Cluster string

	IPAddresses []Address

	// IPv4AllocCIDR if set, is the IPv4 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv4AllocCIDR *cidr.CIDR

	// IPv4SecondaryAllocCIDRs contains additional IPv4 CIDRs from which this
	//node allocates IPs for its local endpoints from
	IPv4SecondaryAllocCIDRs []*cidr.CIDR

	// IPv6AllocCIDR if set, is the IPv6 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv6AllocCIDR *cidr.CIDR

	// IPv6SecondaryAllocCIDRs contains additional IPv6 CIDRs from which this
	// node allocates IPs for its local endpoints from
	IPv6SecondaryAllocCIDRs []*cidr.CIDR

	// IPv4HealthIP if not nil, this is the IPv4 address of the
	// cilium-health endpoint located on the node.
	IPv4HealthIP *Address

	// IPv6HealthIP if not nil, this is the IPv6 address of the
	// cilium-health endpoint located on the node.
	IPv6HealthIP *Address

	// IPv4IngressIP if not nil, this is the IPv4 address of the
	// Ingress listener on the node.
	IPv4IngressIP *Address

	// IPv6IngressIP if not nil, this is the IPv6 address of the
	// Ingress listener located on the node.
	IPv6IngressIP *Address

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

	// NodeIdentity is the numeric identity allocated for the node
	NodeIdentity uint32

	// WireguardPubKey is the WireGuard public key of this node
	WireguardPubKey string
}

// Fullname returns the node's full name including the cluster name if a
// cluster name value other than the default value has been specified
func (n *Node) Fullname() string {
	if n.Cluster != defaults.ClusterName {
		return path.Join(n.Cluster, n.Name)
	}

	return n.Name
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
func (n *Node) GetNodeIP(ipv6 bool) *netip.Addr {
	var backup *Address
	for _, addr := range n.IPAddresses {
		if (ipv6 && ip.IsAddrV4(&addr.IP)) ||
			(!ipv6 && ip.IsAddrV6(&addr.IP)) {
			continue
		}
		switch addr.Type {
		// Ignore CiliumInternalIPs
		case addressing.NodeCiliumInternalIP:
			continue
		// Always prefer a cluster internal IP
		case addressing.NodeInternalIP:
			return &addr.IP
		case addressing.NodeExternalIP:
			// Fall back to external Node IP
			// if no internal IP could be found
			backup = &addr
		default:
			// As a last resort, if no internal or external
			// IP was found, use any node address available
			if backup == nil {
				backup = &addr
			}
		}
	}
	return &backup.IP
}

// GetExternalIP returns ExternalIP of k8s Node. If not present, then it
// returns nil;
func (n *Node) GetExternalIP(ipv6 bool) *netip.Addr {
	for _, addr := range n.IPAddresses {
		if (ipv6 && ip.IsAddrV4(&addr.IP)) || (!ipv6 && ip.IsAddrV6(&addr.IP)) {
			continue
		}
		if addr.Type == addressing.NodeExternalIP {
			return &addr.IP
		}
	}

	return nil
}

// GetK8sNodeIPs returns k8s Node IP (either InternalIP or ExternalIP or nil;
// the former is preferred).
func (n *Node) GetK8sNodeIP() *netip.Addr {
	var externalIP netip.Addr

	for _, addr := range n.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			return &addr.IP
		} else if addr.Type == addressing.NodeExternalIP {
			externalIP = addr.IP
		}
	}

	return &externalIP
}

// GetCiliumInternalIP returns the CiliumInternalIP e.g. the IP associated
// with cilium_host on the node.
func (n *Node) GetCiliumInternalIP(ipv6 bool) *netip.Addr {
	for _, addr := range n.IPAddresses {
		if (ipv6 && ip.IsAddrV4(&addr.IP)) ||
			(!ipv6 && ip.IsAddrV6(&addr.IP)) {
			continue
		}
		if addr.Type == addressing.NodeCiliumInternalIP {
			return &addr.IP
		}
	}
	return nil
}

// SetCiliumInternalIP sets the CiliumInternalIP e.g. the IP associated
// with cilium_host on the node.
func (n *Node) SetCiliumInternalIP(newIP *netip.Addr) {
	n.setAddress(addressing.NodeCiliumInternalIP, newIP)
}

// SetNodeExternalIP sets the NodeExternalIP.
func (n *Node) SetNodeExternalIP(newIP *netip.Addr) {
	n.setAddress(addressing.NodeExternalIP, newIP)
}

// SetNodeInternalIP sets the NodeInternalIP.
func (n *Node) SetNodeInternalIP(newIP *netip.Addr) {
	n.setAddress(addressing.NodeInternalIP, newIP)
}

func (n *Node) RemoveAddresses(typ addressing.AddressType) {
	newAddresses := []Address{}
	for _, addr := range n.IPAddresses {
		if addr.Type != typ {
			newAddresses = append(newAddresses, addr)
		}
	}
	n.IPAddresses = newAddresses
}

func (n *Node) setAddress(typ addressing.AddressType, newIP *netip.Addr) {
	if newIP == nil {
		n.RemoveAddresses(typ)
		return
	}

	nodeAddr := Address{Type: typ, IP: *newIP}
	ipv6 := ip.IsAddrV6(newIP)
	// Try first to replace an existing address with same type
	for i, addr := range n.IPAddresses {
		if addr.Type != typ {
			continue
		}
		if ipv6 != addr.IP.Is4() {
			// Don't replace if address family is different.
			continue
		}
		n.IPAddresses[i] = nodeAddr
		return
	}
	n.IPAddresses = append(n.IPAddresses, nodeAddr)

}

func (n *Node) GetAddrByType(addrType addressing.AddressType, ipv6 bool) *Address {
	for _, addr := range n.IPAddresses {
		if addr.Type != addrType {
			continue
		}
		if is4 := addr.IP.Is4(); (!ipv6 && is4) || (ipv6 && !is4) {
			return &addr
		}
	}
	return nil
}

func (n *Node) getPrimaryAddress() *models.NodeAddressing {
	v4 := n.GetNodeIP(false)
	v6 := n.GetNodeIP(true)

	var ipv4AllocStr, ipv6AllocStr string
	if n.IPv4AllocCIDR != nil {
		ipv4AllocStr = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		ipv6AllocStr = n.IPv6AllocCIDR.String()
	}

	var v4Str, v6Str string
	if v4 != nil {
		v4Str = v4.String()
	}
	if v6 != nil {
		v6Str = v6.String()
	}

	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv4,
			IP:         v4Str,
			AllocRange: ipv4AllocStr,
		},
		IPV6: &models.NodeAddressingElement{
			Enabled:    option.Config.EnableIPv6,
			IP:         v6Str,
			AllocRange: ipv6AllocStr,
		},
	}
}

func (n *Node) isPrimaryAddress(addr Address, ipv4 bool) bool {
	return addr.IP.String() == n.GetNodeIP(!ipv4).String()
}

func (n *Node) getSecondaryAddresses() []*models.NodeAddressingElement {
	result := []*models.NodeAddressingElement{}

	for _, addr := range n.IPAddresses {
		ipv4 := false
		if addr.IP.Is4() {
			ipv4 = true
		}
		if !n.isPrimaryAddress(addr, ipv4) {
			result = append(result, &models.NodeAddressingElement{
				IP: addr.IP.String(),
			})
		}
	}

	return result
}

func (n *Node) getHealthAddresses() *models.NodeAddressing {
	if n.IPv4HealthIP == nil && n.IPv6HealthIP == nil {
		return nil
	}

	var v4Str, v6Str string
	if n.IPv4HealthIP != nil {
		v4Str = n.IPv4HealthIP.IP.String()
	}
	if n.IPv6HealthIP != nil {
		v6Str = n.IPv6HealthIP.IP.String()
	}

	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv4,
			IP:      v4Str,
		},
		IPV6: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv6,
			IP:      v6Str,
		},
	}
}

func (n *Node) getIngressAddresses() *models.NodeAddressing {
	if n.IPv4IngressIP == nil && n.IPv6IngressIP == nil {
		return nil
	}

	var v4Str, v6Str string
	if n.IPv4IngressIP != nil {
		v4Str = n.IPv4IngressIP.IP.String()
	}
	if n.IPv6IngressIP != nil {
		v6Str = n.IPv6IngressIP.IP.String()
	}

	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled: option.Config.EnableIPv4,
			IP:      v4Str,
		},
		IPV6: &models.NodeAddressingElement{
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

func (n *Node) GetIPv4AllocCIDRs() []*cidr.CIDR {
	result := make([]*cidr.CIDR, 0, len(n.IPv4SecondaryAllocCIDRs)+1)
	if n.IPv4AllocCIDR != nil {
		result = append(result, n.IPv4AllocCIDR)
	}
	if len(n.IPv4SecondaryAllocCIDRs) > 0 {
		result = append(result, n.IPv4SecondaryAllocCIDRs...)
	}
	return result
}

func (n *Node) GetIPv6AllocCIDRs() []*cidr.CIDR {
	result := make([]*cidr.CIDR, 0, len(n.IPv6SecondaryAllocCIDRs)+1)
	if n.IPv6AllocCIDR != nil {
		result = append(result, n.IPv6AllocCIDR)
	}
	if len(n.IPv4SecondaryAllocCIDRs) > 0 {
		result = append(result, n.IPv6SecondaryAllocCIDRs...)
	}
	return result
}

// GetKeyNodeName constructs the API name for the given cluster and node name.
func GetKeyNodeName(cluster, node string) string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(cluster, node)
}

// GetKeyName returns the kvstore key to be used for the node
func (n *Node) GetKeyName() string {
	return GetKeyNodeName(n.Cluster, n.Name)
}

// DeepKeyCopy creates a deep copy of the LocalKey
func (n *Node) DeepKeyCopy() store.LocalKey {
	return n.DeepCopy()
}

// Marshal returns the node object as JSON byte slice
func (n *Node) Marshal() ([]byte, error) {
	return json.Marshal(n)
}

// Unmarshal parses the JSON byte slice and updates the node receiver
func (n *Node) Unmarshal(data []byte) error {
	newNode := Node{}
	if err := json.Unmarshal(data, &newNode); err != nil {
		return err
	}

	*n = newNode

	return nil
}

// Address defines a node address which contains an address value, family, and type.
type Address struct {
	Type addressing.AddressType
	IP   netip.Addr
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Address) DeepCopyInto(out *Address) {
	*out = *in
}

// DeepCopy is a deepcopy function, copying the receiver, creating a new Address.
func (in *Address) DeepCopy() *Address {
	if in == nil {
		return nil
	}
	out := new(Address)
	in.DeepCopyInto(out)
	return out
}

func (a *Address) IsEqual(ip2 string) bool {
	if a == nil {
		return len(ip2) == 0
	}
	if len(ip2) == 0 {
		return false
	}
	parsedIP, err := netip.ParseAddr(ip2)
	if err != nil {
		return false

	}
	if cmp := a.IP.Compare(parsedIP); cmp != 0 {
		return false
	}
	return true
}

func (a *Address) ToIP() *net.IP {
	if a == nil {
		return nil
	}
	if ret := net.ParseIP(a.IP.String()); ret != nil {
		return &ret
	}
	return nil
}

// AddrFromIP returns ip as an Address with any IPv4-mapped IPv6 address prefix removed.
// If ip it not an IPv4 or IPv6 address, nil is returned.
func AddrFromIP(ip net.IP) *Address {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil
	}
	return &Address{IP: addr.Unmap()}
}

// As4 returns an IPv4 or IPv4-in-IPv6 address in its 4-byte representation. If ip is the zero Addr
// or an IPv6 address, As4 panics. Note that 0.0.0.0 is not the zero Addr.
func (a *Address) As4() (a4 [4]byte) {
	return a.IP.As4()
}

// toAddr returns an Address from the provided ip without an assigned type. A nil Address is returned
// if ip is an empty string or not an IPv4 or IPv6 address.
func toAddr(ip string) *Address {
	if len(ip) == 0 {
		return nil
	}
	parsedIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return &Address{IP: parsedIP}
}

// ToV4Addr returns an IPv4 address from the provided ip without an assigned type. A nil Address is returned
// if ip is an empty string or not an IPv4 address.
func ToV4Addr(ip string) *Address {
	ret := toAddr(ip)
	if ret.IP.Is4() {
		return ret
	}
	return nil
}

// ToV6Addr returns an IPv6 address from the provided ip without an assigned type. A nil Address is returned
// if ip is an empty string or not an IPv6 address.
func ToV6Addr(ip string) *Address {
	ret := toAddr(ip)
	if ret.IP.Is4() || ret.IP.Is4In6() {
		return nil
	}
	return ret
}
