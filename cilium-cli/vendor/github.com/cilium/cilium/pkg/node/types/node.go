// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"path"
	"slices"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
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

	node.IPv4HealthIP = net.ParseIP(n.Spec.HealthAddressing.IPv4)
	node.IPv6HealthIP = net.ParseIP(n.Spec.HealthAddressing.IPv6)

	node.IPv4IngressIP = net.ParseIP(n.Spec.IngressAddressing.IPV4)
	node.IPv6IngressIP = net.ParseIP(n.Spec.IngressAddressing.IPV6)

	for _, address := range n.Spec.Addresses {
		if ip := net.ParseIP(address.IP); ip != nil {
			node.IPAddresses = append(node.IPAddresses, Address{Type: address.Type, IP: ip})
		}
	}

	return
}

// ToCiliumNode converts the node to a CiliumNode
func (n *Node) ToCiliumNode() *ciliumv2.CiliumNode {
	var (
		podCIDRs                 []string
		ipAddrs                  []ciliumv2.NodeAddress
		healthIPv4, healthIPv6   string
		ingressIPv4, ingressIPv6 string
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
		healthIPv4 = n.IPv4HealthIP.String()
	}
	if n.IPv6HealthIP != nil {
		healthIPv6 = n.IPv6HealthIP.String()
	}
	if n.IPv4IngressIP != nil {
		ingressIPv4 = n.IPv4IngressIP.String()
	}
	if n.IPv6IngressIP != nil {
		ingressIPv6 = n.IPv6IngressIP.String()
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
			Annotations: n.Annotations,
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: ipAddrs,
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: healthIPv4,
				IPv6: healthIPv6,
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: ingressIPv4,
				IPV6: ingressIPv6,
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

func (n *RegisterNode) Unmarshal(_ string, data []byte) error {
	newNode := Node{}
	if err := json.Unmarshal(data, &newNode); err != nil {
		return err
	}

	n.Node = newNode
	return nil
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
	IPv4HealthIP net.IP

	// IPv6HealthIP if not nil, this is the IPv6 address of the
	// cilium-health endpoint located on the node.
	IPv6HealthIP net.IP

	// IPv4IngressIP if not nil, this is the IPv4 address of the
	// Ingress listener on the node.
	IPv4IngressIP net.IP

	// IPv6IngressIP if not nil, this is the IPv6 address of the
	// Ingress listener located on the node.
	IPv6IngressIP net.IP

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

// Address is a node address which contains an IP and the address type.
//
// +k8s:deepcopy-gen=true
type Address struct {
	Type addressing.AddressType
	IP   net.IP
}

func (a Address) ToString() string {
	return a.IP.String()
}

func (a Address) AddrType() addressing.AddressType {
	return a.Type
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
// Nil is returned if GetNodeIP fails to extract an IP from the Node based
// on the provided address family.
func (n *Node) GetNodeIP(ipv6 bool) net.IP {
	return addressing.ExtractNodeIP[Address](n.IPAddresses, ipv6)
}

// GetExternalIP returns ExternalIP of k8s Node. If not present, then it
// returns nil;
func (n *Node) GetExternalIP(ipv6 bool) net.IP {
	for _, addr := range n.IPAddresses {
		if (ipv6 && addr.IP.To4() != nil) || (!ipv6 && addr.IP.To4() == nil) {
			continue
		}
		if addr.Type == addressing.NodeExternalIP {
			return addr.IP
		}
	}

	return nil
}

// GetK8sNodeIPs returns k8s Node IP (either InternalIP or ExternalIP or nil;
// the former is preferred).
func (n *Node) GetK8sNodeIP() net.IP {
	var externalIP net.IP

	for _, addr := range n.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			return addr.IP
		} else if addr.Type == addressing.NodeExternalIP {
			externalIP = addr.IP
		}
	}

	return externalIP
}

// GetNodeInternalIP returns the Internal IPv4 of node or nil.
func (n *Node) GetNodeInternalIPv4() net.IP {
	for _, addr := range n.IPAddresses {
		if addr.IP.To4() == nil {
			continue
		}
		if addr.Type == addressing.NodeInternalIP {
			return addr.IP
		}
	}

	return nil
}

// GetNodeInternalIP returns the Internal IPv6 of node or nil.
func (n *Node) GetNodeInternalIPv6() net.IP {
	for _, addr := range n.IPAddresses {
		if addr.IP.To4() != nil {
			continue
		}
		if addr.Type == addressing.NodeInternalIP {
			return addr.IP
		}
	}

	return nil
}

// GetCiliumInternalIP returns the CiliumInternalIP e.g. the IP associated
// with cilium_host on the node.
func (n *Node) GetCiliumInternalIP(ipv6 bool) net.IP {
	for _, addr := range n.IPAddresses {
		if (ipv6 && addr.IP.To4() != nil) ||
			(!ipv6 && addr.IP.To4() == nil) {
			continue
		}
		if addr.Type == addressing.NodeCiliumInternalIP {
			return addr.IP
		}
	}
	return nil
}

// SetCiliumInternalIP sets the CiliumInternalIP e.g. the IP associated
// with cilium_host on the node.
func (n *Node) SetCiliumInternalIP(newAddr net.IP) {
	n.setAddress(addressing.NodeCiliumInternalIP, newAddr)
}

// SetNodeExternalIP sets the NodeExternalIP.
func (n *Node) SetNodeExternalIP(newAddr net.IP) {
	n.setAddress(addressing.NodeExternalIP, newAddr)
}

// SetNodeInternalIP sets the NodeInternalIP.
func (n *Node) SetNodeInternalIP(newAddr net.IP) {
	n.setAddress(addressing.NodeInternalIP, newAddr)
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

func (n *Node) setAddress(typ addressing.AddressType, newIP net.IP) {
	newAddr := Address{Type: typ, IP: newIP}

	if newIP == nil {
		n.RemoveAddresses(typ)
		return
	}

	// Create a copy of the slice, so that we don't modify the
	// current one, which may be captured by any of the observers.
	n.IPAddresses = slices.Clone(n.IPAddresses)

	ipv6 := newIP.To4() == nil
	// Try first to replace an existing address with same type
	for i, addr := range n.IPAddresses {
		if addr.Type != typ {
			continue
		}
		if ipv6 != (addr.IP.To4() == nil) {
			// Don't replace if address family is different.
			continue
		}
		n.IPAddresses[i] = newAddr
		return
	}
	n.IPAddresses = append(n.IPAddresses, newAddr)

}

func (n *Node) GetIPByType(addrType addressing.AddressType, ipv6 bool) net.IP {
	for _, addr := range n.IPAddresses {
		if addr.Type != addrType {
			continue
		}
		if is4 := addr.IP.To4() != nil; (!ipv6 && is4) || (ipv6 && !is4) {
			return addr.IP
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
		if addr.IP.To4() != nil {
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
		v4Str = n.IPv4HealthIP.String()
	}
	if n.IPv6HealthIP != nil {
		v6Str = n.IPv6HealthIP.String()
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
		v4Str = n.IPv4IngressIP.String()
	}
	if n.IPv6IngressIP != nil {
		v6Str = n.IPv6IngressIP.String()
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
	if len(n.IPv6SecondaryAllocCIDRs) > 0 {
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
func (n *Node) Unmarshal(_ string, data []byte) error {
	newNode := Node{}
	if err := json.Unmarshal(data, &newNode); err != nil {
		return err
	}

	if err := newNode.validate(); err != nil {
		return err
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
	// Skip the ClusterID check if it matches the local one, as we assume that
	// it has already been validated, and to allow it to be zero.
	if n.ClusterID != option.Config.ClusterID {
		if err := cmtypes.ValidateClusterID(n.ClusterID); err != nil {
			return err
		}
	}

	return nil
}
