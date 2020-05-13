// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/json"
	"net"
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// ParseCiliumNode parses a CiliumNode custom resource and returns a Node
// instance. Invalid IP and CIDRs are silently ignored
func ParseCiliumNode(n *ciliumv2.CiliumNode) (node Node) {
	node = Node{
		Name:          n.Name,
		EncryptionKey: uint8(n.Spec.Encryption.Key),
		Cluster:       option.Config.ClusterName,
		ClusterID:     option.Config.ClusterID,
		Source:        source.CustomResource,
	}

	for _, cidrString := range n.Spec.IPAM.PodCIDRs {
		ipnet, err := cidr.ParseCIDR(cidrString)
		if err == nil {
			if ipnet.IP.To4() != nil {
				node.IPv4AllocCIDR = ipnet
			} else {
				node.IPv6AllocCIDR = ipnet
			}
		}
	}

	if healthIP := n.Spec.HealthAddressing.IPv4; healthIP != "" {
		node.IPv4HealthIP = net.ParseIP(healthIP)
	}

	if healthIP := n.Spec.HealthAddressing.IPv6; healthIP != "" {
		node.IPv6HealthIP = net.ParseIP(healthIP)
	}

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
		podCIDRs               []string
		ipAddrs                []ciliumv2.NodeAddress
		healthIPv4, healthIPv6 string
	)

	if n.IPv4AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv4AllocCIDR.String())
	}
	if n.IPv6AllocCIDR != nil {
		podCIDRs = append(podCIDRs, n.IPv6AllocCIDR.String())
	}
	if n.IPv4HealthIP != nil {
		healthIPv4 = n.IPv4HealthIP.String()
	}
	if n.IPv6HealthIP != nil {
		healthIPv6 = n.IPv6HealthIP.String()
	}

	for _, address := range n.IPAddresses {
		ipAddrs = append(ipAddrs, ciliumv2.NodeAddress{
			Type: address.Type,
			IP:   address.IP.String(),
		})
	}

	return &ciliumv2.CiliumNode{
		ObjectMeta: v1.ObjectMeta{
			Name: n.Name,
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: ipAddrs,
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: healthIPv4,
				IPv6: healthIPv6,
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: int(n.EncryptionKey),
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: podCIDRs,
			},
		},
	}
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

	// IPv6AllocCIDR if set, is the IPv6 address pool out of which the node
	// allocates IPs for local endpoints from
	IPv6AllocCIDR *cidr.CIDR

	// IPv4HealthIP if not nil, this is the IPv4 address of the
	// cilium-health endpoint located on the node.
	IPv4HealthIP net.IP

	// IPv6HealthIP if not nil, this is the IPv6 address of the
	// cilium-health endpoint located on the node.
	IPv6HealthIP net.IP

	// ClusterID is the unique identifier of the cluster
	ClusterID int

	// Source is the source where the node configuration was generated / created.
	Source source.Source

	// Key index used for transparent encryption or 0 for no encryption
	EncryptionKey uint8
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

func (n *Node) getNodeIP(ipv6 bool) (net.IP, addressing.AddressType) {
	var (
		backupIP net.IP
		ipType   addressing.AddressType
	)
	for _, addr := range n.IPAddresses {
		if (ipv6 && addr.IP.To4() != nil) ||
			(!ipv6 && addr.IP.To4() == nil) {
			continue
		}
		switch addr.Type {
		// Ignore CiliumInternalIPs
		case addressing.NodeCiliumInternalIP:
			continue
		// Always prefer a cluster internal IP
		case addressing.NodeInternalIP:
			return addr.IP, addr.Type
		case addressing.NodeExternalIP:
			// Fall back to external Node IP
			// if no internal IP could be found
			backupIP = addr.IP
			ipType = addr.Type
		default:
			// As a last resort, if no internal or external
			// IP was found, use any node address available
			if backupIP == nil {
				backupIP = addr.IP
				ipType = addr.Type
			}
		}
	}
	return backupIP, ipType
}

// GetNodeIP returns one of the node's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
func (n *Node) GetNodeIP(ipv6 bool) net.IP {
	result, _ := n.getNodeIP(ipv6)
	return result
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

func (n *Node) getPrimaryAddress() *models.NodeAddressing {
	v4, v4Type := n.getNodeIP(false)
	v6, v6Type := n.getNodeIP(true)

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
			Enabled:     option.Config.EnableIPv4,
			IP:          v4Str,
			AllocRange:  ipv4AllocStr,
			AddressType: string(v4Type),
		},
		IPV6: &models.NodeAddressingElement{
			Enabled:     option.Config.EnableIPv6,
			IP:          v6Str,
			AllocRange:  ipv6AllocStr,
			AddressType: string(v6Type),
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
				IP:          addr.IP.String(),
				AddressType: string(addr.Type),
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

// GetModel returns the API model representation of a node.
func (n *Node) GetModel() *models.NodeElement {
	return &models.NodeElement{
		Name:                  n.Fullname(),
		PrimaryAddress:        n.getPrimaryAddress(),
		SecondaryAddresses:    n.getSecondaryAddresses(),
		HealthEndpointAddress: n.getHealthAddresses(),
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
