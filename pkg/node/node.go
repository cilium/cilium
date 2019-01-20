// Copyright 2016-2017 Authors of Cilium
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

package node

import (
	"encoding/json"
	"net"
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/node/addressing"
)

// Source is the description of the source of an identity
type Source string

const (
	// FromKubernetes is the source used for identities derived from k8s
	// resources (pods)
	FromKubernetes Source = "k8s"

	// FromKVStore is the source used for identities derived from the
	// kvstore
	FromKVStore Source = "kvstore"

	// FromAgentLocal is the source used for identities derived during the
	// agent bootup process. This includes identities for endpoint IPs.
	FromAgentLocal Source = "agent-local"

	// FromLocalNode is the source used for the local node
	FromLocalNode Source = "local-node"
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
	Source Source
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

func (n *Node) getPrimaryAddress(ipv4 bool) *models.NodeAddressing {
	v4, v4Type := n.getNodeIP(false)
	v6, v6Type := n.getNodeIP(true)

	var ipv4AllocStr, ipv6AllocStr string
	if n.IPv4AllocCIDR != nil {
		ipv4AllocStr = n.IPv4AllocCIDR.String()
	}
	if n.IPv6AllocCIDR != nil {
		ipv6AllocStr = n.IPv6AllocCIDR.String()
	}
	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled:     ipv4,
			IP:          v4.String(),
			AllocRange:  ipv4AllocStr,
			AddressType: string(v4Type),
		},
		IPV6: &models.NodeAddressingElement{
			Enabled:     !ipv4,
			IP:          v6.String(),
			AllocRange:  ipv6AllocStr,
			AddressType: string(v6Type),
		},
	}
}

func (n *Node) isPrimaryAddress(addr Address, ipv4 bool) bool {
	return addr.IP.String() == n.GetNodeIP(!ipv4).String()
}

func (n *Node) getSecondaryAddresses(ipv4 bool) []*models.NodeAddressingElement {
	result := []*models.NodeAddressingElement{}

	for _, addr := range n.IPAddresses {
		if !n.isPrimaryAddress(addr, ipv4) {
			result = append(result, &models.NodeAddressingElement{
				IP:          addr.IP.String(),
				AddressType: string(addr.Type),
			})
		}
	}

	return result
}

func (n *Node) getHealthAddresses(ipv4 bool) *models.NodeAddressing {
	if n.IPv4HealthIP == nil || n.IPv6HealthIP == nil {
		return nil
	}
	return &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled: ipv4,
			IP:      n.IPv4HealthIP.String(),
		},
		IPV6: &models.NodeAddressingElement{
			Enabled: !ipv4,
			IP:      n.IPv6HealthIP.String(),
		},
	}
}

// GetModel returns the API model representation of a node.
func (n *Node) GetModel(ipv4 bool) *models.NodeElement {
	return &models.NodeElement{
		Name:                  n.Fullname(),
		PrimaryAddress:        n.getPrimaryAddress(ipv4),
		SecondaryAddresses:    n.getSecondaryAddresses(ipv4),
		HealthEndpointAddress: n.getHealthAddresses(ipv4),
	}
}

// Identity returns the identity of the node
func (n *Node) Identity() Identity {
	return Identity{
		Name:    n.Name,
		Cluster: n.Cluster,
	}
}

// IsLocal returns true if this is the node on which the agent itself is
// running on
func (n *Node) IsLocal() bool {
	return n != nil && n.Name == GetName()
}

// PublicAttrEquals returns true only if the public attributes of both nodes
// are the same otherwise returns false.
func (n *Node) PublicAttrEquals(o *Node) bool {
	if (n == nil) != (o == nil) {
		return false
	}

	if n.Name == o.Name &&
		n.Cluster == o.Cluster &&
		n.IPv4HealthIP.Equal(o.IPv4HealthIP) &&
		n.IPv6HealthIP.Equal(o.IPv6HealthIP) &&
		n.ClusterID == o.ClusterID &&
		n.Source == o.Source {

		if len(n.IPAddresses) != len(o.IPAddresses) {
			return false
		}

		for i := range n.IPAddresses {
			if (n.IPAddresses[i].Type != o.IPAddresses[i].Type) ||
				!n.IPAddresses[i].IP.Equal(o.IPAddresses[i].IP) {
				return false
			}
		}

		if (n.IPv4AllocCIDR == nil) != (o.IPv4AllocCIDR == nil) {
			return false
		}
		if n.IPv4AllocCIDR.String() != o.IPv4AllocCIDR.String() {
			return false
		}

		if (n.IPv6AllocCIDR == nil) != (o.IPv6AllocCIDR == nil) {
			return false
		}
		if n.IPv6AllocCIDR.String() != o.IPv6AllocCIDR.String() {
			return false
		}

		return true
	}

	return false
}

// GetKeyName returns the kvstore key to be used for the node
func (n *Node) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(n.Cluster, n.Name)
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
