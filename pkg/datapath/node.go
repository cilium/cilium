// Copyright 2018-2019 Authors of Cilium
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

package datapath

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/mtu"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// LocalNodeConfiguration represents the configuration of the local node
type LocalNodeConfiguration struct {
	// MtuConfig is the MTU configuration of the node.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	MtuConfig mtu.Configuration

	// AuxiliaryPrefixes is the list of auxiliary prefixes that should be
	// configured in addition to the node PodCIDR
	//
	// This field is mutable. The implementation of
	// NodeConfigurationChanged() must adjust the routes accordingly.
	AuxiliaryPrefixes []*cidr.CIDR

	// EnableIPv4 enables use of IPv4. Routing to the IPv4 allocation CIDR
	// of other nodes must be enabled.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	EnableIPv4 bool

	// EnableIPv6 enables use of IPv6. Routing to the IPv6 allocation CIDR
	// of other nodes must be enabled.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	EnableIPv6 bool

	// UseSingleClusterRoute enables the use of a single cluster-wide route
	// to direct traffic from the host into the Cilium datapath.  This
	// avoids the requirement to install a separate route for each node
	// CIDR and can thus improve the overhead when operating large clusters
	// with significant node event churn due to auto-scaling.
	//
	// Use of UseSingleClusterRoute must be compatible with
	// EnableAutoDirectRouting. When both are enabled, any direct node
	// route must take precedence over the cluster-wide route as per LPM
	// routing definition.
	//
	// This field is mutable. The implementation of
	// NodeConfigurationChanged() must adjust the routes accordingly.
	UseSingleClusterRoute bool

	// EnableEncapsulation enables use of encapsulation in communication
	// between nodes.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	EnableEncapsulation bool

	// EnableAutoDirectRouting enables the use of direct routes for
	// communication between nodes if two nodes have direct L2
	// connectivity.
	//
	// EnableAutoDirectRouting must be compatible with EnableEncapsulation
	// and must provide a fallback to use encapsulation if direct routing
	// is not feasible and encapsulation is enabled.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	EnableAutoDirectRouting bool

	// EnableLocalNodeRoute enables installation of the route which points
	// the allocation prefix of the local node. Disabling this option is
	// useful when another component is responsible for the routing of the
	// allocation CIDR IPs into Cilium endpoints.
	EnableLocalNodeRoute bool

	// EnableIPSec enables IPSec routes
	EnableIPSec bool

	// EncryptNode enables encrypting NodeIP traffic requires EnableIPSec
	EncryptNode bool

	// IPv4PodSubnets is a list of IPv4 subnets that pod IPs are assigned from
	// these are then used when encryption is enabled to configure the node
	// for encryption over these subnets at node initialization.
	IPv4PodSubnets []*net.IPNet

	// IPv6PodSubnets is a list of IPv6 subnets that pod IPs are assigned from
	// these are then used when encryption is enabled to configure the node
	// for encryption over these subnets at node initialization.
	IPv6PodSubnets []*net.IPNet
}

// NodeHandler handles node related events such as addition, update or deletion
// of nodes or changes to the local node configuration.
//
// Node events apply to the local node as well as to remote nodes. The
// implementation can differ between the own local node and remote nodes by
// calling node.IsLocal().
type NodeHandler interface {
	// NodeAdd is called when a node is discovered for the first time.
	NodeAdd(newNode nodeTypes.Node) error

	// NodeUpdate is called when a node definition changes. Both the old
	// and new node definition is provided. NodeUpdate() is never called
	// before NodeAdd() is called for a particular node.
	NodeUpdate(oldNode, newNode nodeTypes.Node) error

	// NodeDelete is called after a node has been deleted
	NodeDelete(node nodeTypes.Node) error

	// NodeValidateImplementation is called to validate the implementation
	// of the node in the datapath
	NodeValidateImplementation(node nodeTypes.Node) error

	// NodeConfigurationChanged is called when the local node configuration
	// has changed
	NodeConfigurationChanged(config LocalNodeConfiguration) error

	// NodeNeighDiscoveryEnabled returns whether node neighbor discovery is enabled
	NodeNeighDiscoveryEnabled() bool

	// NodeNeighborRefresh is called to refresh node neighbor table
	NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node)

	// NodeCleanNeighbors cleans all neighbor entries for the direct routing device
	// and the encrypt interface.
	NodeCleanNeighbors()
}
