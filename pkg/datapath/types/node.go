// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type MTUConfiguration interface {
	GetDeviceMTU() int
	GetRouteMTU() int
	GetRoutePostEncryptMTU() int
}

// LocalNodeConfiguration represents the configuration of the local node
//
// This configuration struct is immutable even when passed by reference.
// When the configuration is changed at runtime a new instance is allocated
// and passed down.
type LocalNodeConfiguration struct {
	// NodeIPv4 is the primary IPv4 address of this node.
	// Mutable at runtime.
	NodeIPv4 net.IP

	// NodeIPv6 is the primary IPv6 address of this node.
	// Mutable at runtime.
	NodeIPv6 net.IP

	// CiliumInternalIPv4 is the internal IP address assigned to the cilium_host
	// interface.
	// Immutable at runtime.
	CiliumInternalIPv4 net.IP

	// CiliumInternalIPv6 is the internal IP address assigned to the cilium_host
	// interface.
	// Immutable at runtime.
	CiliumInternalIPv6 net.IP

	// AllocCIDRIPv4 is the IPv4 allocation CIDR from which IP addresses for
	// endpoints are allocated from.
	// Immutable at runtime.
	AllocCIDRIPv4 *cidr.CIDR

	// AllocCIDRIPv6 is the IPv6 allocation CIDR from which IP addresses for
	// endpoints are allocated from.
	// Immutable at runtime.
	AllocCIDRIPv6 *cidr.CIDR

	// LoopbackIPv4 is the IPv4 loopback address.
	// Immutable at runtime.
	LoopbackIPv4 net.IP

	// Devices is the native network devices selected for datapath use.
	// Mutable at runtime.
	Devices []*tables.Device

	// DirectRoutingDevice is the device used in direct routing mode.
	// Mutable at runtime.
	DirectRoutingDevice *tables.Device

	// NodeAddresses are the IP addresses of the local node that are considered
	// as this node's addresses. From this set we pick the addresses that are
	// used as NodePort frontends and the addresses to use for BPF masquerading.
	// Mutable at runtime.
	NodeAddresses []tables.NodeAddress

	// HostEndpointID is the endpoint ID assigned to the host endpoint.
	// Immutable at runtime.
	HostEndpointID uint64

	// DeviceMTU is the MTU used on workload facing devices.
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	DeviceMTU int

	// RouteMTU is the MTU used on the network.
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	RouteMTU int

	// RoutePostEncryptMTU is the MTU without the encryption overhead
	// included.
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	RoutePostEncryptMTU int

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

	// DirectRoutingSkipUnreachable will skip any direct routes between
	// nodes if they have different L2 connectivity, only adding L2 routes
	// if the underlying L2 shares the same gateway.
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	DirectRoutingSkipUnreachable bool

	// EnableLocalNodeRoute enables installation of the route which points
	// the allocation prefix of the local node. Disabling this option is
	// useful when another component is responsible for the routing of the
	// allocation CIDR IPs into Cilium endpoints.
	EnableLocalNodeRoute bool

	// EnableIPSec enables IPSec routes
	EnableIPSec bool

	// EnableIPSecEncryptedOverlay enables IPSec routes for overlay traffic
	EnableIPSecEncryptedOverlay bool

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

func (cfg *LocalNodeConfiguration) DeviceNames() []string {
	return tables.DeviceNames(cfg.Devices)
}

// NodeHandler handles node related events such as addition, update or deletion
// of nodes or changes to the local node configuration.
//
// Node events apply to the local node as well as to remote nodes. The
// implementation can differ between the own local node and remote nodes by
// calling node.IsLocal().
type NodeHandler interface {
	// Name identifies the handler, this is used in logging/reporting handler
	// reconciliation errors.
	Name() string

	// NodeAdd is called when a node is discovered for the first time.
	NodeAdd(newNode nodeTypes.Node) error

	// NodeUpdate is called when a node definition changes. Both the old
	// and new node definition is provided. NodeUpdate() is never called
	// before NodeAdd() is called for a particular node.
	NodeUpdate(oldNode, newNode nodeTypes.Node) error

	// NodeDelete is called after a node has been deleted
	NodeDelete(node nodeTypes.Node) error

	// AllNodeValidateImplementation is called to validate the implementation
	// of all nodes in the node cache.
	AllNodeValidateImplementation()

	// NodeValidateImplementation is called to validate the implementation of
	// the node in the datapath. This function is intended to be run on an
	// interval to ensure that the datapath is consistently converged.
	NodeValidateImplementation(node nodeTypes.Node) error

	// NodeConfigurationChanged is called when the local node configuration
	// has changed
	NodeConfigurationChanged(config LocalNodeConfiguration) error
}

type NodeNeighbors interface {
	// NodeNeighDiscoveryEnabled returns whether node neighbor discovery is enabled
	NodeNeighDiscoveryEnabled() bool

	// NodeNeighborRefresh is called to refresh node neighbor table
	NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node, refresh bool) error

	// NodeCleanNeighbors cleans all neighbor entries for the direct routing device
	// and the encrypt interface.
	NodeCleanNeighbors(migrateOnly bool)

	// InsertMiscNeighbor inserts a neighbor entry for the address passed via newNode.
	// This is needed for in-agent users where neighbors outside the cluster need to
	// be added, for example, for external service backends.
	InsertMiscNeighbor(newNode *nodeTypes.Node)

	// DeleteMiscNeighbor delets a eighbor entry for the address passed via oldNode.
	// This is needed to delete the entries which have been inserted at an earlier
	// point in time through InsertMiscNeighbor.
	DeleteMiscNeighbor(oldNode *nodeTypes.Node)
}

type NodeIDHandler interface {
	// GetNodeIP returns the string node IP that was previously registered as the given node ID.
	GetNodeIP(uint16) string

	// GetNodeID gets the node ID for the given node IP. If none is found, exists is false.
	GetNodeID(nodeIP net.IP) (nodeID uint16, exists bool)

	// DumpNodeIDs returns all node IDs and their associated IP addresses.
	DumpNodeIDs() []*models.NodeID

	// RestoreNodeIDs restores node IDs and their associated IP addresses from the
	// BPF map and into the node handler in-memory copy.
	RestoreNodeIDs()
}
