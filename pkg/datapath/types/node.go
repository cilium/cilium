// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
)

type MTUConfiguration interface {
	GetDeviceMTU() int
	GetRouteMTU() int
}

// LocalNodeConfiguration represents the configuration of the local node
//
// This configuration struct is immutable even when passed by reference.
// When the configuration is changed at runtime a new instance is allocated
// and passed down.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type LocalNodeConfiguration struct {
	// NodeIPv4 is the primary IPv4 address of this node.
	// Mutable at runtime.
	// +deepequal-gen=false
	NodeIPv4 netip.Addr

	// NodeIPv6 is the primary IPv6 address of this node.
	// Mutable at runtime.
	// +deepequal-gen=false
	NodeIPv6 netip.Addr

	// CiliumInternalIPv4 is the internal IP address assigned to the cilium_host
	// interface.
	// Immutable at runtime.
	// +deepequal-gen=false
	CiliumInternalIPv4 netip.Addr

	// CiliumInternalIPv6 is the internal IP address assigned to the cilium_host
	// interface.
	// Immutable at runtime.
	// +deepequal-gen=false
	CiliumInternalIPv6 netip.Addr

	// AllocCIDRIPv4 is the IPv4 allocation CIDR from which IP addresses for
	// endpoints are allocated from.
	// Immutable at runtime.
	AllocCIDRIPv4 *cidr.CIDR

	// AllocCIDRIPv6 is the IPv6 allocation CIDR from which IP addresses for
	// endpoints are allocated from.
	// Immutable at runtime.
	AllocCIDRIPv6 *cidr.CIDR

	// NativeRoutingCIDRIPv4 is the v4 CIDR in which pod IPs are routable.
	NativeRoutingCIDRIPv4 *cidr.CIDR

	// NativeRoutingCIDRIPv6 is the v4 CIDR in which pod IPs are routable.
	NativeRoutingCIDRIPv6 *cidr.CIDR

	// LoopbackIPv4 is the source address used for SNAT when a Pod talks to itself
	// over a Service.
	//
	// Immutable at runtime.
	// +deepequal-gen=false
	ServiceLoopbackIPv4 netip.Addr

	// ServiceLoopbackIPv6 is the source address used for SNAT when a Pod talks to itself
	// over a Service.
	// Immutable at runtime.
	// +deepequal-gen=false
	ServiceLoopbackIPv6 netip.Addr

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

	// DeriveMasqIPAddrFromDevice overrides the interface name to use for deriving
	// the masquerading IP address for the node.
	DeriveMasqIPAddrFromDevice string

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

	// TunnelProtocol is the datapath ID of the encapsulation protocol
	// (0 if disabled, 1 for VXLAN, 2 for Geneve).
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	TunnelProtocol tunnel.BPFEncapProtocol

	// TunnelPort is the UDP port used by the tunnel protocol (0 if disabled).
	//
	// This field is immutable at runtime. The value will not change in
	// subsequent calls to NodeConfigurationChanged().
	TunnelPort uint16

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

	// DatapathIsLayer2 holds the configuration for whether the underlying
	// connector to Pods on this node operate at Layer 2.
	DatapathIsLayer2 bool

	// DatapathIsNetkit holds the configuration for whether the underlying
	// connector to pods on this node is Netkit or not.
	DatapathIsNetkit bool

	// EnableWireguard is used to check if we need to attach to the native
	// device and to cilium_wg0.
	EnableWireguard bool

	// Ephemeral port range minimun.
	EphemeralMin uint16

	// Index of the cilium_wg0 interface if enabled.
	WireguardIfIndex uint32

	// EnableIPSec enables IPSec routes
	EnableIPSec bool

	// EncryptNode enables encrypting NodeIP traffic
	EncryptNode bool

	// EnablePolicyAccounting enables maintaining packet and byte counters for every
	// policy entry
	EnablePolicyAccounting bool

	// Enable per flow (conntrack) statistics
	EnableConntrackAccounting bool

	// IPv4PodSubnets is a list of IPv4 subnets that pod IPs are assigned from
	// these are then used when encryption is enabled to configure the node
	// for encryption over these subnets at node initialization.
	IPv4PodSubnets []*cidr.CIDR

	// IPv6PodSubnets is a list of IPv6 subnets that pod IPs are assigned from
	// these are then used when encryption is enabled to configure the node
	// for encryption over these subnets at node initialization.
	IPv6PodSubnets []*cidr.CIDR

	// XDPConfig holds configuration options to determine how the node should
	// handle XDP programs.
	XDPConfig xdp.Config

	// LBConfig holds the configuration options for load-balancing
	LBConfig loadbalancer.Config

	// Maglev configuration provides the maglev table sizes and seeds for
	// the BPF programs.
	MaglevConfig maglev.Config

	KPRConfig kpr.KPRConfig

	SvcRouteConfig svcrouteconfig.RoutesConfig
}

// DeepEqual compares two LocalNodeConfiguration structs for equality.
func (cfg *LocalNodeConfiguration) DeepEqual(other *LocalNodeConfiguration) bool {
	if other == nil {
		return false
	}
	// Manually compare netip.Addr fields
	if cfg.NodeIPv4 != other.NodeIPv4 {
		return false
	}
	if cfg.NodeIPv6 != other.NodeIPv6 {
		return false
	}
	if cfg.CiliumInternalIPv4 != other.CiliumInternalIPv4 {
		return false
	}
	if cfg.CiliumInternalIPv6 != other.CiliumInternalIPv6 {
		return false
	}
	if cfg.ServiceLoopbackIPv4 != other.ServiceLoopbackIPv4 {
		return false
	}
	if cfg.ServiceLoopbackIPv6 != other.ServiceLoopbackIPv6 {
		return false
	}
	// Call generated `deepEqual` method which compares all other fields
	return cfg.deepEqual(other)
}

func (cfg *LocalNodeConfiguration) DeviceNames() []string {
	return tables.DeviceNames(cfg.Devices)
}

func (cfg *LocalNodeConfiguration) GetIPv4PodSubnets() []*net.IPNet {
	return cidr.CIDRsToIPNets(cfg.IPv4PodSubnets)
}

func (cfg *LocalNodeConfiguration) GetIPv6PodSubnets() []*net.IPNet {
	return cidr.CIDRsToIPNets(cfg.IPv6PodSubnets)
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
}

type NodeConfigChangeHandler interface {
	// NodeConfigurationChanged is called when the local node configuration
	// has changed
	NodeConfigurationChanged(config LocalNodeConfiguration) error
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
