package types

import (
	"net"
	"sync"

	hb "github.com/appc/cni/plugins/ipam/host-local/backend"
	lnAPI "github.com/docker/libnetwork/ipams/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"k8s.io/kubernetes/pkg/registry/service/ipallocator"
)

type IPAMType string

const (
	// CNIIPAMType
	CNIIPAMType IPAMType = "cni-host-local"
	// LibnetworkIPAMType
	LibnetworkIPAMType IPAMType = "libnetwork"

	// LibnetworkDefaultPoolV4 is the IPv4 pool name for libnetwork.
	LibnetworkDefaultPoolV4 = "CiliumPoolv4"
	// LibnetworkDefaultPoolV6 is the IPv6 pool name for libnetwork.
	LibnetworkDefaultPoolV6 = "CiliumPoolv6"
	// LibnetworkDummyV4AllocPool is never exposed, makes libnetwork happy.
	LibnetworkDummyV4AllocPool = "0.0.0.0/0"
	// LibnetworkDummyV4Gateway is never exposed, makes libnetwork happy.
	LibnetworkDummyV4Gateway = "1.1.1.1/32"
)

// IPAMConfig is the IPAM configuration used for a particular IPAM type.
type IPAMConfig struct {
	IPAMConfig    hb.IPAMConfig
	IPAllocator   *ipallocator.Range
	IPAllocatorMU sync.Mutex
}

// IPAMReq is used for IPAM request operation.
type IPAMReq struct {
	ContainerID           string                       `json:",omitempty"`
	IP                    *net.IP                      `json:",omitempty"`
	RequestPoolRequest    *lnAPI.RequestPoolRequest    `json:",omitempty"`
	RequestAddressRequest *lnAPI.RequestAddressRequest `json:",omitempty"`
	ReleaseAddressRequest *lnAPI.ReleaseAddressRequest `json:",omitempty"`
}

// IPAMConfigRep is used for IPAM configuration reply messages.
type IPAMConfigRep struct {
	RequestPoolResponse *lnAPI.RequestPoolResponse `json:",omitempty"`
	IPAMConfig          *IPAMRep                   `json:",omitempty"`
}

// IPAMRep contains both IPv4 and IPv6 IPAM configuration.
type IPAMRep struct {
	// IPv6 configuration.
	IP6 *IPConfig
	// IPv4 configuration.
	IP4 *IPConfig
}

// IPConfig is our network representation of an IP configuration.
type IPConfig struct {
	// Gateway for this IP configuration.
	Gateway net.IP
	// IP of the configuration.
	IP net.IPNet
	// Routes for this IP configuration.
	Routes []Route
}

// Route is the routing representation of an IPConfig. It can be a L2 or L3 route
// depending if NextHop is nil or not.
type Route struct {
	Destination net.IPNet
	NextHop     net.IP
	Type        int
}

// NewRoute returns a Route from dst and nextHop with the proper libnetwork type based on
// NextHop being nil or not.
func NewRoute(dst net.IPNet, nextHop net.IP) *Route {
	ciliumRoute := &Route{
		Destination: dst,
		NextHop:     nextHop,
	}
	if nextHop == nil {
		ciliumRoute.Type = lnTypes.CONNECTED
	} else {
		ciliumRoute.Type = lnTypes.NEXTHOP
	}
	return ciliumRoute
}

// IsL2 returns true if the route represents a L2 route and false otherwise.
func (r *Route) IsL2() bool {
	return r.NextHop == nil
}

// IsL3 returns true if the route represents a L3 route and false otherwise.
func (r *Route) IsL3() bool {
	return r.NextHop != nil
}
