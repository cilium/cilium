package types

import (
	"net"

	libnetworktypes "github.com/docker/libnetwork/types"
)

type IPAMType string

const (
	CNIIPAMType IPAMType = "cni-host-local"
)

type IPAMReq struct {
	ContainerID string
}

// IPAMConfig contains both IPv4 and IPv6 IPAM configuration.
type IPAMConfig struct {
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
		ciliumRoute.Type = libnetworktypes.CONNECTED
	} else {
		ciliumRoute.Type = libnetworktypes.NEXTHOP
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
