package types

import (
	"net"
)

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

// Route is the routing representation of an IPConfig
type Route struct {
	Destination net.IPNet
	NextHop     net.IP
	Type        int
}

// TODO: Add proper methods to check if a route is l3 or l2 and finish route docs
