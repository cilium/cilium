package types

import (
	"net"
)

type IPAMConfig struct {
	IP6 *IPConfig
	IP4 *IPConfig
}

type IPConfig struct {
	Gateway net.IP
	IP      net.IPNet
	Routes  []Route
}

type Route struct {
	Destination net.IPNet
	NextHop     net.IP
	Type        int
}
