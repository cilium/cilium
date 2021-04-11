// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.

package ipaddr

import "net"

// A Position represents a position on IP address space.
type Position struct {
	IP     net.IP // IP address
	Prefix Prefix // IP address prefix
}

// IsBroadcast reports whether p is an IPv4 directed or limited
// broadcast address.
func (p *Position) IsBroadcast() bool {
	return !p.IP.IsUnspecified() && !p.IP.IsMulticast() && p.IP.To4() != nil && (p.IP.Equal(net.IPv4bcast) || p.IP.Equal(p.Prefix.Last()))
}

// IsSubnetRouterAnycast reports whether p is an IPv6 subnet router
// anycast address.
func (p *Position) IsSubnetRouterAnycast() bool {
	return !p.IP.IsUnspecified() && !p.IP.IsLoopback() && !p.IP.IsMulticast() && p.IP.To16() != nil && p.IP.To4() == nil && p.IP.Equal(p.Prefix.IP)
}
