// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipaddr

import (
	"net"
	"strings"
)

// Parse parses s as a single or combination of multiple IP addresses
// and IP address prefixes.
//
// Examples:
//
//	Parse("192.0.2.1")
//	Parse("2001:db8::1/128")
//	Parse("203.0.113.0/24")
//	Parse("192.0.2.1,2001:db8::1/128,203.0.113.0/24")
func Parse(s string) (*Cursor, error) {
	poss, ps, err := parseMulti(s)
	if err != nil {
		return nil, err
	}
	if len(ps) == 1 {
		c := NewCursor(ps)
		if err := c.Set(&poss[0]); err != nil {
			return nil, err
		}
		return c, nil
	}
	return NewCursor(ps), nil
}

func parseMulti(s string) ([]Position, []Prefix, error) {
	ss := strings.Split(s, ",")
	var poss []Position
	var ps []Prefix
	for _, s := range ss {
		s = strings.TrimSpace(s)
		pos, p, err := parse(s)
		if err != nil {
			return nil, nil, err
		}
		poss = append(poss, *pos)
		ps = append(ps, *p)
	}
	return poss, ps, nil
}

func parse(s string) (*Position, *Prefix, error) {
	ip, n, err := net.ParseCIDR(s)
	if err == nil {
		p := NewPrefix(n)
		pos := Position{IP: ip, Prefix: *p}
		return &pos, p, nil
	}
	ip = net.ParseIP(s)
	if ip == nil {
		return nil, nil, &net.AddrError{Err: "invalid address", Addr: s}
	}
	var m net.IPMask
	if ip.To4() != nil {
		m = net.CIDRMask(IPv4PrefixLen, IPv4PrefixLen)
	}
	if ip.To16() != nil && ip.To4() == nil {
		m = net.CIDRMask(IPv6PrefixLen, IPv6PrefixLen)
	}
	p := NewPrefix(&net.IPNet{IP: ip, Mask: m})
	return &Position{IP: ip, Prefix: *p}, p, nil
}
