// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//go:build linux
// +build linux

package config

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func GetIPv6LinkLocalNeighborAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	neighs, err := netlink.NeighList(ifi.Index, netlink.FAMILY_V6)
	if err != nil {
		return "", err
	}
	cnt := 0
	var addr net.IP
	for _, neigh := range neighs {
		local, err := isLocalLinkLocalAddress(ifi.Index, neigh.IP)
		if err != nil {
			return "", err
		}
		if neigh.State&netlink.NUD_FAILED == 0 && neigh.IP.IsLinkLocalUnicast() && !local {
			addr = neigh.IP
			cnt++
		}
	}

	if cnt == 0 {
		return "", fmt.Errorf("no ipv6 link-local neighbor found")
	} else if cnt > 1 {
		return "", fmt.Errorf("found %d link-local neighbors. only support p2p link", cnt)
	}

	return fmt.Sprintf("%s%%%s", addr, ifname), nil
}

func isLocalLinkLocalAddress(ifindex int, addr net.IP) (bool, error) {
	ifi, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return false, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if ip, _, _ := net.ParseCIDR(a.String()); addr.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}
