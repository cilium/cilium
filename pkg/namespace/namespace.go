// Copyright 2018 Authors of Cilium
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

package namespace

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type HealthNetns struct {
	HostDevName  string
	NetnsDevName string
	IPv6Cidr     string
	IPv4Cidr     string

	oldNetns netns.NsHandle
	newNetns netns.NsHandle

	hostDev  netlink.Link
	netnsDev netlink.Link

	ipv6Addr *netlink.Addr
	ipv4Addr *netlink.Addr
}

func (n *HealthNetns) fetchDevices() error {
	hostDev, err := netlink.LinkByName(n.HostDevName)
	if err != nil {
		return fmt.Errorf("could not find the host link %s: %s", n.HostDevName, err)
	}
	n.hostDev = hostDev

	netnsDev, err := netlink.LinkByName(n.NetnsDevName)
	if err != nil {
		return fmt.Errorf("could not find the network namespace link %s: %s", n.NetnsDevName, err)
	}
	n.netnsDev = netnsDev

	return nil
}

func (n *HealthNetns) configureHost() error {
	if err := netlink.LinkSetUp(n.hostDev); err != nil {
		return fmt.Errorf("could not set up the link %s: %s", n.HostDevName, err)
	}

	if err := netlink.LinkSetNsFd(n.netnsDev, int(n.newNetns)); err != nil {
		return fmt.Errorf("could not put the device %s into the new network namespace: %s", n.NetnsDevName, err)
	}

	return nil
}

func (n *HealthNetns) configureNetns() error {
	if err := netlink.LinkSetUp(n.netnsDev); err != nil {
		return fmt.Errorf("could not set up the link %s: %s", n.NetnsDevName, err)
	}

	ipv6Addr, err := netlink.ParseAddr(n.IPv6Cidr)
	if err != nil {
		return fmt.Errorf("could not parse IPv6 address %s: %s", n.IPv6Cidr, err)
	}
	n.ipv6Addr = ipv6Addr
	if err := netlink.AddrAdd(n.netnsDev, ipv6Addr); err != nil {
		return fmt.Errorf("could not add IP address %s to the netns link: %s", n.IPv6Cidr, err)
	}

	if n.IPv4Cidr != "" {
		ipv4Addr, err := netlink.ParseAddr(n.IPv4Cidr)
		if err != nil {
			return fmt.Errorf("could not parse IPv4 address %s: %s", n.IPv4Cidr, err)
		}
		n.ipv4Addr = ipv4Addr
		if err := netlink.AddrAdd(n.netnsDev, ipv4Addr); err != nil {
			return fmt.Errorf("could not add IP address %s to the netns link: %s", n.IPv4Cidr, err)
		}
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("could not find the lo link: %s", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("could not set up the lo link: %s", err)
	}

	return nil
}

func (n *HealthNetns) Spawn() error {
	oldNetns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("could not get the current network namespace: %s", err)
	}
	n.oldNetns = oldNetns

	newNetns, err := netns.New()
	if err != nil {
		return fmt.Errorf("could not create the new network namespace: %s", err)
	}
	n.newNetns = newNetns

	if err := n.fetchDevices(); err != nil {
		return err
	}
	if err := n.configureHost(); err != nil {
		return err
	}

	if err := netns.Set(newNetns); err != nil {
		return fmt.Errorf("could not set the new network namespace: %s", err)
	}

	if err := n.configureNetns(); err != nil {
		return err
	}

	return nil
}

func (n *HealthNetns) Unspawn() {
	netlink.LinkSetDown(n.netnsDev)
	netlink.AddrDel(n.netnsDev, n.ipv6Addr)
	if n.ipv4Addr != nil {
		netlink.AddrDel(n.netnsDev, n.ipv4Addr)
	}
	netlink.LinkSetNsFd(n.netnsDev, int(n.oldNetns))

	netns.Set(n.oldNetns)

	n.oldNetns.Close()
	n.newNetns.Close()
}
