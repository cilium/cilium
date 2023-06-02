// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package mtu

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// externalProbeIPv4 is an IPv4 address specifically designed for tests. We
	// only want to retrieve default route for external IP addresses, thus it
	// doesn't need to be a real address.
	externalProbeIPv4 = "203.0.113.1"

	// externalProbeIPv6 is an IPv4 address specifically designed for tests. We
	// only want to retrieve default route for external IP addresses, thus it
	// doesn't need to be a real address.
	externalProbeIPv6 = "2001:db8::1"
)

func getRoute(externalProbe string) ([]netlink.Route, error) {
	ip := net.ParseIP(externalProbe)
	if ip == nil {
		return nil, fmt.Errorf("unable to parse IP %s", externalProbe)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup route to %s: %w", externalProbe, err)
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no route to %s", externalProbe)
	}

	return routes, nil
}

func autoDetect() (int, error) {
	var routes []netlink.Route
	var err error

	routes, err = getRoute(externalProbeIPv4)
	if err != nil {
		prevErr := err
		routes, err = getRoute(externalProbeIPv6)
		if err != nil {
			return 0, fmt.Errorf("%v, %v", err.Error(), prevErr.Error())
		}
	}

	if routes[0].Gw == nil {
		return 0, fmt.Errorf("unable to find default gateway from the routes: %s", routes)
	}

	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return 0, fmt.Errorf("unable to find interface of default route: %w", err)
	}

	if mtu := link.Attrs().MTU; mtu != 0 {
		log.Infof("Detected MTU %d", mtu)
		return mtu, nil
	}

	return EthernetMTU, nil
}

// getMTUFromIf finds the interface that holds the ip and returns its mtu
func getMTUFromIf(ip net.IP) (int, error) {
	ifaces, err := netlink.LinkList()
	if err != nil {
		return 0, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.Device: iface.Attrs().Name,
			}).Warning("Unable to list all addresses")
			continue
		}

		for _, addr := range addrs {
			if addr.IPNet.IP.Equal(ip) {
				myMTU := iface.Attrs().MTU
				log.WithFields(logrus.Fields{
					logfields.Device: iface.Attrs().Name,
					logfields.IPAddr: ip,
					logfields.MTU:    myMTU,
				}).Info("Inheriting MTU from external network interface")
				return myMTU, nil
			}
		}
	}
	return 0, fmt.Errorf("No interface contains the provided ip: %v", ip)
}
