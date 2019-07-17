// Copyright 2016-2018 Authors of Cilium
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

package route

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Route struct {
	Prefix  net.IPNet
	Nexthop *net.IP
	Local   net.IP
	Device  string
	MTU     int
	Proto   int
	Scope   netlink.Scope
	Table   int
	Type    int
}

// LogFields returns the route attributes as logrus.Fields map
func (r *Route) LogFields() logrus.Fields {
	return logrus.Fields{
		"prefix":            r.Prefix,
		"nexthop":           r.Nexthop,
		"local":             r.Local,
		logfields.Interface: r.Device,
	}
}

func (r *Route) getLogger() *logrus.Entry {
	return log.WithFields(r.LogFields())
}

// ByMask is used to sort an array of routes by mask, narrow first.
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	lenA, _ := a[i].Prefix.Mask.Size()
	lenB, _ := a[j].Prefix.Mask.Size()
	return lenA > lenB
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// ToIPCommand converts the route into a full "ip route ..." command
func (r *Route) ToIPCommand(dev string) []string {
	res := []string{"ip"}
	if r.Prefix.IP.To4() == nil {
		res = append(res, "-6")
	}
	res = append(res, "route", "add", r.Prefix.String())
	if r.Nexthop != nil {
		res = append(res, "via", r.Nexthop.String())
	}
	if r.MTU != 0 {
		res = append(res, "mtu", fmt.Sprintf("%d", r.MTU))
	}
	res = append(res, "dev", dev)
	return res
}

func lookupDefaultRoute(family int) (netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		log.WithError(err).Error("Unable to list direct routes")
		return netlink.Route{}, err
	}

	if len(routes) != 1 {
		return netlink.Route{}, fmt.Errorf("Multiple default routes found")
	}

	log.Debugf("Found default route on node %v", routes[0])
	return routes[0], nil
}

// NodeDeviceWithDefaultRoute returns the node's device which handles the
// default route in the current namespace
func NodeDeviceWithDefaultRoute() (netlink.Link, error) {
	linkIndex := 0
	if option.Config.EnableIPv4 {
		route, err := lookupDefaultRoute(netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		linkIndex = route.LinkIndex
	}
	if option.Config.EnableIPv6 {
		route, err := lookupDefaultRoute(netlink.FAMILY_V6)
		if err != nil {
			return nil, err
		}
		if linkIndex != 0 && linkIndex != route.LinkIndex {
			return nil, fmt.Errorf("IPv4/IPv6 have different link indices")
		}
		linkIndex = route.LinkIndex
	}
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return nil, err
	}
	return link, nil
}
