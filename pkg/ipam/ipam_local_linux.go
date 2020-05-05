// Copyright 2017-2020 Authors of Cilium
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

//+build linux

package ipam

import (
	"github.com/cilium/cilium/pkg/defaults"

	"github.com/vishvananda/netlink"
)

func (ipam *IPAM) reserveLocalRoutes() {
	log.Debug("Checking local routes for conflicts...")

	link, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil || link == nil {
		log.WithError(err).Warnf("Unable to find net_device %s", defaults.HostDevice)
		return
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Warn("Unable to retrieve local routes")
		return
	}

	for _, r := range routes {
		// ignore routes which point to defaults.HostDevice
		if r.LinkIndex == link.Attrs().Index {
			log.WithField("route", r).Debugf("Ignoring route: points to %s", defaults.HostDevice)
			continue
		}

		if r.Dst == nil {
			log.WithField("route", r).Debug("Ignoring route: no destination address")
			continue
		}

		// ignore black hole route
		if r.Src == nil && r.Gw == nil {
			log.WithField("route", r).Debugf("Ignoring route: black hole")
			continue
		}

		log.WithField("route", r.Dst).Info("Blacklisting local route as no-alloc")
		ipam.BlacklistIPNet(*r.Dst, "local route: "+r.Dst.String())
	}
}
