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

package mtu

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/logging"

	"github.com/vishvananda/netlink"
)

var log = logging.DefaultLogger

const (
	externalProbe = "1.1.1.1"
)

func autoDetect() (int, error) {
	ip := net.ParseIP(externalProbe)
	if ip == nil {
		return 0, fmt.Errorf("unable to parse IP %s", externalProbe)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return 0, fmt.Errorf("unable to lookup route to %s: %s", externalProbe, err)
	}

	if len(routes) == 0 {
		return 0, fmt.Errorf("no route to %s", externalProbe)
	}

	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return 0, fmt.Errorf("unable to find interface of default route: %s", err)
	}

	if mtu := link.Attrs().MTU; mtu != 0 {
		log.Infof("Detected MTU %d", mtu)
		return mtu, nil
	}

	return StandardMTU, nil
}

// AutoDetect tries to automatically detect the MTU of the underlying network
func AutoDetect() int {
	mtu, err := autoDetect()
	if err != nil {
		log.WithError(err).Warning("Unable to automatically detect MTU")
		return StandardMTU
	}

	return mtu
}
