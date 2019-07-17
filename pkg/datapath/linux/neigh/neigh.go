// Copyright 2019 Authors of Cilium
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

package neigh

import (
	"net"

	"github.com/cilium/arping"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func NeighAddAddress(device string, address net.IP) error {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		logrus.WithError(err).Error("Unable to retrieve default route device")
		return err
	}
	_, err = arping.FindIPInNetworkFromIface(address, *iface)
	if err != nil {
		return nil
	}
	hwAddr, _, err := arping.PingOverIface(address, *iface)
	if err != nil {
		logrus.WithError(err).Errorf("Unable to perform ARP request for %s", address)
		return err
	}
	neigh := netlink.Neigh{
		LinkIndex:    iface.Index,
		IP:           address,
		HardwareAddr: hwAddr,
		State:        netlink.NUD_PERMANENT,
	}
	err = netlink.NeighSet(&neigh)
	if err != nil {
		logrus.WithError(err).Errorf("Unable to set neigh entry for %s", address)
	}
	return err
}
