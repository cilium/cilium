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

package connector

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

func SetupVethRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) (int, int, error) {
	return 0, 0, netNs.Do(func(_ ns.NetNS) error {
		err := link.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename veth from %q to %q: %s", srcIfName, dstIfName, err)
		}
		return nil
	})
}

// SetupVeth sets up the net interface, the temporary interface and fills up some endpoint
// fields such as LXCMAC, NodeMac, IfIndex and IfName. Returns a pointer for the created
// veth, a pointer for the temporary link, the name of the temporary link and error if
// something fails.
func SetupVeth(id string, mtu int, ep *models.EndpointChangeRequest) (*netlink.Veth, *netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	lxcIfName := Endpoint2IfName(id)
	tmpIfName := Endpoint2TempIfName(id)

	veth, link, err := SetupVethWithNames(lxcIfName, tmpIfName, mtu, ep)
	return veth, link, tmpIfName, err
}

// SetupVethWithNames sets up the net interface, the temporary interface and fills up some endpoint
// fields such as LXCMAC, NodeMac, IfIndex and IfName. Returns a pointer for the created
// veth, a pointer for the temporary link, the name of the temporary link and error if
// something fails.
func SetupVethWithNames(lxcIfName, tmpIfName string, mtu int, ep *models.EndpointChangeRequest) (*netlink.Veth, *netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: lxcIfName},
		PeerName:  tmpIfName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("unable to create veth pair: %s", err)
	}
	var err error
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.WithError(err).WithField(logfields.Veth, veth.Name).Warn("failed to clean up veth")
			}
		}
	}()

	log.WithField(logfields.VethPair, []string{veth.PeerName, lxcIfName}).Debug("Created veth pair")

	// Disable reverse path filter on the host side veth peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	rpFilterPath := filepath.Join("/proc", "sys", "net", "ipv4", "conf", lxcIfName, "rp_filter")
	err = WriteSysConfig(rpFilterPath, "0\n")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to disable %s: %s", rpFilterPath, err)
	}

	peer, err := netlink.LinkByName(tmpIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth peer just created: %s", err)
	}

	if err = netlink.LinkSetMTU(peer, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", tmpIfName, err)
	}

	hostVeth, err := netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth just created: %s", err)
	}

	if err = netlink.LinkSetMTU(hostVeth, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	if err = netlink.LinkSetUp(veth); err != nil {
		return nil, nil, fmt.Errorf("unable to bring up veth pair: %s", err)
	}

	ep.Mac = peer.Attrs().HardwareAddr.String()
	ep.HostMac = hostVeth.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(hostVeth.Attrs().Index)
	ep.InterfaceName = lxcIfName

	return veth, &peer, nil
}
