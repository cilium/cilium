// Copyright 2016-2017 Authors of Cilium
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

package plugins

import (
	"fmt"
	"os/exec"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/op/go-logging"
	"github.com/vishvananda/netlink"
)

const (
	// hostInterfacePrefix is the Host interface prefix.
	hostInterfacePrefix = "lxc"
	// temporaryInterfacePrefix is the temporary interface prefix while setting up libNetwork interface.
	temporaryInterfacePrefix = "tmp"
)

var (
	log = logging.MustGetLogger("cilium-net")
)

// Endpoint2IfName returns the host interface name for the given endpointID.
func Endpoint2IfName(endpointID string) string {
	return hostInterfacePrefix + endpointID[:5]
}

// SetupVeth sets up the net interface, the temporary interface and fills up some endpoint
// fields such as LXCMAC, NodeMac, IfIndex and IfName. Returns a pointer for the created
// veth, a pointer for the temporary link, the name of the temporary link and error if
// something fails.
func SetupVeth(id string, mtu int, ep *models.EndpointChangeRequest) (*netlink.Veth, *netlink.Link, string, error) {

	lxcIfName := Endpoint2IfName(id)
	tmpIfName := temporaryInterfacePrefix + id[:5]

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: lxcIfName},
		PeerName:  tmpIfName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, "", fmt.Errorf("unable to create veth pair: %s", err)
	}
	var err error
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.Warningf("failed to clean up veth %q: %s", veth.Name, err)
			}
		}
	}()

	log.Debugf("Created veth pair %s <-> %s", lxcIfName, veth.PeerName)

	// Disable reverse path filter on the host side veth peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	args := []string{"-w", "net.ipv4.conf." + lxcIfName + ".rp_filter=0"}
	_, err = exec.Command("sysctl", args...).CombinedOutput()
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to disable rp_filter on %s: %s",
			lxcIfName, err)
	}

	peer, err := netlink.LinkByName(tmpIfName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to lookup veth peer just created: %s", err)
	}

	if err = netlink.LinkSetMTU(peer, mtu); err != nil {
		return nil, nil, "", fmt.Errorf("unable to set MTU to %q: %s", tmpIfName, err)
	}

	hostVeth, err := netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to lookup veth just created: %s", err)
	}

	if err = netlink.LinkSetMTU(hostVeth, mtu); err != nil {
		return nil, nil, "", fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	if err = netlink.LinkSetUp(veth); err != nil {
		return nil, nil, "", fmt.Errorf("unable to bring up veth pair: %s", err)
	}

	ep.Mac = peer.Attrs().HardwareAddr.String()
	ep.HostMac = hostVeth.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(hostVeth.Attrs().Index)
	ep.InterfaceName = lxcIfName

	return veth, &peer, tmpIfName, nil
}
