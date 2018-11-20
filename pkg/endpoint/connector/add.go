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

package connector

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-connector")

const (
	// hostInterfacePrefix is the Host interface prefix.
	hostInterfacePrefix = "lxc"
	// temporaryInterfacePrefix is the temporary interface prefix while setting up libNetwork interface.
	temporaryInterfacePrefix = "tmp"
)

// Endpoint2IfName returns the host interface name for the given endpointID.
func Endpoint2IfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(temporaryInterfacePrefix) - 1)
	return hostInterfacePrefix + truncateString(sum, truncateLength)
}

// Endpoint2TempIfName returns the temporary interface name for the given
// endpointID.
func Endpoint2TempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
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

// WriteSysConfig tries to emulate a sysctl call by writing directly to the
// given fileName the given value.
func WriteSysConfig(fileName, value string) error {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("unable to open configuration file: %s", err)
	}
	_, err = f.WriteString(value)
	if err != nil {
		f.Close()
		return fmt.Errorf("unable to write value: %s", err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("unable to close configuration file: %s", err)
	}
	return nil
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

// GetNetInfoFromPID returns the index of the interface parent, the MAC address
// and IP address of the first interface that contains an IP address with global
// scope.
func GetNetInfoFromPID(pid int) (int, string, net.IP, error) {
	netNs, err := ns.GetNS(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return 0, "", nil, err
	}
	defer netNs.Close()

	var (
		lxcMAC      string
		parentIndex int
		ip          net.IP
	)

	err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, l := range links {
			addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				return err
			}
			for _, addr := range addrs {
				if addr.IP.IsGlobalUnicast() {
					ip = addr.IP
					lxcMAC = l.Attrs().HardwareAddr.String()
					parentIndex = l.Attrs().ParentIndex
					log.Debugf("link found: %+v", l.Attrs())
					return nil
				}
			}
		}
		return nil
	})
	return parentIndex, lxcMAC, ip, err
}

// GetVethInfo populates the given endpoint with the arguments provided where
// * nodeIfName - Node Interface Name
// * parentIdx - Interface Index of the container veth pair in the host side.
// * netNSMac - MAC address of the veth pair in the container side.
func GetVethInfo(nodeIfName string, parentIdx int, netNSMac string, ep *models.EndpointChangeRequest) error {
	nodeVet, err := netlink.LinkByName(nodeIfName)
	if err != nil {
		return fmt.Errorf("unable to lookup veth just created: %s", err)
	}
	l, err := netlink.LinkByIndex(parentIdx)
	if err != nil {
		return err
	}
	ep.Mac = netNSMac
	ep.HostMac = nodeVet.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(parentIdx)
	ep.InterfaceName = l.Attrs().Name
	return nil
}
