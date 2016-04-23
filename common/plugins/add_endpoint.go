package plugins

import (
	"fmt"

	"github.com/noironetworks/cilium-net/common/types"

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
func SetupVeth(id string, mtu int, ep *types.Endpoint) (*netlink.Veth, *netlink.Link, string, error) {

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

	ep.LXCMAC = types.MAC(peer.Attrs().HardwareAddr)
	ep.NodeMAC = types.MAC(hostVeth.Attrs().HardwareAddr)
	ep.IfIndex = hostVeth.Attrs().Index
	ep.IfName = lxcIfName

	return veth, &peer, tmpIfName, nil
}
