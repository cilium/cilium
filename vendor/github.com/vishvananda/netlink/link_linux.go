package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	SizeofLinkStats32 = 0x5c
	SizeofLinkStats64 = 0xb8
)

const (
	TUNTAP_MODE_TUN             TuntapMode = unix.IFF_TUN
	TUNTAP_MODE_TAP             TuntapMode = unix.IFF_TAP
	TUNTAP_DEFAULTS             TuntapFlag = unix.IFF_TUN_EXCL | unix.IFF_ONE_QUEUE
	TUNTAP_VNET_HDR             TuntapFlag = unix.IFF_VNET_HDR
	TUNTAP_TUN_EXCL             TuntapFlag = unix.IFF_TUN_EXCL
	TUNTAP_NO_PI                TuntapFlag = unix.IFF_NO_PI
	TUNTAP_ONE_QUEUE            TuntapFlag = unix.IFF_ONE_QUEUE
	TUNTAP_MULTI_QUEUE          TuntapFlag = unix.IFF_MULTI_QUEUE
	TUNTAP_MULTI_QUEUE_DEFAULTS TuntapFlag = TUNTAP_MULTI_QUEUE | TUNTAP_NO_PI
)

var lookupByDump = false

var macvlanModes = [...]uint32{
	0,
	nl.MACVLAN_MODE_PRIVATE,
	nl.MACVLAN_MODE_VEPA,
	nl.MACVLAN_MODE_BRIDGE,
	nl.MACVLAN_MODE_PASSTHRU,
	nl.MACVLAN_MODE_SOURCE,
}

func ensureIndex(link *LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}

func (h *Handle) ensureIndex(link *LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := h.LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}

func (h *Handle) LinkSetARPOff(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change |= unix.IFF_NOARP
	msg.Flags |= unix.IFF_NOARP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func LinkSetARPOff(link Link) error {
	return pkgHandle.LinkSetARPOff(link)
}

func (h *Handle) LinkSetARPOn(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change |= unix.IFF_NOARP
	msg.Flags &= ^uint32(unix.IFF_NOARP)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func LinkSetARPOn(link Link) error {
	return pkgHandle.LinkSetARPOn(link)
}

func (h *Handle) SetPromiscOn(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_PROMISC
	msg.Flags = unix.IFF_PROMISC
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetAllmulticastOn enables the reception of all hardware multicast packets for the link device.
// Equivalent to: `ip link set $link allmulticast on`
func LinkSetAllmulticastOn(link Link) error {
	return pkgHandle.LinkSetAllmulticastOn(link)
}

// LinkSetAllmulticastOn enables the reception of all hardware multicast packets for the link device.
// Equivalent to: `ip link set $link allmulticast on`
func (h *Handle) LinkSetAllmulticastOn(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_ALLMULTI
	msg.Flags = unix.IFF_ALLMULTI

	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetAllmulticastOff disables the reception of all hardware multicast packets for the link device.
// Equivalent to: `ip link set $link allmulticast off`
func LinkSetAllmulticastOff(link Link) error {
	return pkgHandle.LinkSetAllmulticastOff(link)
}

// LinkSetAllmulticastOff disables the reception of all hardware multicast packets for the link device.
// Equivalent to: `ip link set $link allmulticast off`
func (h *Handle) LinkSetAllmulticastOff(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_ALLMULTI
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func MacvlanMACAddrAdd(link Link, addr net.HardwareAddr) error {
	return pkgHandle.MacvlanMACAddrAdd(link, addr)
}

func (h *Handle) MacvlanMACAddrAdd(link Link, addr net.HardwareAddr) error {
	return h.macvlanMACAddrChange(link, []net.HardwareAddr{addr}, nl.MACVLAN_MACADDR_ADD)
}

func MacvlanMACAddrDel(link Link, addr net.HardwareAddr) error {
	return pkgHandle.MacvlanMACAddrDel(link, addr)
}

func (h *Handle) MacvlanMACAddrDel(link Link, addr net.HardwareAddr) error {
	return h.macvlanMACAddrChange(link, []net.HardwareAddr{addr}, nl.MACVLAN_MACADDR_DEL)
}

func MacvlanMACAddrFlush(link Link) error {
	return pkgHandle.MacvlanMACAddrFlush(link)
}

func (h *Handle) MacvlanMACAddrFlush(link Link) error {
	return h.macvlanMACAddrChange(link, nil, nl.MACVLAN_MACADDR_FLUSH)
}

func MacvlanMACAddrSet(link Link, addrs []net.HardwareAddr) error {
	return pkgHandle.MacvlanMACAddrSet(link, addrs)
}

func (h *Handle) MacvlanMACAddrSet(link Link, addrs []net.HardwareAddr) error {
	return h.macvlanMACAddrChange(link, addrs, nl.MACVLAN_MACADDR_SET)
}

func (h *Handle) macvlanMACAddrChange(link Link, addrs []net.HardwareAddr, mode uint32) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))
	inner := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	// IFLA_MACVLAN_MACADDR_MODE = mode
	b := make([]byte, 4)
	native.PutUint32(b, mode)
	inner.AddRtAttr(nl.IFLA_MACVLAN_MACADDR_MODE, b)

	// populate message with MAC addrs, if necessary
	switch mode {
	case nl.MACVLAN_MACADDR_ADD, nl.MACVLAN_MACADDR_DEL:
		if len(addrs) == 1 {
			inner.AddRtAttr(nl.IFLA_MACVLAN_MACADDR, []byte(addrs[0]))
		}
	case nl.MACVLAN_MACADDR_SET:
		mad := inner.AddRtAttr(nl.IFLA_MACVLAN_MACADDR_DATA, nil)
		for _, addr := range addrs {
			mad.AddRtAttr(nl.IFLA_MACVLAN_MACADDR, []byte(addr))
		}
	}

	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func BridgeSetMcastSnoop(link Link, on bool) error {
	return pkgHandle.BridgeSetMcastSnoop(link, on)
}

func (h *Handle) BridgeSetMcastSnoop(link Link, on bool) error {
	bridge := link.(*Bridge)
	bridge.MulticastSnooping = &on
	return h.linkModify(bridge, unix.NLM_F_ACK)
}

func SetPromiscOn(link Link) error {
	return pkgHandle.SetPromiscOn(link)
}

func (h *Handle) SetPromiscOff(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_PROMISC
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func SetPromiscOff(link Link) error {
	return pkgHandle.SetPromiscOff(link)
}

// LinkSetUp enables the link device.
// Equivalent to: `ip link set $link up`
func LinkSetUp(link Link) error {
	return pkgHandle.LinkSetUp(link)
}

// LinkSetUp enables the link device.
// Equivalent to: `ip link set $link up`
func (h *Handle) LinkSetUp(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_UP
	msg.Flags = unix.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetDown disables link device.
// Equivalent to: `ip link set $link down`
func LinkSetDown(link Link) error {
	return pkgHandle.LinkSetDown(link)
}

// LinkSetDown disables link device.
// Equivalent to: `ip link set $link down`
func (h *Handle) LinkSetDown(link Link) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Change = unix.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMTU sets the mtu of the link device.
// Equivalent to: `ip link set $link mtu $mtu`
func LinkSetMTU(link Link, mtu int) error {
	return pkgHandle.LinkSetMTU(link, mtu)
}

// LinkSetMTU sets the mtu of the link device.
// Equivalent to: `ip link set $link mtu $mtu`
func (h *Handle) LinkSetMTU(link Link, mtu int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(mtu))

	data := nl.NewRtAttr(unix.IFLA_MTU, b)
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetName sets the name of the link device.
// Equivalent to: `ip link set $link name $name`
func LinkSetName(link Link, name string) error {
	return pkgHandle.LinkSetName(link, name)
}

// LinkSetName sets the name of the link device.
// Equivalent to: `ip link set $link name $name`
func (h *Handle) LinkSetName(link Link, name string) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_IFNAME, []byte(name))
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetAlias sets the alias of the link device.
// Equivalent to: `ip link set dev $link alias $name`
func LinkSetAlias(link Link, name string) error {
	return pkgHandle.LinkSetAlias(link, name)
}

// LinkSetAlias sets the alias of the link device.
// Equivalent to: `ip link set dev $link alias $name`
func (h *Handle) LinkSetAlias(link Link, name string) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_IFALIAS, []byte(name))
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetHardwareAddr sets the hardware address of the link device.
// Equivalent to: `ip link set $link address $hwaddr`
func LinkSetHardwareAddr(link Link, hwaddr net.HardwareAddr) error {
	return pkgHandle.LinkSetHardwareAddr(link, hwaddr)
}

// LinkSetHardwareAddr sets the hardware address of the link device.
// Equivalent to: `ip link set $link address $hwaddr`
func (h *Handle) LinkSetHardwareAddr(link Link, hwaddr net.HardwareAddr) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_ADDRESS, []byte(hwaddr))
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfHardwareAddr sets the hardware address of a vf for the link.
// Equivalent to: `ip link set $link vf $vf mac $hwaddr`
func LinkSetVfHardwareAddr(link Link, vf int, hwaddr net.HardwareAddr) error {
	return pkgHandle.LinkSetVfHardwareAddr(link, vf, hwaddr)
}

// LinkSetVfHardwareAddr sets the hardware address of a vf for the link.
// Equivalent to: `ip link set $link vf $vf mac $hwaddr`
func (h *Handle) LinkSetVfHardwareAddr(link Link, vf int, hwaddr net.HardwareAddr) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	vfmsg := nl.VfMac{
		Vf: uint32(vf),
	}
	copy(vfmsg.Mac[:], []byte(hwaddr))
	info.AddRtAttr(nl.IFLA_VF_MAC, vfmsg.Serialize())
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfVlan sets the vlan of a vf for the link.
// Equivalent to: `ip link set $link vf $vf vlan $vlan`
func LinkSetVfVlan(link Link, vf, vlan int) error {
	return pkgHandle.LinkSetVfVlan(link, vf, vlan)
}

// LinkSetVfVlan sets the vlan of a vf for the link.
// Equivalent to: `ip link set $link vf $vf vlan $vlan`
func (h *Handle) LinkSetVfVlan(link Link, vf, vlan int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	vfmsg := nl.VfVlan{
		Vf:   uint32(vf),
		Vlan: uint32(vlan),
	}
	info.AddRtAttr(nl.IFLA_VF_VLAN, vfmsg.Serialize())
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfTxRate sets the tx rate of a vf for the link.
// Equivalent to: `ip link set $link vf $vf rate $rate`
func LinkSetVfTxRate(link Link, vf, rate int) error {
	return pkgHandle.LinkSetVfTxRate(link, vf, rate)
}

// LinkSetVfTxRate sets the tx rate of a vf for the link.
// Equivalent to: `ip link set $link vf $vf rate $rate`
func (h *Handle) LinkSetVfTxRate(link Link, vf, rate int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	vfmsg := nl.VfTxRate{
		Vf:   uint32(vf),
		Rate: uint32(rate),
	}
	info.AddRtAttr(nl.IFLA_VF_TX_RATE, vfmsg.Serialize())
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfSpoofchk enables/disables spoof check on a vf for the link.
// Equivalent to: `ip link set $link vf $vf spoofchk $check`
func LinkSetVfSpoofchk(link Link, vf int, check bool) error {
	return pkgHandle.LinkSetVfSpoofchk(link, vf, check)
}

// LinkSetVfSpookfchk enables/disables spoof check on a vf for the link.
// Equivalent to: `ip link set $link vf $vf spoofchk $check`
func (h *Handle) LinkSetVfSpoofchk(link Link, vf int, check bool) error {
	var setting uint32
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	if check {
		setting = 1
	}
	vfmsg := nl.VfSpoofchk{
		Vf:      uint32(vf),
		Setting: setting,
	}
	info.AddRtAttr(nl.IFLA_VF_SPOOFCHK, vfmsg.Serialize())
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfTrust enables/disables trust state on a vf for the link.
// Equivalent to: `ip link set $link vf $vf trust $state`
func LinkSetVfTrust(link Link, vf int, state bool) error {
	return pkgHandle.LinkSetVfTrust(link, vf, state)
}

// LinkSetVfTrust enables/disables trust state on a vf for the link.
// Equivalent to: `ip link set $link vf $vf trust $state`
func (h *Handle) LinkSetVfTrust(link Link, vf int, state bool) error {
	var setting uint32
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	if state {
		setting = 1
	}
	vfmsg := nl.VfTrust{
		Vf:      uint32(vf),
		Setting: setting,
	}
	info.AddRtAttr(nl.IFLA_VF_TRUST, vfmsg.Serialize())
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetVfNodeGUID sets the node GUID of a vf for the link.
// Equivalent to: `ip link set dev $link vf $vf node_guid $nodeguid`
func LinkSetVfNodeGUID(link Link, vf int, nodeguid net.HardwareAddr) error {
	return pkgHandle.LinkSetVfGUID(link, vf, nodeguid, nl.IFLA_VF_IB_NODE_GUID)
}

// LinkSetVfPortGUID sets the port GUID of a vf for the link.
// Equivalent to: `ip link set dev $link vf $vf port_guid $portguid`
func LinkSetVfPortGUID(link Link, vf int, portguid net.HardwareAddr) error {
	return pkgHandle.LinkSetVfGUID(link, vf, portguid, nl.IFLA_VF_IB_PORT_GUID)
}

// LinkSetVfGUID sets the node or port GUID of a vf for the link.
func (h *Handle) LinkSetVfGUID(link Link, vf int, vfGuid net.HardwareAddr, guidType int) error {
	var err error
	var guid uint64

	buf := bytes.NewBuffer(vfGuid)
	err = binary.Read(buf, binary.LittleEndian, &guid)
	if err != nil {
		return err
	}

	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	data := nl.NewRtAttr(unix.IFLA_VFINFO_LIST, nil)
	info := data.AddRtAttr(nl.IFLA_VF_INFO, nil)
	vfmsg := nl.VfGUID{
		Vf:   uint32(vf),
		GUID: guid,
	}
	info.AddRtAttr(guidType, vfmsg.Serialize())
	req.AddData(data)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMaster sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func LinkSetMaster(link Link, master *Bridge) error {
	return pkgHandle.LinkSetMaster(link, master)
}

// LinkSetMaster sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func (h *Handle) LinkSetMaster(link Link, master *Bridge) error {
	index := 0
	if master != nil {
		masterBase := master.Attrs()
		h.ensureIndex(masterBase)
		index = masterBase.Index
	}
	if index <= 0 {
		return fmt.Errorf("Device does not exist")
	}
	return h.LinkSetMasterByIndex(link, index)
}

// LinkSetNoMaster removes the master of the link device.
// Equivalent to: `ip link set $link nomaster`
func LinkSetNoMaster(link Link) error {
	return pkgHandle.LinkSetNoMaster(link)
}

// LinkSetNoMaster removes the master of the link device.
// Equivalent to: `ip link set $link nomaster`
func (h *Handle) LinkSetNoMaster(link Link) error {
	return h.LinkSetMasterByIndex(link, 0)
}

// LinkSetMasterByIndex sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func LinkSetMasterByIndex(link Link, masterIndex int) error {
	return pkgHandle.LinkSetMasterByIndex(link, masterIndex)
}

// LinkSetMasterByIndex sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func (h *Handle) LinkSetMasterByIndex(link Link, masterIndex int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(masterIndex))

	data := nl.NewRtAttr(unix.IFLA_MASTER, b)
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsPid puts the device into a new network namespace. The
// pid must be a pid of a running process.
// Equivalent to: `ip link set $link netns $pid`
func LinkSetNsPid(link Link, nspid int) error {
	return pkgHandle.LinkSetNsPid(link, nspid)
}

// LinkSetNsPid puts the device into a new network namespace. The
// pid must be a pid of a running process.
// Equivalent to: `ip link set $link netns $pid`
func (h *Handle) LinkSetNsPid(link Link, nspid int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(nspid))

	data := nl.NewRtAttr(unix.IFLA_NET_NS_PID, b)
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsFd puts the device into a new network namespace. The
// fd must be an open file descriptor to a network namespace.
// Similar to: `ip link set $link netns $ns`
func LinkSetNsFd(link Link, fd int) error {
	return pkgHandle.LinkSetNsFd(link, fd)
}

// LinkSetNsFd puts the device into a new network namespace. The
// fd must be an open file descriptor to a network namespace.
// Similar to: `ip link set $link netns $ns`
func (h *Handle) LinkSetNsFd(link Link, fd int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(fd))

	data := nl.NewRtAttr(unix.IFLA_NET_NS_FD, b)
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// LinkSetXdpFd adds a bpf function to the driver. The fd must be a bpf
// program loaded with bpf(type=BPF_PROG_TYPE_XDP)
func LinkSetXdpFd(link Link, fd int) error {
	return LinkSetXdpFdWithFlags(link, fd, 0)
}

// LinkSetXdpFdWithFlags adds a bpf function to the driver with the given
// options. The fd must be a bpf program loaded with bpf(type=BPF_PROG_TYPE_XDP)
func LinkSetXdpFdWithFlags(link Link, fd, flags int) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	addXdpAttrs(&LinkXdp{Fd: fd, Flags: uint32(flags)}, req)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func boolAttr(val bool) []byte {
	var v uint8
	if val {
		v = 1
	}
	return nl.Uint8Attr(v)
}

type vxlanPortRange struct {
	Lo, Hi uint16
}

func addVxlanAttrs(vxlan *Vxlan, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	if vxlan.FlowBased {
		vxlan.VxlanId = 0
	}

	data.AddRtAttr(nl.IFLA_VXLAN_ID, nl.Uint32Attr(uint32(vxlan.VxlanId)))

	if vxlan.VtepDevIndex != 0 {
		data.AddRtAttr(nl.IFLA_VXLAN_LINK, nl.Uint32Attr(uint32(vxlan.VtepDevIndex)))
	}
	if vxlan.SrcAddr != nil {
		ip := vxlan.SrcAddr.To4()
		if ip != nil {
			data.AddRtAttr(nl.IFLA_VXLAN_LOCAL, []byte(ip))
		} else {
			ip = vxlan.SrcAddr.To16()
			if ip != nil {
				data.AddRtAttr(nl.IFLA_VXLAN_LOCAL6, []byte(ip))
			}
		}
	}
	if vxlan.Group != nil {
		group := vxlan.Group.To4()
		if group != nil {
			data.AddRtAttr(nl.IFLA_VXLAN_GROUP, []byte(group))
		} else {
			group = vxlan.Group.To16()
			if group != nil {
				data.AddRtAttr(nl.IFLA_VXLAN_GROUP6, []byte(group))
			}
		}
	}

	data.AddRtAttr(nl.IFLA_VXLAN_TTL, nl.Uint8Attr(uint8(vxlan.TTL)))
	data.AddRtAttr(nl.IFLA_VXLAN_TOS, nl.Uint8Attr(uint8(vxlan.TOS)))
	data.AddRtAttr(nl.IFLA_VXLAN_LEARNING, boolAttr(vxlan.Learning))
	data.AddRtAttr(nl.IFLA_VXLAN_PROXY, boolAttr(vxlan.Proxy))
	data.AddRtAttr(nl.IFLA_VXLAN_RSC, boolAttr(vxlan.RSC))
	data.AddRtAttr(nl.IFLA_VXLAN_L2MISS, boolAttr(vxlan.L2miss))
	data.AddRtAttr(nl.IFLA_VXLAN_L3MISS, boolAttr(vxlan.L3miss))
	data.AddRtAttr(nl.IFLA_VXLAN_UDP_ZERO_CSUM6_TX, boolAttr(vxlan.UDP6ZeroCSumTx))
	data.AddRtAttr(nl.IFLA_VXLAN_UDP_ZERO_CSUM6_RX, boolAttr(vxlan.UDP6ZeroCSumRx))

	if vxlan.UDPCSum {
		data.AddRtAttr(nl.IFLA_VXLAN_UDP_CSUM, boolAttr(vxlan.UDPCSum))
	}
	if vxlan.GBP {
		data.AddRtAttr(nl.IFLA_VXLAN_GBP, []byte{})
	}
	if vxlan.FlowBased {
		data.AddRtAttr(nl.IFLA_VXLAN_FLOWBASED, boolAttr(vxlan.FlowBased))
	}
	if vxlan.NoAge {
		data.AddRtAttr(nl.IFLA_VXLAN_AGEING, nl.Uint32Attr(0))
	} else if vxlan.Age > 0 {
		data.AddRtAttr(nl.IFLA_VXLAN_AGEING, nl.Uint32Attr(uint32(vxlan.Age)))
	}
	if vxlan.Limit > 0 {
		data.AddRtAttr(nl.IFLA_VXLAN_LIMIT, nl.Uint32Attr(uint32(vxlan.Limit)))
	}
	if vxlan.Port > 0 {
		data.AddRtAttr(nl.IFLA_VXLAN_PORT, htons(uint16(vxlan.Port)))
	}
	if vxlan.PortLow > 0 || vxlan.PortHigh > 0 {
		pr := vxlanPortRange{uint16(vxlan.PortLow), uint16(vxlan.PortHigh)}

		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, &pr)

		data.AddRtAttr(nl.IFLA_VXLAN_PORT_RANGE, buf.Bytes())
	}
}

func addBondAttrs(bond *Bond, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	if bond.Mode >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_MODE, nl.Uint8Attr(uint8(bond.Mode)))
	}
	if bond.ActiveSlave >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_ACTIVE_SLAVE, nl.Uint32Attr(uint32(bond.ActiveSlave)))
	}
	if bond.Miimon >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_MIIMON, nl.Uint32Attr(uint32(bond.Miimon)))
	}
	if bond.UpDelay >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_UPDELAY, nl.Uint32Attr(uint32(bond.UpDelay)))
	}
	if bond.DownDelay >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_DOWNDELAY, nl.Uint32Attr(uint32(bond.DownDelay)))
	}
	if bond.UseCarrier >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_USE_CARRIER, nl.Uint8Attr(uint8(bond.UseCarrier)))
	}
	if bond.ArpInterval >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_ARP_INTERVAL, nl.Uint32Attr(uint32(bond.ArpInterval)))
	}
	if bond.ArpIpTargets != nil {
		msg := data.AddRtAttr(nl.IFLA_BOND_ARP_IP_TARGET, nil)
		for i := range bond.ArpIpTargets {
			ip := bond.ArpIpTargets[i].To4()
			if ip != nil {
				msg.AddRtAttr(i, []byte(ip))
				continue
			}
			ip = bond.ArpIpTargets[i].To16()
			if ip != nil {
				msg.AddRtAttr(i, []byte(ip))
			}
		}
	}
	if bond.ArpValidate >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_ARP_VALIDATE, nl.Uint32Attr(uint32(bond.ArpValidate)))
	}
	if bond.ArpAllTargets >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_ARP_ALL_TARGETS, nl.Uint32Attr(uint32(bond.ArpAllTargets)))
	}
	if bond.Primary >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_PRIMARY, nl.Uint32Attr(uint32(bond.Primary)))
	}
	if bond.PrimaryReselect >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_PRIMARY_RESELECT, nl.Uint8Attr(uint8(bond.PrimaryReselect)))
	}
	if bond.FailOverMac >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_FAIL_OVER_MAC, nl.Uint8Attr(uint8(bond.FailOverMac)))
	}
	if bond.XmitHashPolicy >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_XMIT_HASH_POLICY, nl.Uint8Attr(uint8(bond.XmitHashPolicy)))
	}
	if bond.ResendIgmp >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_RESEND_IGMP, nl.Uint32Attr(uint32(bond.ResendIgmp)))
	}
	if bond.NumPeerNotif >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_NUM_PEER_NOTIF, nl.Uint8Attr(uint8(bond.NumPeerNotif)))
	}
	if bond.AllSlavesActive >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_ALL_SLAVES_ACTIVE, nl.Uint8Attr(uint8(bond.AllSlavesActive)))
	}
	if bond.MinLinks >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_MIN_LINKS, nl.Uint32Attr(uint32(bond.MinLinks)))
	}
	if bond.LpInterval >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_LP_INTERVAL, nl.Uint32Attr(uint32(bond.LpInterval)))
	}
	if bond.PackersPerSlave >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_PACKETS_PER_SLAVE, nl.Uint32Attr(uint32(bond.PackersPerSlave)))
	}
	if bond.LacpRate >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_AD_LACP_RATE, nl.Uint8Attr(uint8(bond.LacpRate)))
	}
	if bond.AdSelect >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_AD_SELECT, nl.Uint8Attr(uint8(bond.AdSelect)))
	}
	if bond.AdActorSysPrio >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_AD_ACTOR_SYS_PRIO, nl.Uint16Attr(uint16(bond.AdActorSysPrio)))
	}
	if bond.AdUserPortKey >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_AD_USER_PORT_KEY, nl.Uint16Attr(uint16(bond.AdUserPortKey)))
	}
	if bond.AdActorSystem != nil {
		data.AddRtAttr(nl.IFLA_BOND_AD_ACTOR_SYSTEM, []byte(bond.AdActorSystem))
	}
	if bond.TlbDynamicLb >= 0 {
		data.AddRtAttr(nl.IFLA_BOND_TLB_DYNAMIC_LB, nl.Uint8Attr(uint8(bond.TlbDynamicLb)))
	}
}

func cleanupFds(fds []*os.File) {
	for _, f := range fds {
		f.Close()
	}
}

// LinkAdd adds a new link device. The type and features of the device
// are taken from the parameters in the link object.
// Equivalent to: `ip link add $link`
func LinkAdd(link Link) error {
	return pkgHandle.LinkAdd(link)
}

// LinkAdd adds a new link device. The type and features of the device
// are taken from the parameters in the link object.
// Equivalent to: `ip link add $link`
func (h *Handle) LinkAdd(link Link) error {
	return h.linkModify(link, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
}

func (h *Handle) linkModify(link Link, flags int) error {
	// TODO: support extra data for macvlan
	base := link.Attrs()

	// if tuntap, then the name can be empty, OS will provide a name
	tuntap, isTuntap := link.(*Tuntap)

	if base.Name == "" && !isTuntap {
		return fmt.Errorf("LinkAttrs.Name cannot be empty")
	}

	if isTuntap {
		// TODO: support user
		// TODO: support group
		if tuntap.Mode < unix.IFF_TUN || tuntap.Mode > unix.IFF_TAP {
			return fmt.Errorf("Tuntap.Mode %v unknown", tuntap.Mode)
		}

		queues := tuntap.Queues

		var fds []*os.File
		var req ifReq
		copy(req.Name[:15], base.Name)

		req.Flags = uint16(tuntap.Flags)

		if queues == 0 { //Legacy compatibility
			queues = 1
			if tuntap.Flags == 0 {
				req.Flags = uint16(TUNTAP_DEFAULTS)
			}
		} else {
			// For best peformance set Flags to TUNTAP_MULTI_QUEUE_DEFAULTS | TUNTAP_VNET_HDR
			// when a) KVM has support for this ABI and
			//      b) the value of the flag is queryable using the TUNGETIFF ioctl
			if tuntap.Flags == 0 {
				req.Flags = uint16(TUNTAP_MULTI_QUEUE_DEFAULTS)
			}
		}

		req.Flags |= uint16(tuntap.Mode)

		for i := 0; i < queues; i++ {
			localReq := req
			file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
			if err != nil {
				cleanupFds(fds)
				return err
			}

			fds = append(fds, file)
			_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&localReq)))
			if errno != 0 {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETIFF failed [%d], errno %v", i, errno)
			}
			// 1) we only care for the name of the first tap in the multi queue set
			// 2) if the original name was empty, the localReq has now the actual name
			//
			// In addition:
			// This ensures that the link name is always identical to what the kernel returns.
			// Not only in case of an empty name, but also when using name templates.
			// e.g. when the provided name is "tap%d", the kernel replaces %d with the next available number.
			if i == 0 {
				link.Attrs().Name = strings.Trim(string(localReq.Name[:]), "\x00")
			}
		}

		// only persist interface if NonPersist is NOT set
		if !tuntap.NonPersist {
			_, _, errno := unix.Syscall(unix.SYS_IOCTL, fds[0].Fd(), uintptr(unix.TUNSETPERSIST), 1)
			if errno != 0 {
				cleanupFds(fds)
				return fmt.Errorf("Tuntap IOCTL TUNSETPERSIST failed, errno %v", errno)
			}
		}

		h.ensureIndex(base)

		// can't set master during create, so set it afterwards
		if base.MasterIndex != 0 {
			// TODO: verify MasterIndex is actually a bridge?
			err := h.LinkSetMasterByIndex(link, base.MasterIndex)
			if err != nil {
				// un-persist (e.g. allow the interface to be removed) the tuntap
				// should not hurt if not set prior, condition might be not needed
				if !tuntap.NonPersist {
					_, _, _ = unix.Syscall(unix.SYS_IOCTL, fds[0].Fd(), uintptr(unix.TUNSETPERSIST), 0)
				}
				cleanupFds(fds)
				return err
			}
		}

		if tuntap.Queues == 0 {
			cleanupFds(fds)
		} else {
			tuntap.Fds = fds
		}

		return nil
	}

	req := h.newNetlinkRequest(unix.RTM_NEWLINK, flags)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	// TODO: make it shorter
	if base.Flags&net.FlagUp != 0 {
		msg.Change = unix.IFF_UP
		msg.Flags = unix.IFF_UP
	}
	if base.Flags&net.FlagBroadcast != 0 {
		msg.Change |= unix.IFF_BROADCAST
		msg.Flags |= unix.IFF_BROADCAST
	}
	if base.Flags&net.FlagLoopback != 0 {
		msg.Change |= unix.IFF_LOOPBACK
		msg.Flags |= unix.IFF_LOOPBACK
	}
	if base.Flags&net.FlagPointToPoint != 0 {
		msg.Change |= unix.IFF_POINTOPOINT
		msg.Flags |= unix.IFF_POINTOPOINT
	}
	if base.Flags&net.FlagMulticast != 0 {
		msg.Change |= unix.IFF_MULTICAST
		msg.Flags |= unix.IFF_MULTICAST
	}
	if base.Index != 0 {
		msg.Index = int32(base.Index)
	}

	req.AddData(msg)

	if base.ParentIndex != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(base.ParentIndex))
		data := nl.NewRtAttr(unix.IFLA_LINK, b)
		req.AddData(data)
	} else if link.Type() == "ipvlan" {
		return fmt.Errorf("Can't create ipvlan link without ParentIndex")
	}

	nameData := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(base.Name))
	req.AddData(nameData)

	if base.MTU > 0 {
		mtu := nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(base.MTU)))
		req.AddData(mtu)
	}

	if base.TxQLen >= 0 {
		qlen := nl.NewRtAttr(unix.IFLA_TXQLEN, nl.Uint32Attr(uint32(base.TxQLen)))
		req.AddData(qlen)
	}

	if base.HardwareAddr != nil {
		hwaddr := nl.NewRtAttr(unix.IFLA_ADDRESS, []byte(base.HardwareAddr))
		req.AddData(hwaddr)
	}

	if base.NumTxQueues > 0 {
		txqueues := nl.NewRtAttr(unix.IFLA_NUM_TX_QUEUES, nl.Uint32Attr(uint32(base.NumTxQueues)))
		req.AddData(txqueues)
	}

	if base.NumRxQueues > 0 {
		rxqueues := nl.NewRtAttr(unix.IFLA_NUM_RX_QUEUES, nl.Uint32Attr(uint32(base.NumRxQueues)))
		req.AddData(rxqueues)
	}

	if base.Namespace != nil {
		var attr *nl.RtAttr
		switch ns := base.Namespace.(type) {
		case NsPid:
			val := nl.Uint32Attr(uint32(ns))
			attr = nl.NewRtAttr(unix.IFLA_NET_NS_PID, val)
		case NsFd:
			val := nl.Uint32Attr(uint32(ns))
			attr = nl.NewRtAttr(unix.IFLA_NET_NS_FD, val)
		}

		req.AddData(attr)
	}

	if base.Xdp != nil {
		addXdpAttrs(base.Xdp, req)
	}

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))

	switch link := link.(type) {
	case *Vlan:
		b := make([]byte, 2)
		native.PutUint16(b, uint16(link.VlanId))
		data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
		data.AddRtAttr(nl.IFLA_VLAN_ID, b)
	case *Veth:
		data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
		peer := data.AddRtAttr(nl.VETH_INFO_PEER, nil)
		nl.NewIfInfomsgChild(peer, unix.AF_UNSPEC)
		peer.AddRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(link.PeerName))
		if base.TxQLen >= 0 {
			peer.AddRtAttr(unix.IFLA_TXQLEN, nl.Uint32Attr(uint32(base.TxQLen)))
		}
		if base.MTU > 0 {
			peer.AddRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(base.MTU)))
		}

	case *Vxlan:
		addVxlanAttrs(link, linkInfo)
	case *Bond:
		addBondAttrs(link, linkInfo)
	case *IPVlan:
		data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
		data.AddRtAttr(nl.IFLA_IPVLAN_MODE, nl.Uint16Attr(uint16(link.Mode)))
	case *Macvlan:
		if link.Mode != MACVLAN_MODE_DEFAULT {
			data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
			data.AddRtAttr(nl.IFLA_MACVLAN_MODE, nl.Uint32Attr(macvlanModes[link.Mode]))
		}
	case *Macvtap:
		if link.Mode != MACVLAN_MODE_DEFAULT {
			data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
			data.AddRtAttr(nl.IFLA_MACVLAN_MODE, nl.Uint32Attr(macvlanModes[link.Mode]))
		}
	case *Gretap:
		addGretapAttrs(link, linkInfo)
	case *Iptun:
		addIptunAttrs(link, linkInfo)
	case *Sittun:
		addSittunAttrs(link, linkInfo)
	case *Gretun:
		addGretunAttrs(link, linkInfo)
	case *Vti:
		addVtiAttrs(link, linkInfo)
	case *Vrf:
		addVrfAttrs(link, linkInfo)
	case *Bridge:
		addBridgeAttrs(link, linkInfo)
	case *GTP:
		addGTPAttrs(link, linkInfo)
	case *Xfrmi:
		addXfrmiAttrs(link, linkInfo)
	}

	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	h.ensureIndex(base)

	// can't set master during create, so set it afterwards
	if base.MasterIndex != 0 {
		// TODO: verify MasterIndex is actually a bridge?
		return h.LinkSetMasterByIndex(link, base.MasterIndex)
	}
	return nil
}

// LinkDel deletes link device. Either Index or Name must be set in
// the link object for it to be deleted. The other values are ignored.
// Equivalent to: `ip link del $link`
func LinkDel(link Link) error {
	return pkgHandle.LinkDel(link)
}

// LinkDel deletes link device. Either Index or Name must be set in
// the link object for it to be deleted. The other values are ignored.
// Equivalent to: `ip link del $link`
func (h *Handle) LinkDel(link Link) error {
	base := link.Attrs()

	h.ensureIndex(base)

	req := h.newNetlinkRequest(unix.RTM_DELLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func (h *Handle) linkByNameDump(name string) (Link, error) {
	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().Name == name {
			return link, nil
		}
	}
	return nil, LinkNotFoundError{fmt.Errorf("Link %s not found", name)}
}

func (h *Handle) linkByAliasDump(alias string) (Link, error) {
	links, err := h.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().Alias == alias {
			return link, nil
		}
	}
	return nil, LinkNotFoundError{fmt.Errorf("Link alias %s not found", alias)}
}

// LinkByName finds a link by name and returns a pointer to the object.
func LinkByName(name string) (Link, error) {
	return pkgHandle.LinkByName(name)
}

// LinkByName finds a link by name and returns a pointer to the object.
func (h *Handle) LinkByName(name string) (Link, error) {
	if h.lookupByDump {
		return h.linkByNameDump(name)
	}

	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)

	attr := nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF))
	req.AddData(attr)

	nameData := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(name))
	req.AddData(nameData)

	link, err := execGetLink(req)
	if err == unix.EINVAL {
		// older kernels don't support looking up via IFLA_IFNAME
		// so fall back to dumping all links
		h.lookupByDump = true
		return h.linkByNameDump(name)
	}

	return link, err
}

// LinkByAlias finds a link by its alias and returns a pointer to the object.
// If there are multiple links with the alias it returns the first one
func LinkByAlias(alias string) (Link, error) {
	return pkgHandle.LinkByAlias(alias)
}

// LinkByAlias finds a link by its alias and returns a pointer to the object.
// If there are multiple links with the alias it returns the first one
func (h *Handle) LinkByAlias(alias string) (Link, error) {
	if h.lookupByDump {
		return h.linkByAliasDump(alias)
	}

	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)

	attr := nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF))
	req.AddData(attr)

	nameData := nl.NewRtAttr(unix.IFLA_IFALIAS, nl.ZeroTerminated(alias))
	req.AddData(nameData)

	link, err := execGetLink(req)
	if err == unix.EINVAL {
		// older kernels don't support looking up via IFLA_IFALIAS
		// so fall back to dumping all links
		h.lookupByDump = true
		return h.linkByAliasDump(alias)
	}

	return link, err
}

// LinkByIndex finds a link by index and returns a pointer to the object.
func LinkByIndex(index int) (Link, error) {
	return pkgHandle.LinkByIndex(index)
}

// LinkByIndex finds a link by index and returns a pointer to the object.
func (h *Handle) LinkByIndex(index int) (Link, error) {
	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(index)
	req.AddData(msg)
	attr := nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF))
	req.AddData(attr)

	return execGetLink(req)
}

func execGetLink(req *nl.NetlinkRequest) (Link, error) {
	msgs, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == unix.ENODEV {
				return nil, LinkNotFoundError{fmt.Errorf("Link not found")}
			}
		}
		return nil, err
	}

	switch {
	case len(msgs) == 0:
		return nil, LinkNotFoundError{fmt.Errorf("Link not found")}

	case len(msgs) == 1:
		return LinkDeserialize(nil, msgs[0])

	default:
		return nil, fmt.Errorf("More than one link found")
	}
}

// linkDeserialize deserializes a raw message received from netlink into
// a link object.
func LinkDeserialize(hdr *unix.NlMsghdr, m []byte) (Link, error) {
	msg := nl.DeserializeIfInfomsg(m)

	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}

	base := LinkAttrs{Index: int(msg.Index), RawFlags: msg.Flags, Flags: linkFlags(msg.Flags), EncapType: msg.EncapType()}
	if msg.Flags&unix.IFF_PROMISC != 0 {
		base.Promisc = 1
	}
	var (
		link     Link
		stats32  []byte
		stats64  []byte
		linkType string
	)
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.IFLA_LINKINFO:
			infos, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case nl.IFLA_INFO_KIND:
					linkType = string(info.Value[:len(info.Value)-1])
					switch linkType {
					case "dummy":
						link = &Dummy{}
					case "ifb":
						link = &Ifb{}
					case "bridge":
						link = &Bridge{}
					case "vlan":
						link = &Vlan{}
					case "veth":
						link = &Veth{}
					case "vxlan":
						link = &Vxlan{}
					case "bond":
						link = &Bond{}
					case "ipvlan":
						link = &IPVlan{}
					case "macvlan":
						link = &Macvlan{}
					case "macvtap":
						link = &Macvtap{}
					case "gretap":
						link = &Gretap{}
					case "ip6gretap":
						link = &Gretap{}
					case "ipip":
						link = &Iptun{}
					case "sit":
						link = &Sittun{}
					case "gre":
						link = &Gretun{}
					case "ip6gre":
						link = &Gretun{}
					case "vti", "vti6":
						link = &Vti{}
					case "vrf":
						link = &Vrf{}
					case "gtp":
						link = &GTP{}
					case "xfrm":
						link = &Xfrmi{}
					default:
						link = &GenericLink{LinkType: linkType}
					}
				case nl.IFLA_INFO_DATA:
					data, err := nl.ParseRouteAttr(info.Value)
					if err != nil {
						return nil, err
					}
					switch linkType {
					case "vlan":
						parseVlanData(link, data)
					case "vxlan":
						parseVxlanData(link, data)
					case "bond":
						parseBondData(link, data)
					case "ipvlan":
						parseIPVlanData(link, data)
					case "macvlan":
						parseMacvlanData(link, data)
					case "macvtap":
						parseMacvtapData(link, data)
					case "gretap":
						parseGretapData(link, data)
					case "ip6gretap":
						parseGretapData(link, data)
					case "ipip":
						parseIptunData(link, data)
					case "sit":
						parseSittunData(link, data)
					case "gre":
						parseGretunData(link, data)
					case "ip6gre":
						parseGretunData(link, data)
					case "vti", "vti6":
						parseVtiData(link, data)
					case "vrf":
						parseVrfData(link, data)
					case "bridge":
						parseBridgeData(link, data)
					case "gtp":
						parseGTPData(link, data)
					case "xfrm":
						parseXfrmiData(link, data)
					}
				}
			}
		case unix.IFLA_ADDRESS:
			var nonzero bool
			for _, b := range attr.Value {
				if b != 0 {
					nonzero = true
				}
			}
			if nonzero {
				base.HardwareAddr = attr.Value[:]
			}
		case unix.IFLA_IFNAME:
			base.Name = string(attr.Value[:len(attr.Value)-1])
		case unix.IFLA_MTU:
			base.MTU = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_LINK:
			base.ParentIndex = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_MASTER:
			base.MasterIndex = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_TXQLEN:
			base.TxQLen = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_IFALIAS:
			base.Alias = string(attr.Value[:len(attr.Value)-1])
		case unix.IFLA_STATS:
			stats32 = attr.Value[:]
		case unix.IFLA_STATS64:
			stats64 = attr.Value[:]
		case unix.IFLA_XDP:
			xdp, err := parseLinkXdp(attr.Value[:])
			if err != nil {
				return nil, err
			}
			base.Xdp = xdp
		case unix.IFLA_PROTINFO | unix.NLA_F_NESTED:
			if hdr != nil && hdr.Type == unix.RTM_NEWLINK &&
				msg.Family == unix.AF_BRIDGE {
				attrs, err := nl.ParseRouteAttr(attr.Value[:])
				if err != nil {
					return nil, err
				}
				protinfo := parseProtinfo(attrs)
				base.Protinfo = &protinfo
			}
		case unix.IFLA_OPERSTATE:
			base.OperState = LinkOperState(uint8(attr.Value[0]))
		case unix.IFLA_LINK_NETNSID:
			base.NetNsID = int(native.Uint32(attr.Value[0:4]))
		case unix.IFLA_VFINFO_LIST:
			data, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			vfs, err := parseVfInfoList(data)
			if err != nil {
				return nil, err
			}
			base.Vfs = vfs
		}
	}

	if stats64 != nil {
		base.Statistics = parseLinkStats64(stats64)
	} else if stats32 != nil {
		base.Statistics = parseLinkStats32(stats32)
	}

	// Links that don't have IFLA_INFO_KIND are hardware devices
	if link == nil {
		link = &Device{}
	}
	*link.Attrs() = base

	return link, nil
}

// LinkList gets a list of link devices.
// Equivalent to: `ip link show`
func LinkList() ([]Link, error) {
	return pkgHandle.LinkList()
}

// LinkList gets a list of link devices.
// Equivalent to: `ip link show`
func (h *Handle) LinkList() ([]Link, error) {
	// NOTE(vish): This duplicates functionality in net/iface_linux.go, but we need
	//             to get the message ourselves to parse link type.
	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)
	attr := nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF))
	req.AddData(attr)

	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	var res []Link
	for _, m := range msgs {
		link, err := LinkDeserialize(nil, m)
		if err != nil {
			return nil, err
		}
		res = append(res, link)
	}

	return res, nil
}

// LinkUpdate is used to pass information back from LinkSubscribe()
type LinkUpdate struct {
	nl.IfInfomsg
	Header unix.NlMsghdr
	Link
}

// LinkSubscribe takes a chan down which notifications will be sent
// when links change.  Close the 'done' chan to stop subscription.
func LinkSubscribe(ch chan<- LinkUpdate, done <-chan struct{}) error {
	return linkSubscribeAt(netns.None(), netns.None(), ch, done, nil, false)
}

// LinkSubscribeAt works like LinkSubscribe plus it allows the caller
// to choose the network namespace in which to subscribe (ns).
func LinkSubscribeAt(ns netns.NsHandle, ch chan<- LinkUpdate, done <-chan struct{}) error {
	return linkSubscribeAt(ns, netns.None(), ch, done, nil, false)
}

// LinkSubscribeOptions contains a set of options to use with
// LinkSubscribeWithOptions.
type LinkSubscribeOptions struct {
	Namespace     *netns.NsHandle
	ErrorCallback func(error)
	ListExisting  bool
}

// LinkSubscribeWithOptions work like LinkSubscribe but enable to
// provide additional options to modify the behavior. Currently, the
// namespace can be provided as well as an error callback.
func LinkSubscribeWithOptions(ch chan<- LinkUpdate, done <-chan struct{}, options LinkSubscribeOptions) error {
	if options.Namespace == nil {
		none := netns.None()
		options.Namespace = &none
	}
	return linkSubscribeAt(*options.Namespace, netns.None(), ch, done, options.ErrorCallback, options.ListExisting)
}

func linkSubscribeAt(newNs, curNs netns.NsHandle, ch chan<- LinkUpdate, done <-chan struct{}, cberr func(error), listExisting bool) error {
	s, err := nl.SubscribeAt(newNs, curNs, unix.NETLINK_ROUTE, unix.RTNLGRP_LINK)
	if err != nil {
		return err
	}
	if done != nil {
		go func() {
			<-done
			s.Close()
		}()
	}
	if listExisting {
		req := pkgHandle.newNetlinkRequest(unix.RTM_GETLINK,
			unix.NLM_F_DUMP)
		msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
		req.AddData(msg)
		if err := s.Send(req); err != nil {
			return err
		}
	}
	go func() {
		defer close(ch)
		for {
			msgs, err := s.Receive()
			if err != nil {
				if cberr != nil {
					cberr(err)
				}
				return
			}
			for _, m := range msgs {
				if m.Header.Type == unix.NLMSG_DONE {
					continue
				}
				if m.Header.Type == unix.NLMSG_ERROR {
					native := nl.NativeEndian()
					error := int32(native.Uint32(m.Data[0:4]))
					if error == 0 {
						continue
					}
					if cberr != nil {
						cberr(syscall.Errno(-error))
					}
					return
				}
				ifmsg := nl.DeserializeIfInfomsg(m.Data)
				header := unix.NlMsghdr(m.Header)
				link, err := LinkDeserialize(&header, m.Data)
				if err != nil {
					if cberr != nil {
						cberr(err)
					}
					return
				}
				ch <- LinkUpdate{IfInfomsg: *ifmsg, Header: header, Link: link}
			}
		}
	}()

	return nil
}

func LinkSetHairpin(link Link, mode bool) error {
	return pkgHandle.LinkSetHairpin(link, mode)
}

func (h *Handle) LinkSetHairpin(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_MODE)
}

func LinkSetGuard(link Link, mode bool) error {
	return pkgHandle.LinkSetGuard(link, mode)
}

func (h *Handle) LinkSetGuard(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_GUARD)
}

func LinkSetFastLeave(link Link, mode bool) error {
	return pkgHandle.LinkSetFastLeave(link, mode)
}

func (h *Handle) LinkSetFastLeave(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_FAST_LEAVE)
}

func LinkSetLearning(link Link, mode bool) error {
	return pkgHandle.LinkSetLearning(link, mode)
}

func (h *Handle) LinkSetLearning(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_LEARNING)
}

func LinkSetRootBlock(link Link, mode bool) error {
	return pkgHandle.LinkSetRootBlock(link, mode)
}

func (h *Handle) LinkSetRootBlock(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_PROTECT)
}

func LinkSetFlood(link Link, mode bool) error {
	return pkgHandle.LinkSetFlood(link, mode)
}

func (h *Handle) LinkSetFlood(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_UNICAST_FLOOD)
}

func LinkSetBrProxyArp(link Link, mode bool) error {
	return pkgHandle.LinkSetBrProxyArp(link, mode)
}

func (h *Handle) LinkSetBrProxyArp(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_PROXYARP)
}

func LinkSetBrProxyArpWiFi(link Link, mode bool) error {
	return pkgHandle.LinkSetBrProxyArpWiFi(link, mode)
}

func (h *Handle) LinkSetBrProxyArpWiFi(link Link, mode bool) error {
	return h.setProtinfoAttr(link, mode, nl.IFLA_BRPORT_PROXYARP_WIFI)
}

func (h *Handle) setProtinfoAttr(link Link, mode bool, attr int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_BRIDGE)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	br := nl.NewRtAttr(unix.IFLA_PROTINFO|unix.NLA_F_NESTED, nil)
	br.AddRtAttr(attr, boolToByte(mode))
	req.AddData(br)
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}
	return nil
}

// LinkSetTxQLen sets the transaction queue length for the link.
// Equivalent to: `ip link set $link txqlen $qlen`
func LinkSetTxQLen(link Link, qlen int) error {
	return pkgHandle.LinkSetTxQLen(link, qlen)
}

// LinkSetTxQLen sets the transaction queue length for the link.
// Equivalent to: `ip link set $link txqlen $qlen`
func (h *Handle) LinkSetTxQLen(link Link, qlen int) error {
	base := link.Attrs()
	h.ensureIndex(base)
	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	b := make([]byte, 4)
	native.PutUint32(b, uint32(qlen))

	data := nl.NewRtAttr(unix.IFLA_TXQLEN, b)
	req.AddData(data)

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func parseVlanData(link Link, data []syscall.NetlinkRouteAttr) {
	vlan := link.(*Vlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_VLAN_ID:
			vlan.VlanId = int(native.Uint16(datum.Value[0:2]))
		}
	}
}

func parseVxlanData(link Link, data []syscall.NetlinkRouteAttr) {
	vxlan := link.(*Vxlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_VXLAN_ID:
			vxlan.VxlanId = int(native.Uint32(datum.Value[0:4]))
		case nl.IFLA_VXLAN_LINK:
			vxlan.VtepDevIndex = int(native.Uint32(datum.Value[0:4]))
		case nl.IFLA_VXLAN_LOCAL:
			vxlan.SrcAddr = net.IP(datum.Value[0:4])
		case nl.IFLA_VXLAN_LOCAL6:
			vxlan.SrcAddr = net.IP(datum.Value[0:16])
		case nl.IFLA_VXLAN_GROUP:
			vxlan.Group = net.IP(datum.Value[0:4])
		case nl.IFLA_VXLAN_GROUP6:
			vxlan.Group = net.IP(datum.Value[0:16])
		case nl.IFLA_VXLAN_TTL:
			vxlan.TTL = int(datum.Value[0])
		case nl.IFLA_VXLAN_TOS:
			vxlan.TOS = int(datum.Value[0])
		case nl.IFLA_VXLAN_LEARNING:
			vxlan.Learning = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_PROXY:
			vxlan.Proxy = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_RSC:
			vxlan.RSC = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_L2MISS:
			vxlan.L2miss = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_L3MISS:
			vxlan.L3miss = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_UDP_CSUM:
			vxlan.UDPCSum = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_UDP_ZERO_CSUM6_TX:
			vxlan.UDP6ZeroCSumTx = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_UDP_ZERO_CSUM6_RX:
			vxlan.UDP6ZeroCSumRx = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_GBP:
			vxlan.GBP = true
		case nl.IFLA_VXLAN_FLOWBASED:
			vxlan.FlowBased = int8(datum.Value[0]) != 0
		case nl.IFLA_VXLAN_AGEING:
			vxlan.Age = int(native.Uint32(datum.Value[0:4]))
			vxlan.NoAge = vxlan.Age == 0
		case nl.IFLA_VXLAN_LIMIT:
			vxlan.Limit = int(native.Uint32(datum.Value[0:4]))
		case nl.IFLA_VXLAN_PORT:
			vxlan.Port = int(ntohs(datum.Value[0:2]))
		case nl.IFLA_VXLAN_PORT_RANGE:
			buf := bytes.NewBuffer(datum.Value[0:4])
			var pr vxlanPortRange
			if binary.Read(buf, binary.BigEndian, &pr) != nil {
				vxlan.PortLow = int(pr.Lo)
				vxlan.PortHigh = int(pr.Hi)
			}
		}
	}
}

func parseBondData(link Link, data []syscall.NetlinkRouteAttr) {
	bond := link.(*Bond)
	for i := range data {
		switch data[i].Attr.Type {
		case nl.IFLA_BOND_MODE:
			bond.Mode = BondMode(data[i].Value[0])
		case nl.IFLA_BOND_ACTIVE_SLAVE:
			bond.ActiveSlave = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_MIIMON:
			bond.Miimon = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_UPDELAY:
			bond.UpDelay = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_DOWNDELAY:
			bond.DownDelay = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_USE_CARRIER:
			bond.UseCarrier = int(data[i].Value[0])
		case nl.IFLA_BOND_ARP_INTERVAL:
			bond.ArpInterval = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_ARP_IP_TARGET:
			// TODO: implement
		case nl.IFLA_BOND_ARP_VALIDATE:
			bond.ArpValidate = BondArpValidate(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_ARP_ALL_TARGETS:
			bond.ArpAllTargets = BondArpAllTargets(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_PRIMARY:
			bond.Primary = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_PRIMARY_RESELECT:
			bond.PrimaryReselect = BondPrimaryReselect(data[i].Value[0])
		case nl.IFLA_BOND_FAIL_OVER_MAC:
			bond.FailOverMac = BondFailOverMac(data[i].Value[0])
		case nl.IFLA_BOND_XMIT_HASH_POLICY:
			bond.XmitHashPolicy = BondXmitHashPolicy(data[i].Value[0])
		case nl.IFLA_BOND_RESEND_IGMP:
			bond.ResendIgmp = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_NUM_PEER_NOTIF:
			bond.NumPeerNotif = int(data[i].Value[0])
		case nl.IFLA_BOND_ALL_SLAVES_ACTIVE:
			bond.AllSlavesActive = int(data[i].Value[0])
		case nl.IFLA_BOND_MIN_LINKS:
			bond.MinLinks = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_LP_INTERVAL:
			bond.LpInterval = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_PACKETS_PER_SLAVE:
			bond.PackersPerSlave = int(native.Uint32(data[i].Value[0:4]))
		case nl.IFLA_BOND_AD_LACP_RATE:
			bond.LacpRate = BondLacpRate(data[i].Value[0])
		case nl.IFLA_BOND_AD_SELECT:
			bond.AdSelect = BondAdSelect(data[i].Value[0])
		case nl.IFLA_BOND_AD_INFO:
			// TODO: implement
		case nl.IFLA_BOND_AD_ACTOR_SYS_PRIO:
			bond.AdActorSysPrio = int(native.Uint16(data[i].Value[0:2]))
		case nl.IFLA_BOND_AD_USER_PORT_KEY:
			bond.AdUserPortKey = int(native.Uint16(data[i].Value[0:2]))
		case nl.IFLA_BOND_AD_ACTOR_SYSTEM:
			bond.AdActorSystem = net.HardwareAddr(data[i].Value[0:6])
		case nl.IFLA_BOND_TLB_DYNAMIC_LB:
			bond.TlbDynamicLb = int(data[i].Value[0])
		}
	}
}

func parseIPVlanData(link Link, data []syscall.NetlinkRouteAttr) {
	ipv := link.(*IPVlan)
	for _, datum := range data {
		if datum.Attr.Type == nl.IFLA_IPVLAN_MODE {
			ipv.Mode = IPVlanMode(native.Uint32(datum.Value[0:4]))
			return
		}
	}
}

func parseMacvtapData(link Link, data []syscall.NetlinkRouteAttr) {
	macv := link.(*Macvtap)
	parseMacvlanData(&macv.Macvlan, data)
}

func parseMacvlanData(link Link, data []syscall.NetlinkRouteAttr) {
	macv := link.(*Macvlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_MACVLAN_MODE:
			switch native.Uint32(datum.Value[0:4]) {
			case nl.MACVLAN_MODE_PRIVATE:
				macv.Mode = MACVLAN_MODE_PRIVATE
			case nl.MACVLAN_MODE_VEPA:
				macv.Mode = MACVLAN_MODE_VEPA
			case nl.MACVLAN_MODE_BRIDGE:
				macv.Mode = MACVLAN_MODE_BRIDGE
			case nl.MACVLAN_MODE_PASSTHRU:
				macv.Mode = MACVLAN_MODE_PASSTHRU
			case nl.MACVLAN_MODE_SOURCE:
				macv.Mode = MACVLAN_MODE_SOURCE
			}
		case nl.IFLA_MACVLAN_MACADDR_COUNT:
			macv.MACAddrs = make([]net.HardwareAddr, 0, int(native.Uint32(datum.Value[0:4])))
		case nl.IFLA_MACVLAN_MACADDR_DATA:
			macs, err := nl.ParseRouteAttr(datum.Value[:])
			if err != nil {
				panic(fmt.Sprintf("failed to ParseRouteAttr for IFLA_MACVLAN_MACADDR_DATA: %v", err))
			}
			for _, macDatum := range macs {
				macv.MACAddrs = append(macv.MACAddrs, net.HardwareAddr(macDatum.Value[0:6]))
			}
		}
	}
}

// copied from pkg/net_linux.go
func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&unix.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&unix.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&unix.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&unix.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&unix.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}

func addGretapAttrs(gretap *Gretap, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	if gretap.FlowBased {
		// In flow based mode, no other attributes need to be configured
		data.AddRtAttr(nl.IFLA_GRE_COLLECT_METADATA, boolAttr(gretap.FlowBased))
		return
	}

	if ip := gretap.Local; ip != nil {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		data.AddRtAttr(nl.IFLA_GRE_LOCAL, []byte(ip))
	}

	if ip := gretap.Remote; ip != nil {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		data.AddRtAttr(nl.IFLA_GRE_REMOTE, []byte(ip))
	}

	if gretap.IKey != 0 {
		data.AddRtAttr(nl.IFLA_GRE_IKEY, htonl(gretap.IKey))
		gretap.IFlags |= uint16(nl.GRE_KEY)
	}

	if gretap.OKey != 0 {
		data.AddRtAttr(nl.IFLA_GRE_OKEY, htonl(gretap.OKey))
		gretap.OFlags |= uint16(nl.GRE_KEY)
	}

	data.AddRtAttr(nl.IFLA_GRE_IFLAGS, htons(gretap.IFlags))
	data.AddRtAttr(nl.IFLA_GRE_OFLAGS, htons(gretap.OFlags))

	if gretap.Link != 0 {
		data.AddRtAttr(nl.IFLA_GRE_LINK, nl.Uint32Attr(gretap.Link))
	}

	data.AddRtAttr(nl.IFLA_GRE_PMTUDISC, nl.Uint8Attr(gretap.PMtuDisc))
	data.AddRtAttr(nl.IFLA_GRE_TTL, nl.Uint8Attr(gretap.Ttl))
	data.AddRtAttr(nl.IFLA_GRE_TOS, nl.Uint8Attr(gretap.Tos))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_TYPE, nl.Uint16Attr(gretap.EncapType))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_FLAGS, nl.Uint16Attr(gretap.EncapFlags))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_SPORT, htons(gretap.EncapSport))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_DPORT, htons(gretap.EncapDport))
}

func parseGretapData(link Link, data []syscall.NetlinkRouteAttr) {
	gre := link.(*Gretap)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_GRE_OKEY:
			gre.IKey = ntohl(datum.Value[0:4])
		case nl.IFLA_GRE_IKEY:
			gre.OKey = ntohl(datum.Value[0:4])
		case nl.IFLA_GRE_LOCAL:
			gre.Local = net.IP(datum.Value)
		case nl.IFLA_GRE_REMOTE:
			gre.Remote = net.IP(datum.Value)
		case nl.IFLA_GRE_ENCAP_SPORT:
			gre.EncapSport = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_ENCAP_DPORT:
			gre.EncapDport = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_IFLAGS:
			gre.IFlags = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_OFLAGS:
			gre.OFlags = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_TTL:
			gre.Ttl = uint8(datum.Value[0])
		case nl.IFLA_GRE_TOS:
			gre.Tos = uint8(datum.Value[0])
		case nl.IFLA_GRE_PMTUDISC:
			gre.PMtuDisc = uint8(datum.Value[0])
		case nl.IFLA_GRE_ENCAP_TYPE:
			gre.EncapType = native.Uint16(datum.Value[0:2])
		case nl.IFLA_GRE_ENCAP_FLAGS:
			gre.EncapFlags = native.Uint16(datum.Value[0:2])
		case nl.IFLA_GRE_COLLECT_METADATA:
			if len(datum.Value) > 0 {
				gre.FlowBased = int8(datum.Value[0]) != 0
			}
		}
	}
}

func addGretunAttrs(gre *Gretun, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	if ip := gre.Local; ip != nil {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		data.AddRtAttr(nl.IFLA_GRE_LOCAL, []byte(ip))
	}

	if ip := gre.Remote; ip != nil {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		data.AddRtAttr(nl.IFLA_GRE_REMOTE, []byte(ip))
	}

	if gre.IKey != 0 {
		data.AddRtAttr(nl.IFLA_GRE_IKEY, htonl(gre.IKey))
		gre.IFlags |= uint16(nl.GRE_KEY)
	}

	if gre.OKey != 0 {
		data.AddRtAttr(nl.IFLA_GRE_OKEY, htonl(gre.OKey))
		gre.OFlags |= uint16(nl.GRE_KEY)
	}

	data.AddRtAttr(nl.IFLA_GRE_IFLAGS, htons(gre.IFlags))
	data.AddRtAttr(nl.IFLA_GRE_OFLAGS, htons(gre.OFlags))

	if gre.Link != 0 {
		data.AddRtAttr(nl.IFLA_GRE_LINK, nl.Uint32Attr(gre.Link))
	}

	data.AddRtAttr(nl.IFLA_GRE_PMTUDISC, nl.Uint8Attr(gre.PMtuDisc))
	data.AddRtAttr(nl.IFLA_GRE_TTL, nl.Uint8Attr(gre.Ttl))
	data.AddRtAttr(nl.IFLA_GRE_TOS, nl.Uint8Attr(gre.Tos))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_TYPE, nl.Uint16Attr(gre.EncapType))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_FLAGS, nl.Uint16Attr(gre.EncapFlags))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_SPORT, htons(gre.EncapSport))
	data.AddRtAttr(nl.IFLA_GRE_ENCAP_DPORT, htons(gre.EncapDport))
}

func parseGretunData(link Link, data []syscall.NetlinkRouteAttr) {
	gre := link.(*Gretun)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_GRE_IKEY:
			gre.IKey = ntohl(datum.Value[0:4])
		case nl.IFLA_GRE_OKEY:
			gre.OKey = ntohl(datum.Value[0:4])
		case nl.IFLA_GRE_LOCAL:
			gre.Local = net.IP(datum.Value)
		case nl.IFLA_GRE_REMOTE:
			gre.Remote = net.IP(datum.Value)
		case nl.IFLA_GRE_IFLAGS:
			gre.IFlags = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_OFLAGS:
			gre.OFlags = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_TTL:
			gre.Ttl = uint8(datum.Value[0])
		case nl.IFLA_GRE_TOS:
			gre.Tos = uint8(datum.Value[0])
		case nl.IFLA_GRE_PMTUDISC:
			gre.PMtuDisc = uint8(datum.Value[0])
		case nl.IFLA_GRE_ENCAP_TYPE:
			gre.EncapType = native.Uint16(datum.Value[0:2])
		case nl.IFLA_GRE_ENCAP_FLAGS:
			gre.EncapFlags = native.Uint16(datum.Value[0:2])
		case nl.IFLA_GRE_ENCAP_SPORT:
			gre.EncapSport = ntohs(datum.Value[0:2])
		case nl.IFLA_GRE_ENCAP_DPORT:
			gre.EncapDport = ntohs(datum.Value[0:2])
		}
	}
}

func parseLinkStats32(data []byte) *LinkStatistics {
	return (*LinkStatistics)((*LinkStatistics32)(unsafe.Pointer(&data[0:SizeofLinkStats32][0])).to64())
}

func parseLinkStats64(data []byte) *LinkStatistics {
	return (*LinkStatistics)((*LinkStatistics64)(unsafe.Pointer(&data[0:SizeofLinkStats64][0])))
}

func addXdpAttrs(xdp *LinkXdp, req *nl.NetlinkRequest) {
	attrs := nl.NewRtAttr(unix.IFLA_XDP|unix.NLA_F_NESTED, nil)
	b := make([]byte, 4)
	native.PutUint32(b, uint32(xdp.Fd))
	attrs.AddRtAttr(nl.IFLA_XDP_FD, b)
	if xdp.Flags != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, xdp.Flags)
		attrs.AddRtAttr(nl.IFLA_XDP_FLAGS, b)
	}
	req.AddData(attrs)
}

func parseLinkXdp(data []byte) (*LinkXdp, error) {
	attrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return nil, err
	}
	xdp := &LinkXdp{}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.IFLA_XDP_FD:
			xdp.Fd = int(native.Uint32(attr.Value[0:4]))
		case nl.IFLA_XDP_ATTACHED:
			xdp.Attached = attr.Value[0] != 0
		case nl.IFLA_XDP_FLAGS:
			xdp.Flags = native.Uint32(attr.Value[0:4])
		case nl.IFLA_XDP_PROG_ID:
			xdp.ProgId = native.Uint32(attr.Value[0:4])
		}
	}
	return xdp, nil
}

func addIptunAttrs(iptun *Iptun, linkInfo *nl.RtAttr) {
	if iptun.FlowBased {
		// In flow based mode, no other attributes need to be configured
		linkInfo.AddRtAttr(nl.IFLA_IPTUN_COLLECT_METADATA, boolAttr(iptun.FlowBased))
		return
	}

	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	ip := iptun.Local.To4()
	if ip != nil {
		data.AddRtAttr(nl.IFLA_IPTUN_LOCAL, []byte(ip))
	}

	ip = iptun.Remote.To4()
	if ip != nil {
		data.AddRtAttr(nl.IFLA_IPTUN_REMOTE, []byte(ip))
	}

	if iptun.Link != 0 {
		data.AddRtAttr(nl.IFLA_IPTUN_LINK, nl.Uint32Attr(iptun.Link))
	}
	data.AddRtAttr(nl.IFLA_IPTUN_PMTUDISC, nl.Uint8Attr(iptun.PMtuDisc))
	data.AddRtAttr(nl.IFLA_IPTUN_TTL, nl.Uint8Attr(iptun.Ttl))
	data.AddRtAttr(nl.IFLA_IPTUN_TOS, nl.Uint8Attr(iptun.Tos))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_TYPE, nl.Uint16Attr(iptun.EncapType))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_FLAGS, nl.Uint16Attr(iptun.EncapFlags))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_SPORT, htons(iptun.EncapSport))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_DPORT, htons(iptun.EncapDport))
}

func parseIptunData(link Link, data []syscall.NetlinkRouteAttr) {
	iptun := link.(*Iptun)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_IPTUN_LOCAL:
			iptun.Local = net.IP(datum.Value[0:4])
		case nl.IFLA_IPTUN_REMOTE:
			iptun.Remote = net.IP(datum.Value[0:4])
		case nl.IFLA_IPTUN_TTL:
			iptun.Ttl = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_TOS:
			iptun.Tos = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_PMTUDISC:
			iptun.PMtuDisc = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_ENCAP_SPORT:
			iptun.EncapSport = ntohs(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_DPORT:
			iptun.EncapDport = ntohs(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_TYPE:
			iptun.EncapType = native.Uint16(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_FLAGS:
			iptun.EncapFlags = native.Uint16(datum.Value[0:2])
		case nl.IFLA_IPTUN_COLLECT_METADATA:
			iptun.FlowBased = int8(datum.Value[0]) != 0
		}
	}
}

func addSittunAttrs(sittun *Sittun, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	if sittun.Link != 0 {
		data.AddRtAttr(nl.IFLA_IPTUN_LINK, nl.Uint32Attr(sittun.Link))
	}

	ip := sittun.Local.To4()
	if ip != nil {
		data.AddRtAttr(nl.IFLA_IPTUN_LOCAL, []byte(ip))
	}

	ip = sittun.Remote.To4()
	if ip != nil {
		data.AddRtAttr(nl.IFLA_IPTUN_REMOTE, []byte(ip))
	}

	if sittun.Ttl > 0 {
		// Would otherwise fail on 3.10 kernel
		data.AddRtAttr(nl.IFLA_IPTUN_TTL, nl.Uint8Attr(sittun.Ttl))
	}

	data.AddRtAttr(nl.IFLA_IPTUN_TOS, nl.Uint8Attr(sittun.Tos))
	data.AddRtAttr(nl.IFLA_IPTUN_PMTUDISC, nl.Uint8Attr(sittun.PMtuDisc))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_TYPE, nl.Uint16Attr(sittun.EncapType))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_FLAGS, nl.Uint16Attr(sittun.EncapFlags))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_SPORT, htons(sittun.EncapSport))
	data.AddRtAttr(nl.IFLA_IPTUN_ENCAP_DPORT, htons(sittun.EncapDport))
}

func parseSittunData(link Link, data []syscall.NetlinkRouteAttr) {
	sittun := link.(*Sittun)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_IPTUN_LOCAL:
			sittun.Local = net.IP(datum.Value[0:4])
		case nl.IFLA_IPTUN_REMOTE:
			sittun.Remote = net.IP(datum.Value[0:4])
		case nl.IFLA_IPTUN_TTL:
			sittun.Ttl = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_TOS:
			sittun.Tos = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_PMTUDISC:
			sittun.PMtuDisc = uint8(datum.Value[0])
		case nl.IFLA_IPTUN_ENCAP_TYPE:
			sittun.EncapType = native.Uint16(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_FLAGS:
			sittun.EncapFlags = native.Uint16(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_SPORT:
			sittun.EncapSport = ntohs(datum.Value[0:2])
		case nl.IFLA_IPTUN_ENCAP_DPORT:
			sittun.EncapDport = ntohs(datum.Value[0:2])
		}
	}
}

func addVtiAttrs(vti *Vti, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)

	family := FAMILY_V4
	if vti.Local.To4() == nil {
		family = FAMILY_V6
	}

	var ip net.IP

	if family == FAMILY_V4 {
		ip = vti.Local.To4()
	} else {
		ip = vti.Local
	}
	if ip != nil {
		data.AddRtAttr(nl.IFLA_VTI_LOCAL, []byte(ip))
	}

	if family == FAMILY_V4 {
		ip = vti.Remote.To4()
	} else {
		ip = vti.Remote
	}
	if ip != nil {
		data.AddRtAttr(nl.IFLA_VTI_REMOTE, []byte(ip))
	}

	if vti.Link != 0 {
		data.AddRtAttr(nl.IFLA_VTI_LINK, nl.Uint32Attr(vti.Link))
	}

	data.AddRtAttr(nl.IFLA_VTI_IKEY, htonl(vti.IKey))
	data.AddRtAttr(nl.IFLA_VTI_OKEY, htonl(vti.OKey))
}

func parseVtiData(link Link, data []syscall.NetlinkRouteAttr) {
	vti := link.(*Vti)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_VTI_LOCAL:
			vti.Local = net.IP(datum.Value)
		case nl.IFLA_VTI_REMOTE:
			vti.Remote = net.IP(datum.Value)
		case nl.IFLA_VTI_IKEY:
			vti.IKey = ntohl(datum.Value[0:4])
		case nl.IFLA_VTI_OKEY:
			vti.OKey = ntohl(datum.Value[0:4])
		}
	}
}

func addVrfAttrs(vrf *Vrf, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	b := make([]byte, 4)
	native.PutUint32(b, uint32(vrf.Table))
	data.AddRtAttr(nl.IFLA_VRF_TABLE, b)
}

func parseVrfData(link Link, data []syscall.NetlinkRouteAttr) {
	vrf := link.(*Vrf)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_VRF_TABLE:
			vrf.Table = native.Uint32(datum.Value[0:4])
		}
	}
}

func addBridgeAttrs(bridge *Bridge, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	if bridge.MulticastSnooping != nil {
		data.AddRtAttr(nl.IFLA_BR_MCAST_SNOOPING, boolToByte(*bridge.MulticastSnooping))
	}
	if bridge.HelloTime != nil {
		data.AddRtAttr(nl.IFLA_BR_HELLO_TIME, nl.Uint32Attr(*bridge.HelloTime))
	}
	if bridge.VlanFiltering != nil {
		data.AddRtAttr(nl.IFLA_BR_VLAN_FILTERING, boolToByte(*bridge.VlanFiltering))
	}
}

func parseBridgeData(bridge Link, data []syscall.NetlinkRouteAttr) {
	br := bridge.(*Bridge)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_BR_HELLO_TIME:
			helloTime := native.Uint32(datum.Value[0:4])
			br.HelloTime = &helloTime
		case nl.IFLA_BR_MCAST_SNOOPING:
			mcastSnooping := datum.Value[0] == 1
			br.MulticastSnooping = &mcastSnooping
		case nl.IFLA_BR_VLAN_FILTERING:
			vlanFiltering := datum.Value[0] == 1
			br.VlanFiltering = &vlanFiltering
		}
	}
}

func addGTPAttrs(gtp *GTP, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	data.AddRtAttr(nl.IFLA_GTP_FD0, nl.Uint32Attr(uint32(gtp.FD0)))
	data.AddRtAttr(nl.IFLA_GTP_FD1, nl.Uint32Attr(uint32(gtp.FD1)))
	data.AddRtAttr(nl.IFLA_GTP_PDP_HASHSIZE, nl.Uint32Attr(131072))
	if gtp.Role != nl.GTP_ROLE_GGSN {
		data.AddRtAttr(nl.IFLA_GTP_ROLE, nl.Uint32Attr(uint32(gtp.Role)))
	}
}

func parseGTPData(link Link, data []syscall.NetlinkRouteAttr) {
	gtp := link.(*GTP)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_GTP_FD0:
			gtp.FD0 = int(native.Uint32(datum.Value))
		case nl.IFLA_GTP_FD1:
			gtp.FD1 = int(native.Uint32(datum.Value))
		case nl.IFLA_GTP_PDP_HASHSIZE:
			gtp.PDPHashsize = int(native.Uint32(datum.Value))
		case nl.IFLA_GTP_ROLE:
			gtp.Role = int(native.Uint32(datum.Value))
		}
	}
}

func parseVfInfoList(data []syscall.NetlinkRouteAttr) ([]VfInfo, error) {
	var vfs []VfInfo

	for i, element := range data {
		if element.Attr.Type != nl.IFLA_VF_INFO {
			return nil, fmt.Errorf("Incorrect element type in vf info list: %d", element.Attr.Type)
		}
		vfAttrs, err := nl.ParseRouteAttr(element.Value)
		if err != nil {
			return nil, err
		}
		vfs = append(vfs, parseVfInfo(vfAttrs, i))
	}
	return vfs, nil
}

func parseVfInfo(data []syscall.NetlinkRouteAttr, id int) VfInfo {
	vf := VfInfo{ID: id}
	for _, element := range data {
		switch element.Attr.Type {
		case nl.IFLA_VF_MAC:
			mac := nl.DeserializeVfMac(element.Value[:])
			vf.Mac = mac.Mac[:6]
		case nl.IFLA_VF_VLAN:
			vl := nl.DeserializeVfVlan(element.Value[:])
			vf.Vlan = int(vl.Vlan)
			vf.Qos = int(vl.Qos)
		case nl.IFLA_VF_TX_RATE:
			txr := nl.DeserializeVfTxRate(element.Value[:])
			vf.TxRate = int(txr.Rate)
		case nl.IFLA_VF_SPOOFCHK:
			sp := nl.DeserializeVfSpoofchk(element.Value[:])
			vf.Spoofchk = sp.Setting != 0
		case nl.IFLA_VF_LINK_STATE:
			ls := nl.DeserializeVfLinkState(element.Value[:])
			vf.LinkState = ls.LinkState
		}
	}
	return vf
}

func addXfrmiAttrs(xfrmi *Xfrmi, linkInfo *nl.RtAttr) {
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	data.AddRtAttr(nl.IFLA_XFRM_LINK, nl.Uint32Attr(uint32(xfrmi.ParentIndex)))
	data.AddRtAttr(nl.IFLA_XFRM_IF_ID, nl.Uint32Attr(xfrmi.Ifid))

}

func parseXfrmiData(link Link, data []syscall.NetlinkRouteAttr) {
	xfrmi := link.(*Xfrmi)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_XFRM_LINK:
			xfrmi.ParentIndex = int(native.Uint32(datum.Value))
		case nl.IFLA_XFRM_IF_ID:
			xfrmi.Ifid = native.Uint32(datum.Value)
		}
	}
}

// LinkSetBondSlave add slave to bond link via ioctl interface.
func LinkSetBondSlave(link Link, master *Bond) error {
	fd, err := getSocketUDP()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	ifreq := newIocltSlaveReq(link.Attrs().Name, master.Attrs().Name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.SIOCBONDENSLAVE, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return fmt.Errorf("Failed to enslave %q to %q, errno=%v", link.Attrs().Name, master.Attrs().Name, errno)
	}
	return nil
}

// VethPeerIndex get veth peer index.
func VethPeerIndex(link *Veth) (int, error) {
	fd, err := getSocketUDP()
	if err != nil {
		return -1, err
	}
	defer syscall.Close(fd)

	ifreq, sSet := newIocltStringSetReq(link.Name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}

	gstrings := &ethtoolGstrings{
		cmd:       ETHTOOL_GSTRINGS,
		stringSet: ETH_SS_STATS,
		length:    sSet.data[0],
	}
	ifreq.Data = uintptr(unsafe.Pointer(gstrings))
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}

	stats := &ethtoolStats{
		cmd:    ETHTOOL_GSTATS,
		nStats: gstrings.length,
	}
	ifreq.Data = uintptr(unsafe.Pointer(stats))
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return -1, fmt.Errorf("SIOCETHTOOL request for %q failed, errno=%v", link.Attrs().Name, errno)
	}
	return int(stats.data[0]), nil
}
