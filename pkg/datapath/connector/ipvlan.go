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

package connector

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

// TODO: We cannot include bpf package here due to CGO_ENABLED=0,
// but we should refactor common bits into a pure golang package.

type bpfAttrProg struct {
	ProgType    uint32
	InsnCnt     uint32
	Insns       uintptr
	License     uintptr
	LogLevel    uint32
	LogSize     uint32
	LogBuf      uintptr
	KernVersion uint32
	Flags       uint32
	Name        [16]byte
}

func loadEntryProg(mapFd int) (int, error) {
	tmp := (*[4]byte)(unsafe.Pointer(&mapFd))
	insns := []byte{
		0x18, 0x12, 0x00, 0x00, tmp[0], tmp[1], tmp[2], tmp[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	license := []byte{'A', 'S', 'L', '2', '\x00'}
	bpfAttr := bpfAttrProg{
		ProgType: 3,
		InsnCnt:  uint32(len(insns) / 8),
		Insns:    uintptr(unsafe.Pointer(&insns[0])),
		License:  uintptr(unsafe.Pointer(&license[0])),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5, /* BPF_PROG_LOAD */
		uintptr(unsafe.Pointer(&bpfAttr)),
		unsafe.Sizeof(bpfAttr))
	runtime.KeepAlive(&insns)
	runtime.KeepAlive(&license)
	runtime.KeepAlive(&bpfAttr)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

type bpfAttrMap struct {
	MapType    uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type bpfMapInfo struct {
	MapType    uint32
	MapID      uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type bpfAttrObjInfo struct {
	Fd      uint32
	InfoLen uint32
	Info    uint64
}

func createTailCallMap() (int, int, error) {
	bpfAttr := bpfAttrMap{
		MapType:    3,
		SizeKey:    4,
		SizeValue:  4,
		MaxEntries: 1,
		Flags:      0,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 0, /* BPF_MAP_CREATE */
		uintptr(unsafe.Pointer(&bpfAttr)),
		unsafe.Sizeof(bpfAttr))
	runtime.KeepAlive(&bpfAttr)
	if int(fd) < 0 || errno != 0 {
		return 0, 0, errno
	}

	info := bpfMapInfo{}
	bpfAttrInfo := bpfAttrObjInfo{
		Fd:      uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	bpfAttr2 := struct {
		info bpfAttrObjInfo
	}{
		info: bpfAttrInfo,
	}
	ret, _, errno := unix.Syscall(unix.SYS_BPF, 15, /* BPF_OBJ_GET_INFO_BY_FD */
		uintptr(unsafe.Pointer(&bpfAttr2)),
		unsafe.Sizeof(bpfAttr2))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&bpfAttr2)
	if ret != 0 || errno != 0 {
		unix.Close(int(fd))
		return 0, 0, errno
	}

	return int(fd), int(info.MapID), nil
}

// setupIpvlanInRemoteNs creates a tail call map, renames the netdevice inside
// the target netns and attaches a BPF program to it on egress path which
// then jumps into the tail call map index 0.
//
// NB: Do not close the returned mapFd before it has been pinned. Otherwise,
// the map will be destroyed.
func setupIpvlanInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) (int, int, error) {
	rl := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	mapFd, mapId, err := createTailCallMap()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create root BPF map for %q: %s", dstIfName, err)
	}

	err = netNs.Do(func(_ ns.NetNS) error {
		var err error

		if srcIfName != dstIfName {
			err = link.Rename(srcIfName, dstIfName)
			if err != nil {
				return fmt.Errorf("failed to rename ipvlan from %q to %q: %s", srcIfName, dstIfName, err)
			}
		}

		ipvlan, err := netlink.LinkByName(dstIfName)
		if err != nil {
			return fmt.Errorf("failed to lookup ipvlan device %q: %s", dstIfName, err)
		}

		qdiscAttrs := netlink.QdiscAttrs{
			LinkIndex: ipvlan.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		}
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: qdiscAttrs,
			QdiscType:  "clsact",
		}
		if err = netlink.QdiscAdd(qdisc); err != nil {
			return fmt.Errorf("failed to create clsact qdisc on %q: %s", dstIfName, err)
		}

		progFd, err := loadEntryProg(mapFd)
		if err != nil {
			return fmt.Errorf("failed to load root BPF prog for %q: %s", dstIfName, err)
		}

		filterAttrs := netlink.FilterAttrs{
			LinkIndex: ipvlan.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  3,
			Priority:  1,
		}
		filter := &netlink.BpfFilter{
			FilterAttrs:  filterAttrs,
			Fd:           progFd,
			Name:         "polEntry",
			DirectAction: true,
		}
		if err = netlink.FilterAdd(filter); err != nil {
			unix.Close(progFd)
			return fmt.Errorf("failed to create cls_bpf filter on %q: %s", dstIfName, err)
		}

		return nil
	})
	if err != nil {
		unix.Close(mapFd)
		return 0, 0, err
	}
	return mapFd, mapId, nil
}

// CreateIpvlanSlave creates an ipvlan slave in L3 based on the master device.
func CreateIpvlanSlave(id string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	tmpIfName := Endpoint2TempIfName(id)
	ipvlan, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)

	return ipvlan, link, tmpIfName, err
}

func createIpvlanSlave(lxcIfName string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, error) {
	var (
		link       netlink.Link
		err        error
		ipvlanMode netlink.IPVlanMode
	)

	if masterDev == 0 {
		return nil, nil, fmt.Errorf("invalid: master device ifindex")
	}

	switch mode {
	case OperationModeL3:
		ipvlanMode = netlink.IPVLAN_MODE_L3
	case OperationModeL3S:
		ipvlanMode = netlink.IPVLAN_MODE_L3S
	default:
		return nil, nil, fmt.Errorf("invalid or unsupported ipvlan operation mode: %s", mode)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        lxcIfName,
			ParentIndex: masterDev,
		},
		Mode: ipvlanMode,
	}

	if err = netlink.LinkAdd(ipvlan); err != nil {
		return nil, nil, fmt.Errorf("unable to create ipvlan slave device: %s", err)
	}

	master, err := netlink.LinkByIndex(masterDev)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find master device: %s", err)
	}

	defer func() {
		if err != nil {
			if err = netlink.LinkDel(ipvlan); err != nil {
				log.WithError(err).WithField(logfields.Ipvlan, ipvlan.Name).Warn("failed to clean up ipvlan")
			}
		}
	}()

	log.WithField(logfields.Ipvlan, []string{lxcIfName}).Debug("Created ipvlan slave in L3 mode")

	err = DisableRpFilter(lxcIfName)
	if err != nil {
		return nil, nil, err
	}

	link, err = netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup ipvlan slave just created: %s", err)
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	ep.Mac = link.Attrs().HardwareAddr.String()
	ep.HostMac = master.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(link.Attrs().Index)
	ep.InterfaceName = link.Attrs().Name

	return ipvlan, &link, nil
}

// CreateAndSetupIpvlanSlave creates an ipvlan slave device for the given
// master device, moves it to the given network namespace, and finally
// initializes it (see setupIpvlanInRemoteNs).
func CreateAndSetupIpvlanSlave(id string, slaveIfName string, netNs ns.NetNS, mtu int, masterDev int, mode string, ep *models.EndpointChangeRequest) (int, error) {
	var tmpIfName string

	if id == "" {
		tmpIfName = Endpoint2TempRandIfName()
	} else {
		tmpIfName = Endpoint2TempIfName(id)
	}

	_, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)
	if err != nil {
		return 0, fmt.Errorf("createIpvlanSlave has failed: %s", err)
	}

	if err = netlink.LinkSetNsFd(*link, int(netNs.Fd())); err != nil {
		return 0, fmt.Errorf("unable to move ipvlan slave '%v' to netns: %s", link, err)
	}

	mapFD, mapID, err := setupIpvlanInRemoteNs(netNs, tmpIfName, slaveIfName)
	if err != nil {
		return 0, fmt.Errorf("unable to setup ipvlan slave in remote netns: %s", err)
	}

	ep.DatapathMapID = int64(mapID)

	return mapFD, nil
}

// ConfigureNetNSForIPVLAN sets up IPVLAN in the specified network namespace.
// Returns the file descriptor for the tail call map / ID, and an error if
// any operation while configuring said namespace fails.
func ConfigureNetNSForIPVLAN(netNsPath string) (mapFD, mapID int, err error) {
	var ipvlanIface string
	// To access the netns, `/var/run/docker/netns` has to
	// be bind mounted into the cilium-agent container with
	// the `rshared` option to prevent from leaking netns
	netNs, err := ns.GetNS(netNsPath)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to open container netns %s: %s", netNsPath, err)
	}

	// Docker doesn't report about interfaces used to connect to
	// container network, so we need to scan all to find the ipvlan slave
	err = netNs.Do(func(ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.Type() == "ipvlan" &&
				strings.HasPrefix(link.Attrs().Name,
					ContainerInterfacePrefix) {
				ipvlanIface = link.Attrs().Name
				break
			}
		}
		if ipvlanIface == "" {
			return fmt.Errorf("ipvlan slave link not found")
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to find ipvlan slave in container netns: %s", err)
	}

	mapFD, mapID, err = setupIpvlanInRemoteNs(netNs,
		ipvlanIface, ipvlanIface)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to setup ipvlan slave: %s", err)
	}

	return mapFD, mapID, nil
}
