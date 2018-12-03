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
	"math"
	"math/rand"
	"net"
	"time"
	"path/filepath"
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

type BPFAttrProg struct {
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
	bpfAttr := BPFAttrProg{
		ProgType: 3,
		InsnCnt:  uint32(len(insns)/8),
		Insns:    uintptr(unsafe.Pointer(&insns[0])),
		License:  uintptr(unsafe.Pointer(&license[0])),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5 /* BPF_PROG_LOAD */,
				     uintptr(unsafe.Pointer(&bpfAttr)),
				     unsafe.Sizeof(bpfAttr))
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

type BPFAttrMap struct {
	MapType    uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type BPFMapInfo struct {
	MapType    uint32
	MapID      uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type BPFAttrObjInfo struct {
	Fd      uint32
	InfoLen uint32
	Info    uint64
}

func createTailCallMap() (int, int, error) {
	bpfAttr := BPFAttrMap{
		MapType:    3,
		SizeKey:    4,
		SizeValue:  4,
		MaxEntries: 1,
		Flags:      0,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 0 /* BPF_MAP_CREATE */,
				     uintptr(unsafe.Pointer(&bpfAttr)),
				     unsafe.Sizeof(bpfAttr))
	if int(fd) < 0 || errno != 0 {
		return 0, 0, errno
	}

	info := BPFMapInfo{}
	bpfAttrInfo := BPFAttrObjInfo{
		Fd:      uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	bpfAttr2 := struct {
		info BPFAttrObjInfo
	}{
		info: bpfAttrInfo,
	}
	ret, _, errno := unix.Syscall(unix.SYS_BPF, 15 /* BPF_OBJ_GET_INFO_BY_FD */,
				      uintptr(unsafe.Pointer(&bpfAttr2)),
				      unsafe.Sizeof(bpfAttr2))
	if ret != 0 || errno != 0 {
		unix.Close(int(fd))
		return 0, 0, errno
	}

	return int(fd), int(info.MapID), nil
}

func SetupIpvlanRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) (int, int, error) {
	rl := unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	mapFd, mapId, err := createTailCallMap()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create root BPF map for %q: %s", dstIfName, err)
	}

	rand.Seed(time.Now().UTC().UnixNano())

	err = netNs.Do(func(_ ns.NetNS) error {
		// FIXME: Ugly hack for testing till we get IPAM to switch over, needed to UP the dev
		var address = &net.IPNet{IP: net.IPv4(10, 8, 1, 1 + byte(rand.Intn(128))), Mask: net.CIDRMask(24, 32)}
		var addr = &netlink.Addr{IPNet: address}
		var err error

		err = link.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename ipvlan from %q to %q: %s", srcIfName, dstIfName, err)
		}

		ipvlan, err := netlink.LinkByName(dstIfName)
		if err != nil {
			return fmt.Errorf("failed to lookup ipvlan device %q: %s", dstIfName, err)
		}

		if err = netlink.AddrAdd(ipvlan, addr); err != nil {
			return fmt.Errorf("failed to set ipvlan device %q IP addr: %s", dstIfName, err)
		}

		if err = netlink.LinkSetUp(ipvlan); err != nil {
			return fmt.Errorf("unable to bring up ipvlan device %q: %s", dstIfName, err)
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

func getIpvlanMasterName() string {
	return hostInterfacePrefix + "_master"
}

func SetupIpvlanMaster() (int, error) {
	var err error

	masterIfName := getIpvlanMasterName()
	master := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: masterIfName,
		},
	}

	link, err := netlink.LinkByName(masterIfName)
	if err == nil {
		base := link.Attrs()
		master.Index = base.Index
	} else {
		if err = netlink.LinkAdd(master); err != nil {
			return 0, fmt.Errorf("unable to create ipvlan master device: %s", err)
		}
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("unable to bring up ipvlan: %s", err)
	}

	return master.Index, nil
}

func SetupIpvlan(id string, mtu int, masterDev int, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}
	if masterDev == 0 {
		return nil, nil, "", fmt.Errorf("invalid: master device ifindex")
	}

	tmpIfName := Endpoint2TempRandIfName()
	ipvlan, link, err := setupIpvlanWithNames(tmpIfName, mtu, masterDev, ep)

	return ipvlan, link, tmpIfName, err
}

func setupIpvlanWithNames(lxcIfName string, mtu int, masterDev int, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, error) {
	var err error

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        lxcIfName,
			ParentIndex: masterDev,
		},
		Mode: netlink.IPVLAN_MODE_L3,
	}

	if err = netlink.LinkAdd(ipvlan); err != nil {
		return nil, nil, fmt.Errorf("unable to create ipvlan slave device: %s", err)
	}

	defer func() {
		if err != nil {
			if err = netlink.LinkDel(ipvlan); err != nil {
				log.WithError(err).WithField(logfields.Ipvlan, ipvlan.Name).Warn("failed to clean up ipvlan")
			}
		}
	}()

	log.WithField(logfields.Ipvlan, []string{lxcIfName}).Debug("Created ipvlan slave in L3 mode")

	rpFilterPath := filepath.Join("/proc", "sys", "net", "ipv4", "conf", lxcIfName, "rp_filter")
	err = WriteSysConfig(rpFilterPath, "0\n")
	if err != nil {
		return nil, nil, fmt.Errorf("unable to disable %s: %s", rpFilterPath, err)
	}

	link, err := netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup ipvlan slave just created: %s", err)
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	return ipvlan, &link, nil
}
