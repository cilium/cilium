// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func getEntryProgInstructions(fd int) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R2, fd),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}
}

// setupIpvlanInRemoteNs creates a tail call map, renames the netdevice inside
// the target netns and attaches a BPF program to it on egress path which
// then jumps into the tail call map index 0.
//
// NB: Do not close the returned map before it has been pinned. Otherwise,
// the map will be destroyed.
func setupIpvlanInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) (*ebpf.Map, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("unable to increase rlimit: %s", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create root BPF map for %q: %s", dstIfName, err)
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

		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Type:         ebpf.SchedCLS,
			Instructions: getEntryProgInstructions(m.FD()),
			License:      "ASL2",
		})
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
			Fd:           prog.FD(),
			Name:         "polEntry",
			DirectAction: true,
		}
		if err = netlink.FilterAdd(filter); err != nil {
			prog.Close()
			return fmt.Errorf("failed to create cls_bpf filter on %q: %s", dstIfName, err)
		}

		return nil
	})
	if err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

// CreateIpvlanSlave creates an ipvlan slave in L3 based on the master device.
func CreateIpvlanSlave(id string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	tmpIfName := Endpoint2TempIfName(id)
	ipvlan, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)

	return ipvlan, link, tmpIfName, err
}

func createIpvlanSlave(lxcIfName string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, netlink.Link, error) {
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
			TxQLen:      1000,
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

	log.WithFields(logrus.Fields{
		logfields.Ipvlan: []string{lxcIfName},
		"mode":           mode,
	}).Debugf("Created ipvlan slave")

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

	return ipvlan, link, nil
}

// CreateAndSetupIpvlanSlave creates an ipvlan slave device for the given
// master device, moves it to the given network namespace, and finally
// initializes it (see setupIpvlanInRemoteNs).
func CreateAndSetupIpvlanSlave(id string, slaveIfName string, netNs ns.NetNS, mtu int, masterDev int, mode string, ep *models.EndpointChangeRequest) (*ebpf.Map, error) {
	var tmpIfName string

	if id == "" {
		tmpIfName = Endpoint2TempRandIfName()
	} else {
		tmpIfName = Endpoint2TempIfName(id)
	}

	_, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)
	if err != nil {
		return nil, fmt.Errorf("createIpvlanSlave has failed: %w", err)
	}

	if err = netlink.LinkSetNsFd(link, int(netNs.Fd())); err != nil {
		return nil, fmt.Errorf("unable to move ipvlan slave '%v' to netns: %s", link, err)
	}

	m, err := setupIpvlanInRemoteNs(netNs, tmpIfName, slaveIfName)
	if err != nil {
		return nil, fmt.Errorf("unable to setup ipvlan slave in remote netns: %w", err)
	}

	mapID, err := m.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to get map ID: %w", err)
	}
	ep.DatapathMapID = int64(mapID)

	return m, nil
}
