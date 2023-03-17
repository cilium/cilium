// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

const (
	PodlinkEntryFromEndpoint = "cil_plk_from_container"
	PodlinkEntryToEndpoint   = "cil_plk_to_container"
)

const (
	unknownEntryIndex = -1

	egressEntryIndex  = 0
	ingressEntryIndex = 1
)

const (
	programArrayMapKeySize   = 4
	programArrayMapValueSize = 4
)

type LinkInfo struct {
	Name, IPv4, IPv6, Mac string
	Index                 int64
}

type AttachFuncType func(netlink.Link, *ebpf.Program, string) error

type EntryProgSpec struct {
	Index    int32
	ProgName string
	Attach   AttachFuncType
}

type StubMapSpec struct {
	MaxEntries uint32
	Progs      []EntryProgSpec
}

func setupStubMap(sms StubMapSpec) (*ebpf.Map, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    programArrayMapKeySize,
		ValueSize:  programArrayMapValueSize,
		MaxEntries: sms.MaxEntries,
	})
	return m, err
}

func attachEntryProgram(link netlink.Link, mapfd int, progSpec EntryProgSpec) error {
	if progSpec.Index < 0 {
		return fmt.Errorf("invalid entry prog index")
	}

	linkName := link.Attrs().Name
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: progSpec.ProgName,
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R2, mapfd),
			asm.Mov.Imm(asm.R3, progSpec.Index),
			asm.FnTailCall.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "ASL2",
	})
	if err != nil {
		return fmt.Errorf("failed to load BPF prog for %q: %s", linkName, err)
	}

	if progSpec.Attach == nil {
		return fmt.Errorf("failed to load AttachFunc, prog %s AttachFunc has not been specified", progSpec.ProgName)
	}
	if err = progSpec.Attach(link, prog, progSpec.ProgName); err != nil {
		prog.Close()
		return fmt.Errorf("failed to attach BPF prog for %q: %s", linkName, err)
	}
	return nil
}

func SetupPodlink(netNs ns.NetNS, sms StubMapSpec) (*ebpf.Map, *LinkInfo, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, err
	}

	m, err := setupStubMap(sms)
	if err != nil {
		return nil, nil, err
	}

	var linkInfo LinkInfo
	if err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}

		for _, link := range links {
			if link.Attrs().Name == "lo" {
				continue
			}
			linkInfo.Name = link.Attrs().Name
			linkInfo.Mac = link.Attrs().HardwareAddr.String()
			linkInfo.Index = int64(link.Attrs().Index)

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				linkInfo.IPv4 = addrs[0].IPNet.IP.String()
			}

			addrsv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				linkInfo.IPv6 = addrsv6[0].IPNet.IP.String()
			}

			for _, prog := range sms.Progs {
				if err := attachEntryProgram(link, m.FD(), prog); err != nil {
					return err
				}
			}
			return nil
		}
		return fmt.Errorf("no link found inside container")
	}); err != nil {
		m.Close()
		return nil, nil, err
	}

	return m, &linkInfo, nil
}
