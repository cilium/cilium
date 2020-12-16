package connector

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/link"
)

// SetupNicInRemoteNs creates a tail call map, renames the netdevice inside
// the target netns and attaches a BPF program to it.
// egress is on 0. ingress is on 1.
// NB: Do not close the returned map before it has been pinned. Otherwise,
// the map will be destroyed.
func SetupNicInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string, egress bool, ingress bool) (*ebpf.Map, error) {
	rl := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("unable to increase rlimit: %s", err)
	}

	entries := uint32(0)
	if egress {
		entries++
	}
	if ingress {
		entries++
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: entries,
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

		if egress {
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type:         ebpf.SchedCLS,
				Instructions: getEntryProgInstructions(m.FD(), 0),
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
		}

		if ingress {
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type:         ebpf.SchedCLS,
				Instructions: getEntryProgInstructions(m.FD(), 1),
				License:      "ASL2",
			})
			if err != nil {
				return fmt.Errorf("failed to load root BPF prog for %q: %s", dstIfName, err)
			}

			filterAttrs := netlink.FilterAttrs{
				LinkIndex: ipvlan.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  3,
				Priority:  1,
			}
			filter := &netlink.BpfFilter{
				FilterAttrs:  filterAttrs,
				Fd:           prog.FD(),
				Name:         "ingressPolEntry",
				DirectAction: true,
			}
			if err = netlink.FilterAdd(filter); err != nil {
				prog.Close()
				return fmt.Errorf("failed to create ingress cls_bpf filter on %q: %s", dstIfName, err)
			}
		}

		return nil
	})
	if err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}
