// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// CheckRequirements checks that minimum kernel requirements are met for
// configuring the BPF datapath.
func CheckRequirements(log *slog.Logger) error {
	_, err := safenetlink.RuleList(netlink.FAMILY_V4)
	if errors.Is(err, unix.EAFNOSUPPORT) {
		log.Error("Policy routing:NOT OK. "+
			"Please enable kernel configuration item CONFIG_IP_MULTIPLE_TABLES",
			logfields.Error, err,
		)
	}

	if option.Config.EnableIPv6 {
		if _, err := os.Stat("/proc/net/if_inet6"); os.IsNotExist(err) {
			return errors.New("kernel: ipv6 is enabled in agent but ipv6 is either disabled or not compiled in the kernel")
		}
	}

	if !option.Config.DryMode {
		if probes.HaveBPF() != nil {
			return errors.New("Require support for bpf() (CONFIG_BPF_SYSCALL=y)")
		}

		if probes.HaveBPFJIT() != nil {
			return errors.New("Require support for the eBPF JIT (CONFIG_HAVE_EBPF_JIT=y and CONFIG_BPF_JIT=y)")
		}

		if probes.HaveTCBPF() != nil {
			// If tcx is (explicitly) disabled and there's no tc-bpf fallback, suggest
			// a kernel with tc-bpf support.
			if !option.Config.EnableTCX {
				return errors.New("Require support for the clsact qdisc (CONFIG_NET_CLS_ACT=y), ingress classes (CONFIG_NET_SCH_INGRESS=y) and the bpf filter (CONFIG_NET_CLS_BPF=y)")
			}

			// If tcx is enabled but not supported, and there's no tc-bpf fallback,
			// suggest a kernel with tcx support.
			if probes.HaveTCX() != nil {
				return errors.New("Require support for tcx links (Linux 6.6 or newer)")
			}
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnSkbChangeTail) != nil {
			return errors.New("Require support for bpf_skb_change_tail() (Linux 4.9.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.CGroupSockAddr, asm.FnGetSocketCookie) != nil {
			return errors.New("Require support for bpf_get_socket_cookie() (Linux 4.12 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.CGroupSockAddr, asm.FnGetCurrentCgroupId) != nil {
			return errors.New("Require support for bpf_get_current_cgroup_id() (Linux 4.18 or newer)")
		}

		if probes.HaveDeadCodeElim() != nil {
			return errors.New("Require support for dead code elimination (Linux 5.1 or newer)")
		}

		if probes.HaveWriteableQueueMapping() != nil {
			return errors.New("Require support for TCP EDT and writeable skb->queue_mapping (Linux 5.1 or newer)")
		}

		if probes.HaveLargeInstructionLimit(log) != nil {
			return errors.New("Require support for large programs (Linux 5.2.0 or newer)")
		}

		if probes.HaveSKBAdjustRoomL2RoomMACSupport(log) != nil {
			return errors.New("Require support for bpf_skb_adjust_room with BPF_ADJ_ROOM_MAC mode (Linux 5.2 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.CGroupSock, asm.FnJiffies64) != nil ||
			probes.HaveProgramHelper(log, ebpf.CGroupSockAddr, asm.FnJiffies64) != nil ||
			probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnJiffies64) != nil ||
			probes.HaveProgramHelper(log, ebpf.XDP, asm.FnJiffies64) != nil {
			return errors.New("Require support for bpf_jiffies64 (Linux 5.6.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.CGroupSock, asm.FnGetNetnsCookie) != nil ||
			probes.HaveProgramHelper(log, ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) != nil {
			return errors.New("Require support for bpf_get_netns_cookie() (Linux 5.7.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnCsumLevel) != nil {
			return errors.New("Require support for bpf_csum_level() (Linux 5.8.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnSkbChangeHead) != nil {
			return errors.New("Require support for bpf_skb_change_head() (Linux 5.8.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnRedirectNeigh) != nil {
			return errors.New("Require support for bpf_redirect_neigh() (Linux 5.10.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnRedirectPeer) != nil {
			return errors.New("Require support for bpf_redirect_peer() (Linux 5.10.0 or newer)")
		}
	}
	return nil
}
