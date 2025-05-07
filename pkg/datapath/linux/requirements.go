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

	// bpftool checks
	if !option.Config.DryMode {
		probeManager := probes.NewProbeManager(log)

		if probes.HaveProgramHelper(log, ebpf.CGroupSockAddr, asm.FnGetSocketCookie) != nil {
			return errors.New("Require support for bpf_get_socket_cookie() (Linux 4.12 or newer)")
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

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnCsumLevel) != nil {
			return errors.New("Require support for bpf_csum_level() (Linux 5.8.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnRedirectNeigh) != nil {
			return errors.New("Require support for bpf_redirect_neigh() (Linux 5.10.0 or newer)")
		}

		if probes.HaveProgramHelper(log, ebpf.SchedCLS, asm.FnRedirectPeer) != nil {
			return errors.New("Require support for bpf_redirect_peer() (Linux 5.10.0 or newer)")
		}

		if err := probeManager.SystemConfigProbes(); err != nil {
			// TODO(vincentmli): revisit log when GH#14314 has been resolved
			// Warn missing required kernel config option
			log.Warn("BPF system config check: NOT OK.", logfields.Error, err)
		}
	}
	return nil
}
