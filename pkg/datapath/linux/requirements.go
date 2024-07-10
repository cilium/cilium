// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"errors"
	"log/slog"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// CheckRequirements checks that minimum kernel requirements are met for
// configuring the BPF datapath.
func CheckRequirements(log *slog.Logger) error {
	_, err := netlink.RuleList(netlink.FAMILY_V4)
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
		probeManager := probes.NewProbeManager()

		if probes.HaveDeadCodeElim() != nil {
			return errors.New("Require support for dead code elimination (Linux 5.1 or newer)")
		}

		if probes.HaveLargeInstructionLimit() != nil {
			return errors.New("Require support for large programs (Linux 5.2.0 or newer)")
		}

		if err := probeManager.SystemConfigProbes(); err != nil {
			// TODO(vincentmli): revisit log when GH#14314 has been resolved
			// Warn missing required kernel config option
			log.Warn("BPF system config check: NOT OK.", logfields.Error, err)
		}
	}
	return nil
}
