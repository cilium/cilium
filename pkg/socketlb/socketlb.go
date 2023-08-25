// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package socketlb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

const (
	Subsystem = "socketlb"

	Connect4     = "cil_sock4_connect"
	SendMsg4     = "cil_sock4_sendmsg"
	RecvMsg4     = "cil_sock4_recvmsg"
	GetPeerName4 = "cil_sock4_getpeername"
	PostBind4    = "cil_sock4_post_bind"
	PreBind4     = "cil_sock4_pre_bind"
	Connect6     = "cil_sock6_connect"
	SendMsg6     = "cil_sock6_sendmsg"
	RecvMsg6     = "cil_sock6_recvmsg"
	GetPeerName6 = "cil_sock6_getpeername"
	PostBind6    = "cil_sock6_post_bind"
	PreBind6     = "cil_sock6_pre_bind"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsystem)

	cgroupProgs = []string{
		Connect4, SendMsg4, RecvMsg4, GetPeerName4,
		PostBind4, PreBind4, Connect6, SendMsg6,
		RecvMsg6, GetPeerName6, PostBind6, PreBind6}
)

// TODO: Clean up bpffs root logic and make this a var.
func cgroupLinkPath() string {
	return filepath.Join(bpf.CiliumPath(), Subsystem, "links/cgroup")
}

// Enable attaches necessary bpf programs for socketlb based on ciliums config.
//
// On restart, Enable can also detach unnecessary programs if specific configuration
// options have changed.
// It expects bpf_sock.c to be compiled previously, so that bpf_sock.o is present
// in the Runtime dir.
func Enable() (err error) {
	if err := os.MkdirAll(cgroupLinkPath(), 0777); err != nil {
		return fmt.Errorf("create bpffs link directory: %w", err)
	}

	spec, err := bpf.LoadCollectionSpec(filepath.Join(option.Config.StateDir, "bpf_sock.o"))
	if err != nil {
		return fmt.Errorf("failed to load collection spec for bpf_sock.o: %w", err)
	}

	if err := bpf.StartBPFFSMigration(bpf.TCGlobalsPath(), spec); err != nil {
		return fmt.Errorf("failed to start bpffs map migration: %w", err)
	}

	// This captures named return variable err.
	defer func() {
		if err != nil {
			log.WithError(err).Debug("Reverting bpffs map migration")
			if e := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, true); e != nil {
				log.WithError(e).Error("Could not revert bpffs map migration")
				return
			}
		}

		log.Debug("Finalizing bpffs map migration")
		if e := bpf.FinalizeBPFFSMigration(bpf.TCGlobalsPath(), spec, false); e != nil {
			log.WithError(e).Error("Could not finalize bpffs map migration")
		}
	}()

	coll, err := bpf.LoadCollection(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
	})
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %v\n", err, ve); err != nil {
			return fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("failed loading eBPF collection into the kernel: %w", err)
	}
	defer coll.Close()

	// Map a program name to its enabled status. Programs disabled by default.
	enabled := make(map[string]bool)
	for _, p := range cgroupProgs {
		enabled[p] = false
	}

	if option.Config.EnableIPv4 {
		enabled[Connect4] = true
		enabled[SendMsg4] = true
		enabled[RecvMsg4] = true

		if option.Config.EnableSocketLBPeer {
			enabled[GetPeerName4] = true
		}

		if option.Config.EnableNodePort && option.Config.NodePortBindProtection {
			enabled[PostBind4] = true
		}

		if option.Config.EnableHealthDatapath {
			enabled[PreBind4] = true
		}
	}

	// v6 will be non-nil if v6 support is compiled out.
	_, v6 := sysctl.ReadInt("net.ipv6.conf.all.forwarding")

	if option.Config.EnableIPv6 ||
		(option.Config.EnableIPv4 && v6 == nil) {
		enabled[Connect6] = true
		enabled[SendMsg6] = true
		enabled[RecvMsg6] = true

		if option.Config.EnableSocketLBPeer {
			enabled[GetPeerName6] = true
		}

		if option.Config.EnableNodePort && option.Config.NodePortBindProtection {
			enabled[PostBind6] = true
		}

		if option.Config.EnableHealthDatapath {
			enabled[PreBind6] = true
		}
	}

	for p, s := range enabled {
		if s {
			if err := attachCgroup(coll, p, cgroups.GetCgroupRoot(), cgroupLinkPath()); err != nil {
				return fmt.Errorf("cgroup attach: %w", err)
			}
			continue
		}
		if err := detachCgroup(p, cgroups.GetCgroupRoot(), cgroupLinkPath()); err != nil {
			return fmt.Errorf("cgroup detach: %w", err)
		}
	}

	return nil
}

// Disable detaches all bpf programs for socketlb.
func Disable() error {
	for _, p := range cgroupProgs {
		if err := detachCgroup(p, cgroups.GetCgroupRoot(), cgroupLinkPath()); err != nil {
			return fmt.Errorf("detach cgroup: %w", err)
		}
	}

	return nil
}
