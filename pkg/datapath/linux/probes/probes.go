// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

var tpl = template.New("headerfile")

func init() {
	const content = `
/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* THIS FILE WAS GENERATED DURING AGENT STARTUP. */

#pragma once

{{- if not .Common}}
#include "features.h"
{{- end}}

{{- range $key, $value := .Features}}
{{- if $value}}
#define {{$key}} 1
{{end}}
{{- end}}
`
	var err error
	tpl, err = tpl.Parse(content)
	if err != nil {
		logging.Fatal(logging.DefaultSlogLogger, "could not parse headerfile template", logfields.Error, err)
	}
}

// ErrNotSupported indicates that a feature is not supported by the current kernel.
var ErrNotSupported = errors.New("not supported")

type ProgramHelper struct {
	Program ebpf.ProgramType
	Helper  asm.BuiltinFunc
}

type FeatureProbes struct {
	ProgramHelpers map[ProgramHelper]bool
}

// HaveProgramHelper is a wrapper around features.HaveProgramHelper() to
// check if a certain BPF program/helper combination is supported by the kernel.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveProgramHelper(logger *slog.Logger, pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	err := features.HaveProgramHelper(pt, helper)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		logging.Fatal(logger, "failed to probe helper",
			logfields.Error, err,
			logfields.ProgType, pt,
			logfields.Helper, helper,
		)
	}
	return nil
}

// HaveLargeInstructionLimit is a wrapper around features.HaveLargeInstructions()
// to check if the kernel supports the 1 Million instruction limit.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveLargeInstructionLimit(logger *slog.Logger) error {
	err := features.HaveLargeInstructions()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		logging.Fatal(logger, "failed to probe large instruction limit", logfields.Error, err)
	}
	return nil
}

// HaveBoundedLoops is a wrapper around features.HaveBoundedLoops()
// to check if the kernel supports bounded loops in BPF programs.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveBoundedLoops(logger *slog.Logger) error {
	err := features.HaveBoundedLoops()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		logging.Fatal(logger, "failed to probe bounded loops", logfields.Error, err)
	}
	return nil
}

// HaveWriteableQueueMapping checks if kernel has 74e31ca850c1 ("bpf: add
// skb->queue_mapping write access from tc clsact") which is 5.1+. This got merged
// in the same kernel as the bpf_skb_ecn_set_ce() helper.
func HaveWriteableQueueMapping() error {
	return features.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbEcnSetCe)
}

// HaveV2ISA is a wrapper around features.HaveV2ISA() to check if the kernel
// supports the V2 ISA.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveV2ISA(logger *slog.Logger) error {
	err := features.HaveV2ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		logging.Fatal(logger, "failed to probe V2 ISA", logfields.Error, err)
	}
	return nil
}

// HaveV3ISA is a wrapper around features.HaveV3ISA() to check if the kernel
// supports the V3 ISA.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveV3ISA(logger *slog.Logger) error {
	err := features.HaveV3ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		logging.Fatal(logger, "failed to probe V3 ISA", logfields.Error, err)
	}
	return nil
}

func newProgram(progType ebpf.ProgramType) (*ebpf.Program, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: progType,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		return nil, fmt.Errorf("loading bpf program: %w: %w", err, ErrNotSupported)
	}
	return prog, nil
}

// HaveBPF returns nil if the running kernel supports loading BPF programs.
var HaveBPF = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SocketFilter)
	if err != nil {
		return err
	}
	defer prog.Close()

	return nil
})

// HaveBPFJIT returns nil if the running kernel features a BPF JIT and if it is
// enabled in the kernel configuration.
var HaveBPFJIT = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SocketFilter)
	if err != nil {
		return err
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("get prog info: %w", err)
	}
	if _, err := info.JitedSize(); err != nil {
		return fmt.Errorf("get JITed prog size: %w", err)
	}

	return nil
})

// HaveTCBPF returns nil if the running kernel supports attaching a bpf filter
// to a clsact qdisc.
var HaveTCBPF = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: 1, // lo
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: 1, // lo
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		DirectAction: true,
	}

	return ns.Do(func() error {
		if err := netlink.QdiscReplace(qdisc); err != nil {
			return fmt.Errorf("creating clsact qdisc: %w: %w", err, ErrNotSupported)
		}

		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("attaching bpf tc filter: %w: %w", err, ErrNotSupported)
		}

		return nil
	})
})

// HaveTCX returns nil if the running kernel supports attaching bpf programs to
// tcx hooks.
var HaveTCX = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	// link.AttachTCX already performs its own feature detection and returns
	// ebpf.ErrNotSupported if the host kernel doesn't have tcx.
	return ns.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
			Interface: 1, // lo
			Anchor:    link.Tail(),
		})
		if err != nil {
			return fmt.Errorf("creating link: %w", err)
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing link: %w", err)
		}

		return nil
	})
})

// HaveNetkit returns nil if the running kernel supports attaching bpf programs
// to netkit devices.
var HaveNetkit = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	return ns.Do(func() error {
		l, err := link.AttachNetkit(link.NetkitOptions{
			Program:   prog,
			Attach:    ebpf.AttachNetkitPrimary,
			Interface: math.MaxInt,
		})
		// We rely on this being checked during the syscall. With
		// an otherwise correct payload we expect ENODEV here as
		// an indication that the feature is present.
		if errors.Is(err, unix.ENODEV) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("creating link: %w", err)
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing link: %w", err)
		}

		return fmt.Errorf("unexpected success: %w", err)
	})
})

// HaveSKBAdjustRoomL2RoomMACSupport tests whether the kernel supports the `bpf_skb_adjust_room` helper
// with the `BPF_ADJ_ROOM_MAC` mode. To do so, we create a program that requests the passed in SKB
// to be expanded by 20 bytes. The helper checks the `mode` argument and will return -ENOSUPP if
// the mode is unknown. Otherwise it should resize the SKB by 20 bytes and return 0.
func HaveSKBAdjustRoomL2RoomMACSupport(logger *slog.Logger) (err error) {
	defer func() {
		if err != nil && !errors.Is(err, ebpf.ErrNotSupported) {
			logging.Fatal(logger, "failed to probe for bpf_skb_adjust_room L2 room MAC support", logfields.Error, err)
		}
	}()

	progSpec := &ebpf.ProgramSpec{
		Name:    "adjust_mac_room",
		Type:    ebpf.SchedCLS,
		License: "GPL",
	}
	progSpec.Instructions = asm.Instructions{
		asm.Mov.Imm(asm.R2, 20), // len_diff
		asm.Mov.Imm(asm.R3, 1),  // mode: BPF_ADJ_ROOM_MAC
		asm.Mov.Imm(asm.R4, 0),  // flags: 0
		asm.FnSkbAdjustRoom.Call(),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return err
	}
	defer prog.Close()

	// This is a Eth + IPv4 + UDP + data packet. The helper relies on a valid packet being passed in
	// since it wants to know offsets of the different layers.
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
		&layers.Ethernet{
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			SrcMAC:       net.HardwareAddr{0x0e, 0xf5, 0x16, 0x3d, 0x6b, 0xab},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Length:   49,
			Id:       0xCECB,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(0xc0, 0xa8, 0xb2, 0x56),
			DstIP:    net.IPv4(0xc0, 0xa8, 0xb2, 0xff),
		},
		&layers.UDP{
			SrcPort: 23939,
			DstPort: 32412,
		},
		gopacket.Payload("M-SEARCH * HTTP/1.1\x0d\x0a"),
	)
	if err != nil {
		return fmt.Errorf("craft packet: %w", err)
	}

	ret, _, err := prog.Test(buf.Bytes())
	if err != nil {
		return err
	}
	if ret != 0 {
		return ebpf.ErrNotSupported
	}
	return nil
}

// HaveDeadCodeElim tests whether the kernel supports dead code elimination.
func HaveDeadCodeElim() error {
	spec := ebpf.ProgramSpec{
		Name: "test",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R1, 0),
			asm.JEq.Imm(asm.R1, 1, "else"),
			asm.Mov.Imm(asm.R0, 2),
			asm.Ja.Label("end"),
			asm.Mov.Imm(asm.R0, 3).WithSymbol("else"),
			asm.Return().WithSymbol("end"),
		},
	}

	prog, err := ebpf.NewProgram(&spec)
	if err != nil {
		return fmt.Errorf("loading program: %w", err)
	}

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("get prog info: %w", err)
	}
	infoInst, err := info.Instructions()
	if err != nil {
		return fmt.Errorf("get instructions: %w", err)
	}

	for _, inst := range infoInst {
		if inst.OpCode.Class().IsJump() && inst.OpCode.JumpOp() != asm.Exit {
			return fmt.Errorf("Jump instruction found in the final program, no dead code elimination performed")
		}
	}

	return nil
}

// HaveIPv6Support tests whether kernel can open an IPv6 socket. This will
// also implicitly auto-load IPv6 kernel module if available and not yet
// loaded.
func HaveIPv6Support() error {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
		return ErrNotSupported
	}
	unix.Close(fd)
	return nil
}

// CreateHeaderFiles creates C header files with macros indicating which BPF
// features are available in the kernel.
func CreateHeaderFiles(headerDir string, probes *FeatureProbes) error {
	common, err := os.Create(filepath.Join(headerDir, "features.h"))
	if err != nil {
		return fmt.Errorf("could not create common features header file: %w", err)
	}
	defer common.Close()
	if err := writeCommonHeader(common, probes); err != nil {
		return fmt.Errorf("could not write common features header file: %w", err)
	}

	skb, err := os.Create(filepath.Join(headerDir, "features_skb.h"))
	if err != nil {
		return fmt.Errorf("could not create skb related features header file: %w", err)
	}
	defer skb.Close()
	if err := writeSkbHeader(skb, probes); err != nil {
		return fmt.Errorf("could not write skb related features header file: %w", err)
	}

	xdp, err := os.Create(filepath.Join(headerDir, "features_xdp.h"))
	if err != nil {
		return fmt.Errorf("could not create xdp related features header file: %w", err)
	}
	defer xdp.Close()
	if err := writeXdpHeader(xdp, probes); err != nil {
		return fmt.Errorf("could not write xdp related features header file: %w", err)
	}

	return nil
}

// ExecuteHeaderProbes probes the kernel for a specific set of BPF features
// which are currently used to generate various feature macros for the datapath.
// The probe results returned in FeatureProbes are then used in the respective
// function that writes the actual C macro definitions.
// Further needed probes should be added here, while new macro strings need to
// be added in the correct `write*Header()` function.
func ExecuteHeaderProbes(logger *slog.Logger) *FeatureProbes {
	probes := FeatureProbes{
		ProgramHelpers: make(map[ProgramHelper]bool),
	}

	progHelpers := []ProgramHelper{
		// common probes
		{ebpf.CGroupSock, asm.FnSetRetval},

		// xdp related probes
		{ebpf.XDP, asm.FnXdpGetBuffLen},
		{ebpf.XDP, asm.FnXdpLoadBytes},
		{ebpf.XDP, asm.FnXdpStoreBytes},
	}
	for _, ph := range progHelpers {
		probes.ProgramHelpers[ph] = (HaveProgramHelper(logger, ph.Program, ph.Helper) == nil)
	}

	return &probes
}

// writeCommonHeader defines macross for bpf/include/bpf/features.h
func writeCommonHeader(writer io.Writer, probes *FeatureProbes) error {
	features := map[string]bool{
		"HAVE_SET_RETVAL": probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSock, asm.FnSetRetval}],
	}

	return writeFeatureHeader(writer, features, true)
}

// writeSkbHeader defines macros for bpf/include/bpf/features_skb.h
func writeSkbHeader(writer io.Writer, probes *FeatureProbes) error {
	featuresSkb := map[string]bool{}

	return writeFeatureHeader(writer, featuresSkb, false)
}

// writeXdpHeader defines macros for bpf/include/bpf/features_xdp.h
func writeXdpHeader(writer io.Writer, probes *FeatureProbes) error {
	featuresXdp := map[string]bool{
		"HAVE_XDP_GET_BUFF_LEN": probes.ProgramHelpers[ProgramHelper{ebpf.XDP, asm.FnXdpGetBuffLen}],
		"HAVE_XDP_LOAD_BYTES":   probes.ProgramHelpers[ProgramHelper{ebpf.XDP, asm.FnXdpLoadBytes}],
		"HAVE_XDP_STORE_BYTES":  probes.ProgramHelpers[ProgramHelper{ebpf.XDP, asm.FnXdpStoreBytes}],
	}

	return writeFeatureHeader(writer, featuresXdp, false)
}

func writeFeatureHeader(writer io.Writer, features map[string]bool, common bool) error {
	input := struct {
		Common   bool
		Features map[string]bool
	}{
		Common:   common,
		Features: features,
	}

	if err := tpl.Execute(writer, input); err != nil {
		return fmt.Errorf("could not write template: %w", err)
	}

	return nil
}

// HaveBatchAPI checks if kernel supports batched bpf map lookup API.
func HaveBatchAPI() error {
	spec := ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    1,
		ValueSize:  1,
		MaxEntries: 2,
	}
	m, err := ebpf.NewMapWithOptions(&spec, ebpf.MapOptions{})
	if err != nil {
		return ErrNotSupported
	}
	defer m.Close()
	var cursor ebpf.MapBatchCursor
	_, err = m.BatchLookup(&cursor, []byte{0}, []byte{0}, nil) // only do one batched lookup
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return ErrNotSupported
		}
		return nil
	}
	return nil
}
