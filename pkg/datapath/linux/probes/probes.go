// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
	once         sync.Once
	probeManager *ProbeManager
	tpl          = template.New("headerfile")
)

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
		log.WithError(err).Fatal("could not parse headerfile template")
	}
}

// ErrNotSupported indicates that a feature is not supported by the current kernel.
var ErrNotSupported = errors.New("not supported")

// KernelParam is a type based on string which represents CONFIG_* kernel
// parameters which usually have values "y", "n" or "m".
type KernelParam string

// Enabled checks whether the kernel parameter is enabled.
func (kp KernelParam) Enabled() bool {
	return kp == "y"
}

// Module checks whether the kernel parameter is enabled as a module.
func (kp KernelParam) Module() bool {
	return kp == "m"
}

// kernelOption holds information about kernel parameters to probe.
type kernelOption struct {
	Description string
	Enabled     bool
	CanBeModule bool
}

type ProgramHelper struct {
	Program ebpf.ProgramType
	Helper  asm.BuiltinFunc
}

type miscFeatures struct {
	HaveFibIfindex bool
}

type FeatureProbes struct {
	ProgramHelpers map[ProgramHelper]bool
	Misc           miscFeatures
}

// SystemConfig contains kernel configuration and sysctl parameters related to
// BPF functionality.
type SystemConfig struct {
	UnprivilegedBpfDisabled      int         `json:"unprivileged_bpf_disabled"`
	BpfJitEnable                 int         `json:"bpf_jit_enable"`
	BpfJitHarden                 int         `json:"bpf_jit_harden"`
	BpfJitKallsyms               int         `json:"bpf_jit_kallsyms"`
	BpfJitLimit                  int         `json:"bpf_jit_limit"`
	ConfigBpf                    KernelParam `json:"CONFIG_BPF"`
	ConfigBpfSyscall             KernelParam `json:"CONFIG_BPF_SYSCALL"`
	ConfigHaveEbpfJit            KernelParam `json:"CONFIG_HAVE_EBPF_JIT"`
	ConfigBpfJit                 KernelParam `json:"CONFIG_BPF_JIT"`
	ConfigBpfJitAlwaysOn         KernelParam `json:"CONFIG_BPF_JIT_ALWAYS_ON"`
	ConfigCgroups                KernelParam `json:"CONFIG_CGROUPS"`
	ConfigCgroupBpf              KernelParam `json:"CONFIG_CGROUP_BPF"`
	ConfigCgroupNetClassID       KernelParam `json:"CONFIG_CGROUP_NET_CLASSID"`
	ConfigSockCgroupData         KernelParam `json:"CONFIG_SOCK_CGROUP_DATA"`
	ConfigBpfEvents              KernelParam `json:"CONFIG_BPF_EVENTS"`
	ConfigKprobeEvents           KernelParam `json:"CONFIG_KPROBE_EVENTS"`
	ConfigUprobeEvents           KernelParam `json:"CONFIG_UPROBE_EVENTS"`
	ConfigTracing                KernelParam `json:"CONFIG_TRACING"`
	ConfigFtraceSyscalls         KernelParam `json:"CONFIG_FTRACE_SYSCALLS"`
	ConfigFunctionErrorInjection KernelParam `json:"CONFIG_FUNCTION_ERROR_INJECTION"`
	ConfigBpfKprobeOverride      KernelParam `json:"CONFIG_BPF_KPROBE_OVERRIDE"`
	ConfigNet                    KernelParam `json:"CONFIG_NET"`
	ConfigXdpSockets             KernelParam `json:"CONFIG_XDP_SOCKETS"`
	ConfigLwtunnelBpf            KernelParam `json:"CONFIG_LWTUNNEL_BPF"`
	ConfigNetActBpf              KernelParam `json:"CONFIG_NET_ACT_BPF"`
	ConfigNetClsBpf              KernelParam `json:"CONFIG_NET_CLS_BPF"`
	ConfigNetClsAct              KernelParam `json:"CONFIG_NET_CLS_ACT"`
	ConfigNetSchIngress          KernelParam `json:"CONFIG_NET_SCH_INGRESS"`
	ConfigXfrm                   KernelParam `json:"CONFIG_XFRM"`
	ConfigIPRouteClassID         KernelParam `json:"CONFIG_IP_ROUTE_CLASSID"`
	ConfigIPv6Seg6Bpf            KernelParam `json:"CONFIG_IPV6_SEG6_BPF"`
	ConfigBpfLircMode2           KernelParam `json:"CONFIG_BPF_LIRC_MODE2"`
	ConfigBpfStreamParser        KernelParam `json:"CONFIG_BPF_STREAM_PARSER"`
	ConfigNetfilterXtMatchBpf    KernelParam `json:"CONFIG_NETFILTER_XT_MATCH_BPF"`
	ConfigBpfilter               KernelParam `json:"CONFIG_BPFILTER"`
	ConfigBpfilterUmh            KernelParam `json:"CONFIG_BPFILTER_UMH"`
	ConfigTestBpf                KernelParam `json:"CONFIG_TEST_BPF"`
	ConfigKernelHz               KernelParam `json:"CONFIG_HZ"`
}

// MapTypes contains bools indicating which types of BPF maps the currently
// running kernel supports.
type MapTypes struct {
	HaveHashMapType                bool `json:"have_hash_map_type"`
	HaveArrayMapType               bool `json:"have_array_map_type"`
	HaveProgArrayMapType           bool `json:"have_prog_array_map_type"`
	HavePerfEventArrayMapType      bool `json:"have_perf_event_array_map_type"`
	HavePercpuHashMapType          bool `json:"have_percpu_hash_map_type"`
	HavePercpuArrayMapType         bool `json:"have_percpu_array_map_type"`
	HaveStackTraceMapType          bool `json:"have_stack_trace_map_type"`
	HaveCgroupArrayMapType         bool `json:"have_cgroup_array_map_type"`
	HaveLruHashMapType             bool `json:"have_lru_hash_map_type"`
	HaveLruPercpuHashMapType       bool `json:"have_lru_percpu_hash_map_type"`
	HaveLpmTrieMapType             bool `json:"have_lpm_trie_map_type"`
	HaveArrayOfMapsMapType         bool `json:"have_array_of_maps_map_type"`
	HaveHashOfMapsMapType          bool `json:"have_hash_of_maps_map_type"`
	HaveDevmapMapType              bool `json:"have_devmap_map_type"`
	HaveSockmapMapType             bool `json:"have_sockmap_map_type"`
	HaveCpumapMapType              bool `json:"have_cpumap_map_type"`
	HaveXskmapMapType              bool `json:"have_xskmap_map_type"`
	HaveSockhashMapType            bool `json:"have_sockhash_map_type"`
	HaveCgroupStorageMapType       bool `json:"have_cgroup_storage_map_type"`
	HaveReuseportSockarrayMapType  bool `json:"have_reuseport_sockarray_map_type"`
	HavePercpuCgroupStorageMapType bool `json:"have_percpu_cgroup_storage_map_type"`
	HaveQueueMapType               bool `json:"have_queue_map_type"`
	HaveStackMapType               bool `json:"have_stack_map_type"`
}

// Features contains BPF feature checks returned by bpftool.
type Features struct {
	SystemConfig `json:"system_config"`
	MapTypes     `json:"map_types"`
}

// ProbeManager is a manager of BPF feature checks.
type ProbeManager struct {
	features Features
}

// NewProbeManager returns a new instance of ProbeManager - a manager of BPF
// feature checks.
func NewProbeManager() *ProbeManager {
	newProbeManager := func() {
		probeManager = &ProbeManager{}
		probeManager.features = probeManager.Probe()
	}
	once.Do(newProbeManager)
	return probeManager
}

// Probe probes the underlying kernel for features.
func (*ProbeManager) Probe() Features {
	var features Features
	out, err := exec.WithTimeout(
		defaults.ExecTimeout,
		"bpftool", "-j", "feature", "probe",
	).CombinedOutput(log, true)
	if err != nil {
		log.WithError(err).Fatal("could not run bpftool")
	}
	if err := json.Unmarshal(out, &features); err != nil {
		log.WithError(err).Fatal("could not parse bpftool output")
	}
	return features
}

// SystemConfigProbes performs a check of kernel configuration parameters. It
// returns an error when parameters required by Cilium are not enabled. It logs
// warnings when optional parameters are not enabled.
//
// When kernel config file is not found, bpftool can't probe kernel configuration
// parameter real setting, so only return error log when kernel config file exists
// and kernel configuration parameter setting is disabled
func (p *ProbeManager) SystemConfigProbes() error {
	var notFound bool
	if !p.KernelConfigAvailable() {
		notFound = true
		log.Info("Kernel config file not found: if the agent fails to start, check the system requirements at https://docs.cilium.io/en/stable/operations/system_requirements")
	}
	requiredParams := p.GetRequiredConfig()
	for param, kernelOption := range requiredParams {
		if !kernelOption.Enabled && !notFound {
			module := ""
			if kernelOption.CanBeModule {
				module = " or module"
			}
			return fmt.Errorf("%s kernel parameter%s is required (needed for: %s)", param, module, kernelOption.Description)
		}
	}
	optionalParams := p.GetOptionalConfig()
	for param, kernelOption := range optionalParams {
		if !kernelOption.Enabled && !notFound {
			module := ""
			if kernelOption.CanBeModule {
				module = " or module"
			}
			log.Warningf("%s optional kernel parameter%s is not in kernel (needed for: %s)", param, module, kernelOption.Description)
		}
	}
	return nil
}

// GetRequiredConfig performs a check of mandatory kernel configuration options. It
// returns a map indicating which required kernel parameters are enabled - and which are not.
// GetRequiredConfig is being used by CLI "cilium kernel-check".
func (p *ProbeManager) GetRequiredConfig() map[KernelParam]kernelOption {
	config := p.features.SystemConfig
	coreInfraDescription := "Essential eBPF infrastructure"
	kernelParams := make(map[KernelParam]kernelOption)

	kernelParams["CONFIG_BPF"] = kernelOption{
		Enabled:     config.ConfigBpf.Enabled(),
		Description: coreInfraDescription,
		CanBeModule: false,
	}
	kernelParams["CONFIG_BPF_SYSCALL"] = kernelOption{
		Enabled:     config.ConfigBpfSyscall.Enabled(),
		Description: coreInfraDescription,
		CanBeModule: false,
	}
	kernelParams["CONFIG_NET_SCH_INGRESS"] = kernelOption{
		Enabled:     config.ConfigNetSchIngress.Enabled() || config.ConfigNetSchIngress.Module(),
		Description: coreInfraDescription,
		CanBeModule: true,
	}
	kernelParams["CONFIG_NET_CLS_BPF"] = kernelOption{
		Enabled:     config.ConfigNetClsBpf.Enabled() || config.ConfigNetClsBpf.Module(),
		Description: coreInfraDescription,
		CanBeModule: true,
	}
	kernelParams["CONFIG_NET_CLS_ACT"] = kernelOption{
		Enabled:     config.ConfigNetClsAct.Enabled(),
		Description: coreInfraDescription,
		CanBeModule: false,
	}
	kernelParams["CONFIG_BPF_JIT"] = kernelOption{
		Enabled:     config.ConfigBpfJit.Enabled(),
		Description: coreInfraDescription,
		CanBeModule: false,
	}
	kernelParams["CONFIG_HAVE_EBPF_JIT"] = kernelOption{
		Enabled:     config.ConfigHaveEbpfJit.Enabled(),
		Description: coreInfraDescription,
		CanBeModule: false,
	}

	return kernelParams
}

// GetOptionalConfig performs a check of *optional* kernel configuration options. It
// returns a map indicating which optional/non-mandatory kernel parameters are enabled.
// GetOptionalConfig is being used by CLI "cilium kernel-check".
func (p *ProbeManager) GetOptionalConfig() map[KernelParam]kernelOption {
	config := p.features.SystemConfig
	kernelParams := make(map[KernelParam]kernelOption)

	kernelParams["CONFIG_CGROUP_BPF"] = kernelOption{
		Enabled:     config.ConfigCgroupBpf.Enabled(),
		Description: "Host Reachable Services and Sockmap optimization",
		CanBeModule: false,
	}
	kernelParams["CONFIG_LWTUNNEL_BPF"] = kernelOption{
		Enabled:     config.ConfigLwtunnelBpf.Enabled(),
		Description: "Lightweight Tunnel hook for IP-in-IP encapsulation",
		CanBeModule: false,
	}
	kernelParams["CONFIG_BPF_EVENTS"] = kernelOption{
		Enabled:     config.ConfigBpfEvents.Enabled(),
		Description: "Visibility and congestion management with datapath",
		CanBeModule: false,
	}

	return kernelParams
}

// KernelConfigAvailable checks if the Kernel Config is available on the
// system or not.
func (p *ProbeManager) KernelConfigAvailable() bool {
	// Check Kernel Config is available or not.
	// We are replicating BPFTools logic here to check if kernel config is available
	// https://elixir.bootlin.com/linux/v5.7/source/tools/bpf/bpftool/feature.c#L390
	info := unix.Utsname{}
	err := unix.Uname(&info)
	if err != nil {
		return false
	}
	release := strings.TrimSpace(string(bytes.Trim(info.Release[:], "\x00")))

	// Any error checking these files will return Kernel config not found error
	if _, err := os.Stat(fmt.Sprintf("/boot/config-%s", release)); err != nil {
		if _, err = os.Stat("/proc/config.gz"); err != nil {
			return false
		}
	}

	return true
}

// HaveProgramHelper is a wrapper around features.HaveProgramHelper() to
// check if a certain BPF program/helper copmbination is supported by the kernel.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveProgramHelper(pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	err := features.HaveProgramHelper(pt, helper)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).WithField("programtype", pt).WithField("helper", helper).Fatal("failed to probe helper")
	}
	return nil
}

// HaveLargeInstructionLimit is a wrapper around features.HaveLargeInstructions()
// to check if the kernel supports the 1 Million instruction limit.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveLargeInstructionLimit() error {
	err := features.HaveLargeInstructions()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe large instruction limit")
	}
	return nil
}

// HaveBoundedLoops is a wrapper around features.HaveBoundedLoops()
// to check if the kernel supports bounded loops in BPF programs.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveBoundedLoops() error {
	err := features.HaveBoundedLoops()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe bounded loops")
	}
	return nil
}

// HaveFibIfindex checks if kernel has d1c362e1dd68 ("bpf: Always return target
// ifindex in bpf_fib_lookup") which is 5.10+. This got merged in the same kernel
// as the new redirect helpers.
func HaveFibIfindex() error {
	return features.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectPeer)
}

// HaveV2ISA is a wrapper around features.HaveV2ISA() to check if the kernel
// supports the V2 ISA.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveV2ISA() error {
	err := features.HaveV2ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe V2 ISA")
	}
	return nil
}

// HaveV3ISA is a wrapper around features.HaveV3ISA() to check if the kernel
// supports the V3 ISA.
// On unexpected probe results this function will terminate with log.Fatal().
func HaveV3ISA() error {
	err := features.HaveV3ISA()
	if errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}
	if err != nil {
		log.WithError(err).Fatal("failed to probe V3 ISA")
	}
	return nil
}

// HaveTCX returns nil if the running kernel supports attaching bpf programs to
// tcx hooks.
var HaveTCX = sync.OnceValue(func() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
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

// HaveOuterSourceIPSupport tests whether the kernel support setting the outer
// source IP address via the bpf_skb_set_tunnel_key BPF helper. We can't rely
// on the verifier to reject a program using the new support because the
// verifier just accepts any argument size for that helper; non-supported
// fields will simply not be used. Instead, we set the outer source IP and
// retrieve it with bpf_skb_get_tunnel_key right after. If the retrieved value
// equals the value set, we have a confirmation the kernel supports it.
func HaveOuterSourceIPSupport() (err error) {
	defer func() {
		if err != nil && !errors.Is(err, ebpf.ErrNotSupported) {
			log.WithError(err).Fatal("failed to probe for outer source IP support")
		}
	}()

	progSpec := &ebpf.ProgramSpec{
		Name:    "set_tunnel_key_probe",
		Type:    ebpf.SchedACT,
		License: "GPL",
	}
	progSpec.Instructions = asm.Instructions{
		asm.Mov.Reg(asm.R8, asm.R1),

		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -32, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -40, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R2, 42),
		asm.StoreMem(asm.RFP, -44, asm.R2, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.Mov.Imm(asm.R3, 44), // sizeof(struct bpf_tunnel_key) when setting the outer source IP is supported.
		asm.Mov.Imm(asm.R4, 0),
		asm.FnSkbSetTunnelKey.Call(),

		asm.Mov.Reg(asm.R1, asm.R8),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.Mov.Imm(asm.R3, 44),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnSkbGetTunnelKey.Call(),

		asm.LoadMem(asm.R0, asm.RFP, -44, asm.Word),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		return err
	}
	defer prog.Close()

	pkt := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ret, _, err := prog.Test(pkt)
	if err != nil {
		return err
	}
	if ret != 42 {
		return ebpf.ErrNotSupported
	}
	return nil
}

// HaveSKBAdjustRoomL2RoomMACSupport tests whether the kernel supports the `bpf_skb_adjust_room` helper
// with the `BPF_ADJ_ROOM_MAC` mode. To do so, we create a program that requests the passed in SKB
// to be expanded by 20 bytes. The helper checks the `mode` argument and will return -ENOSUPP if
// the mode is unknown. Otherwise it should resize the SKB by 20 bytes and return 0.
func HaveSKBAdjustRoomL2RoomMACSupport() (err error) {
	defer func() {
		if err != nil && !errors.Is(err, ebpf.ErrNotSupported) {
			log.WithError(err).Fatal("failed to probe for bpf_skb_adjust_room L2 room MAC support")
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
func ExecuteHeaderProbes() *FeatureProbes {
	probes := FeatureProbes{
		ProgramHelpers: make(map[ProgramHelper]bool),
		Misc:           miscFeatures{},
	}

	progHelpers := []ProgramHelper{
		// common probes
		{ebpf.CGroupSock, asm.FnGetNetnsCookie},
		{ebpf.CGroupSockAddr, asm.FnGetNetnsCookie},
		{ebpf.CGroupSockAddr, asm.FnGetSocketCookie},
		{ebpf.CGroupSock, asm.FnJiffies64},
		{ebpf.CGroupSockAddr, asm.FnJiffies64},
		{ebpf.SchedCLS, asm.FnJiffies64},
		{ebpf.XDP, asm.FnJiffies64},
		{ebpf.CGroupSockAddr, asm.FnSkLookupTcp},
		{ebpf.CGroupSockAddr, asm.FnSkLookupUdp},
		{ebpf.CGroupSockAddr, asm.FnGetCurrentCgroupId},
		{ebpf.CGroupSock, asm.FnSetRetval},
		{ebpf.SchedCLS, asm.FnRedirectNeigh},
		{ebpf.SchedCLS, asm.FnRedirectPeer},

		// skb related probes
		{ebpf.SchedCLS, asm.FnSkbChangeTail},
		{ebpf.SchedCLS, asm.FnCsumLevel},

		// xdp related probes
		{ebpf.XDP, asm.FnXdpGetBuffLen},
		{ebpf.XDP, asm.FnXdpLoadBytes},
		{ebpf.XDP, asm.FnXdpStoreBytes},
	}
	for _, ph := range progHelpers {
		probes.ProgramHelpers[ph] = (HaveProgramHelper(ph.Program, ph.Helper) == nil)
	}

	probes.Misc.HaveFibIfindex = (HaveFibIfindex() == nil)

	return &probes
}

// writeCommonHeader defines macross for bpf/include/bpf/features.h
func writeCommonHeader(writer io.Writer, probes *FeatureProbes) error {
	features := map[string]bool{
		"HAVE_NETNS_COOKIE": probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSock, asm.FnGetNetnsCookie}] &&
			probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSockAddr, asm.FnGetNetnsCookie}],
		"HAVE_SOCKET_COOKIE": probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSockAddr, asm.FnGetSocketCookie}],
		"HAVE_JIFFIES": probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSock, asm.FnJiffies64}] &&
			probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSockAddr, asm.FnJiffies64}] &&
			probes.ProgramHelpers[ProgramHelper{ebpf.SchedCLS, asm.FnJiffies64}] &&
			probes.ProgramHelpers[ProgramHelper{ebpf.XDP, asm.FnJiffies64}],
		"HAVE_CGROUP_ID":   probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSockAddr, asm.FnGetCurrentCgroupId}],
		"HAVE_SET_RETVAL":  probes.ProgramHelpers[ProgramHelper{ebpf.CGroupSock, asm.FnSetRetval}],
		"HAVE_FIB_NEIGH":   probes.ProgramHelpers[ProgramHelper{ebpf.SchedCLS, asm.FnRedirectNeigh}],
		"HAVE_FIB_IFINDEX": probes.Misc.HaveFibIfindex,
	}

	return writeFeatureHeader(writer, features, true)
}

// writeSkbHeader defines macros for bpf/include/bpf/features_skb.h
func writeSkbHeader(writer io.Writer, probes *FeatureProbes) error {
	featuresSkb := map[string]bool{
		"HAVE_CSUM_LEVEL": probes.ProgramHelpers[ProgramHelper{ebpf.SchedCLS, asm.FnCsumLevel}],
	}

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
