// Copyright 2019-2021 Authors of Cilium
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

package probes

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"golang.org/x/sys/unix"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
	once         sync.Once
	probeManager *ProbeManager
)

// ErrKernelConfigNotFound is the error returned if the kernel config is unavailable
// to the cilium agent.
var ErrKernelConfigNotFound = errors.New("Kernel Config file not found")

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

// Kernel misc configurations kernel large 1M instructions support
type Misc struct {
	HaveLargeInsnLimit bool `json:"have_large_insn_limit"`
}

// Features contains BPF feature checks returned by bpftool.
type Features struct {
	SystemConfig `json:"system_config"`
	MapTypes     `json:"map_types"`
	Helpers      map[string][]string `json:"helpers"`
	Misc         `json:"misc"`
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

func (p *ProbeManager) probeSystemKernelHz() (int, error) {
	out, err := exec.WithTimeout(
		defaults.ExecTimeout,
		"cilium-probe-kernel-hz",
	).Output(log, false)
	if err != nil {
		return 0, fmt.Errorf("Cannot probe CONFIG_HZ")
	}
	hz := 0
	warp := 0
	n, _ := fmt.Sscanf(string(out), "%d, %d\n", &hz, &warp)
	if n == 2 && hz > 0 && hz < 100000 {
		return hz, nil
	}
	return 0, fmt.Errorf("Invalid probed CONFIG_HZ value")
}

// SystemKernelHz returns the HZ value that the kernel has been configured with.
func (p *ProbeManager) SystemKernelHz() (int, error) {
	config := p.features.SystemConfig
	if config.ConfigKernelHz == "" {
		return p.probeSystemKernelHz()
	}
	hz, err := strconv.Atoi(string(config.ConfigKernelHz))
	if err != nil {
		return 0, err
	}
	if hz > 0 && hz < 100000 {
		return hz, nil
	}
	return 0, fmt.Errorf("Invalid CONFIG_HZ value")
}

// SystemConfigProbes performs a check of kernel configuration parameters. It
// returns an error when parameters required by Cilium are not enabled. It logs
// warnings when optional parameters are not enabled.
func (p *ProbeManager) SystemConfigProbes() error {
	if !p.KernelConfigAvailable() {
		return ErrKernelConfigNotFound
	}
	requiredParams := p.GetRequiredConfig()
	for param, kernelOption := range requiredParams {
		if !kernelOption.Enabled {
			module := ""
			if kernelOption.CanBeModule {
				module = " or module"
			}
			return fmt.Errorf("%s kernel parameter%s is required (needed for: %s)", param, module, kernelOption.Description)
		}
	}
	optionalParams := p.GetOptionalConfig()
	for param, kernelOption := range optionalParams {
		if !kernelOption.Enabled {
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

// GetMapTypes returns information about supported BPF map types.
func (p *ProbeManager) GetMapTypes() *MapTypes {
	return &p.features.MapTypes
}

// GetMisc returns information about kernel misc.
func (p *ProbeManager) GetMisc() Misc {
	return p.features.Misc
}

// GetHelpers returns information about available BPF helpers for the given
// program type.
// If program type is not found, returns nil.
func (p *ProbeManager) GetHelpers(prog string) map[string]struct{} {
	for p, helpers := range p.features.Helpers {
		if prog+"_available_helpers" == p {
			ret := map[string]struct{}{}
			for _, h := range helpers {
				ret[h] = struct{}{}
			}
			return ret
		}
	}
	return nil
}

// writeHeaders executes bpftool to generate BPF feature C macros and then
// writes them to the given writer.
func (p *ProbeManager) writeHeaders(featuresFile io.Writer) error {
	cmd := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "feature", "probe", "macros")
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf(
			"could not initialize stdout pipe for bpftool feature probe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf(
			"could not initialize stderr pipe for bpftool feature probe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf(
			"could not start bpftool for bpftool feature probe: %w", err)
	}

	writer := bufio.NewWriter(featuresFile)
	defer writer.Flush()

	io.WriteString(writer, "#ifndef BPF_FEATURES_H_\n")
	io.WriteString(writer, "#define BPF_FEATURES_H_\n\n")

	io.Copy(writer, stdoutPipe)
	if err := cmd.Wait(); err != nil {
		stderr, err := io.ReadAll(stderrPipe)
		if err != nil {
			return fmt.Errorf(
				"reading from bpftool feature probe stderr pipe failed: %w", err)
		}
		return fmt.Errorf(
			"bpftool feature probe did not run successfully: %s (%w)", stderr, err)
	}

	io.WriteString(writer, "#endif /* BPF_FEATURES_H_ */\n")

	return nil
}

// CreateHeadersFile creates a C header file with macros indicating which BPF
// features are available in the kernel.
func (p *ProbeManager) CreateHeadersFile() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		return fmt.Errorf("could not create runtime directory %s: %w", globalsDir, err)
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	featuresFile, err := os.Create(featuresFilePath)
	if err != nil {
		return fmt.Errorf(
			"could not create features header file %s: %w", featuresFilePath, err)
	}
	defer featuresFile.Close()

	if err := p.writeHeaders(featuresFile); err != nil {
		return err
	}
	return nil
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
