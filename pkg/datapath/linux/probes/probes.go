// Copyright 2019 Authors of Cilium
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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
	once         sync.Once
	probeManager *ProbeManager
)

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
	Helpers      map[string][]string `json:"helpers"`
}

// ProbeManager is a manager of BPF feature checks.
type ProbeManager struct {
	features Features
}

// NewProbeManager returns a new instance of ProbeManager - a manager of BPF
// feature checks.
func NewProbeManager() *ProbeManager {
	newProbeManager := func() {
		var features Features
		out, err := exec.WithTimeout(
			defaults.ExecTimeout, "bpftool", "-j", "feature").CombinedOutput(
			log, true)
		if err != nil {
			log.WithError(err).Fatal("could not run bpftool")
		}
		if err := json.Unmarshal(out, &features); err != nil {
			log.WithError(err).Fatal("could not parse bpftool output")
		}
		probeManager = &ProbeManager{features: features}
	}
	once.Do(newProbeManager)
	return probeManager
}

// SystemConfigProbes performs a check of kernel configuration parameters. It
// returns an error when parameters required by Cilium are not enabled. It logs
// warnings when optional parameters are not enabled.
func (p *ProbeManager) SystemConfigProbes() error {
	config := p.features.SystemConfig
	// Required
	if !config.ConfigBpf.Enabled() {
		return fmt.Errorf("CONFIG_BPF kernel parameter is required")
	}
	if !config.ConfigBpfSyscall.Enabled() {
		return fmt.Errorf(
			"CONFIG_BPF_SYSCALL kernel parameter is required")
	}
	if !config.ConfigNetSchIngress.Enabled() && !config.ConfigNetSchIngress.Module() {
		return fmt.Errorf(
			"CONFIG_NET_SCH_INGRESS kernel parameter (or module) is required")
	}
	if !config.ConfigNetClsBpf.Enabled() && !config.ConfigNetClsBpf.Module() {
		return fmt.Errorf(
			"CONFIG_NET_CLS_BPF kernel parameter (or module) is required")
	}
	if !config.ConfigNetClsAct.Enabled() {
		return fmt.Errorf(
			"CONFIG_NET_CLS_ACT kernel parameter is required")
	}
	if !config.ConfigBpfJit.Enabled() {
		return fmt.Errorf(
			"CONFIG_BPF_JIT kernel parameter is required")
	}
	if !config.ConfigHaveEbpfJit.Enabled() {
		return fmt.Errorf(
			"CONFIG_HAVE_EBPF_JIT kernel parameter is required")
	}
	// Optional
	if !config.ConfigCgroupBpf.Enabled() {
		log.Warning(
			"CONFIG_CGROUP_BPF optional kernel parameter is not in kernel configuration")
	}
	if !config.ConfigLwtunnelBpf.Enabled() {
		log.Warning(
			"CONFIG_LWTUNNEL_BPF optional kernel parameter is not in kernel configuration")
	}
	if !config.ConfigBpfEvents.Enabled() {
		log.Warning(
			"CONFIG_BPF_EVENTS optional kernel parameter is not in kernel configuration")
	}
	return nil
}

// GetMapTypes returns information about supported BPF map types.
func (p *ProbeManager) GetMapTypes() *MapTypes {
	return &p.features.MapTypes
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
