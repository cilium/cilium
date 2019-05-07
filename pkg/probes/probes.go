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

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
)

// Helpers represents categorized lists of available BPF helper functions.
type Helpers struct {
	CgroupDeviceAvailableHelpers   []string `json:"cgroup_device_available_helpers"`
	CgroupSkbAvailableHelpers      []string `json:"cgroup_skb_available_helpers"`
	CgroupSockAddrAvailableHelpers []string `json:"cgroup_sock_addr_available_helpers"`
	CgroupSockAvailableHelpers     []string `json:"cgroup_sock_available_helpers"`
	CgroupSysctlAvailableHelpers   []string `json:"cgroup_sysctl_available_helpers"`
	FlowDissectorAvailableHelpers  []string `json:"flow_dissector_available_helpers"`
	KprobeAvailableHelpers         []string `json:"kprobe_available_helpers"`
	LircMode2AvailableHelpers      []string `json:"lirc_mode2_available_helpers"`
	LwtInAvailableHelpers          []string `json:"lwt_in_available_helpers"`
	LwtOutAvailableHelpers         []string `json:"lwt_out_available_helpers"`
	LwtSeg6LocalAvailableHelpers   []string `json:"lwt_seg6local_available_helpers"`
	LwtXmitAvailableHelpers        []string `json:"lwt_xmit_available_helpers"`
	PerfEventAvailableHelpers      []string `json:"perf_event_available_helpers"`
	RawTracepointAvailableHelpers  []string `json:"raw_tracepoint_available_helpers"`
	SchedActAvailableHelpers       []string `json:"sched_act_available_helpers"`
	SchedClsAvailableHelpers       []string `json:"sched_cls_available_helpers"`
	SkMsgAvailableHelpers          []string `json:"sk_msg_available_helpers"`
	SkReuseportAvailableHelpers    []string `json:"sk_reuseport_available_helpers"`
	SkSkbAvailableHelpers          []string `json:"sk_skb_available_helpers"`
	SockOpsAvailableHelpers        []string `json:"sock_ops_available_helpers"`
	SocketFilterAvailableHelpers   []string `json:"socket_filter_available_helpers"`
	TracepointAvailableHelpers     []string `json:"tracepoint_available_helpers"`
	XdpAvailableHelpers            []string `json:"xdp_available_helpers"`
}

// MapTypes represents information about available types of BPF maps.
type MapTypes struct {
	HaveArrayMapType               bool `json:"have_array_map_type"`
	HaveArrayOfMapsMapType         bool `json:"have_array_of_maps_map_type"`
	HaveCgroupArrayMapType         bool `json:"have_cgroup_array_map_type"`
	HaveCgroupStorageMapType       bool `json:"have_cgroup_storage_map_type"`
	HaveCpumapMapType              bool `json:"have_cpumap_map_type"`
	HaveDevmapMapType              bool `json:"have_devmap_map_type"`
	HaveHashMapType                bool `json:"have_hash_map_type"`
	HaveHashOfMapsMapType          bool `json:"have_hash_of_maps_map_type"`
	HaveLpmTrieMapType             bool `json:"have_lpm_trie_map_type"`
	HaveLruHashMapType             bool `json:"have_lru_hash_map_type"`
	HaveLruPercpuHashMapType       bool `json:"have_lru_percpu_hash_map_type"`
	HavePercpuArrayMapType         bool `json:"have_percpu_array_map_type"`
	HavePercpuCgroupStorageMapType bool `json:"have_percpu_cgroup_storage_map_type"`
	HavePercpuHashMapType          bool `json:"have_percpu_hash_map_type"`
	HavePerfEventArrayMapType      bool `json:"have_perf_event_array_map_type"`
	HaveProgArrayMapType           bool `json:"have_prog_array_map_type"`
	HaveQueueMapType               bool `json:"have_queue_map_type"`
	HaveReuseportSockarrayMapType  bool `json:"have_reuseport_sockarray_map_type"`
	HaveSkStorageMapType           bool `json:"have_sk_storage_map_type"`
	HaveSockhashMapType            bool `json:"have_sockhash_map_type"`
	HaveSockmapMapType             bool `json:"have_sockmap_map_type"`
	HaveStackMapType               bool `json:"have_stack_map_type"`
	HaveStackTraceMapType          bool `json:"have_stack_trace_map_type"`
	HaveXskmapMapType              bool `json:"have_xskmap_map_type"`
}

// ProgramTypes represents informaion about available types of BPF programs.
type ProgramTypes struct {
	HaveCgroupDeviceProgType   bool `json:"have_cgroup_device_prog_type"`
	HaveCgroupSkbProgType      bool `json:"have_cgroup_skb_prog_type"`
	HaveCgroupSockAddrProgType bool `json:"have_cgroup_sock_addr_prog_type"`
	HaveCgroupSockProgType     bool `json:"have_cgroup_sock_prog_type"`
	HaveCgroupSysctlProgType   bool `json:"have_cgroup_sysctl_prog_type"`
	HaveFlowDissectorProgType  bool `json:"have_flow_dissector_prog_type"`
	HaveKprobeProgType         bool `json:"have_kprobe_prog_type"`
	HaveLircMode2ProgType      bool `json:"have_lirc_mode2_prog_type"`
	HaveLwtInProgType          bool `json:"have_lwt_in_prog_type"`
	HaveLwtOutProgType         bool `json:"have_lwt_out_prog_type"`
	HaveLwtSeg6LocalProgType   bool `json:"have_lwt_seg6local_prog_type"`
	HaveLwtXmitProgType        bool `json:"have_lwt_xmit_prog_type"`
	HavePerfEventProgType      bool `json:"have_perf_event_prog_type"`
	HaveRawTracepointProgType  bool `json:"have_raw_tracepoint_prog_type"`
	HaveSchedActProgType       bool `json:"have_sched_act_prog_type"`
	HaveSchedClsProgType       bool `json:"have_sched_cls_prog_type"`
	HaveSkMsgProgType          bool `json:"have_sk_msg_prog_type"`
	HaveSkReuseportProgType    bool `json:"have_sk_reuseport_prog_type"`
	HaveSkSkbProgType          bool `json:"have_sk_skb_prog_type"`
	HaveSockOpsProgType        bool `json:"have_sock_ops_prog_type"`
	HaveSocketFilterProgType   bool `json:"have_socket_filter_prog_type"`
	HaveTracepointProgType     bool `json:"have_tracepoint_prog_type"`
	HaveXdpProgType            bool `json:"have_xdp_prog_type"`
}

// SyscallConfig represents information about available BPF syscalls.
type SyscallConfig struct {
	HaveBpfSyscall bool `json:"have_bpf_syscall"`
}

// KernelParam is a type based on string which represents CONFIG_* kernel
// parameters which usually have values "y", "n" or "m".
type KernelParam string

// Enabled checks whether the kernel parameter is enabled (has "y" value).
func (kp *KernelParam) Enabled() bool {
	return kp != nil && *kp == "y"
}

// EnabledOrModule checks whether the kernel parameter is enabled (has "y"
// value) or enabled as a module (has "m" value).
func (kp *KernelParam) EnabledOrModule() bool {
	return kp != nil && (*kp == "y" || *kp == "m")
}

// SystemConfig represents information about kernel configuration parameters
// related to BPF.
type SystemConfig struct {
	ConfigBpf                    KernelParam `json:"CONFIG_BPF"`
	ConfigBpfilter               KernelParam `json:"CONFIG_BPFILTER"`
	ConfigBpfilterUmh            KernelParam `json:"CONFIG_BPFILTER_UMH"`
	ConfigBpfEvents              KernelParam `json:"CONFIG_BPF_EVENTS"`
	ConfigBpfJit                 KernelParam `json:"CONFIG_BPF_JIT"`
	ConfigBpfJitAlwaysOn         KernelParam `json:"CONFIG_BPF_JIT_ALWAYS_ON"`
	ConfigBpfKprobeOverride      KernelParam `json:"CONFIG_BPF_KPROBE_OVERRIDE"`
	ConfigBpfLircMode2           KernelParam `json:"CONFIG_BPF_LIRC_MODE2"`
	ConfigBpfStreamParser        KernelParam `json:"CONFIG_BPF_STREAM_PARSER"`
	ConfigBpfSyscall             KernelParam `json:"CONFIG_BPF_SYSCALL"`
	ConfigCgroups                KernelParam `json:"CONFIG_CGROUPS"`
	ConfigCgroupBpf              KernelParam `json:"CONFIG_CGROUP_BPF"`
	ConfigCgroupNetClassid       KernelParam `json:"CONFIG_CGROUP_NET_CLASSID"`
	ConfigFtraceSyscalls         KernelParam `json:"CONFIG_FTRACE_SYSCALLS"`
	ConfigFunctionErrorInjection KernelParam `json:"CONFIG_FUNCTION_ERROR_INJECTION"`
	ConfigHaveEbpfJit            KernelParam `json:"CONFIG_HAVE_EBPF_JIT"`
	ConfigIpv6Seg6Bpf            KernelParam `json:"CONFIG_IPV6_SEG6_BPF"`
	ConfigIPRouteClassid         KernelParam `json:"CONFIG_IP_ROUTE_CLASSID"`
	ConfigKprobeEvents           KernelParam `json:"CONFIG_KPROBE_EVENTS"`
	ConfigLwtunnelBpf            KernelParam `json:"CONFIG_LWTUNNEL_BPF"`
	ConfigNet                    KernelParam `json:"CONFIG_NET"`
	ConfigNetfilterXtMatchBpf    KernelParam `json:"CONFIG_NETFILTER_XT_MATCH_BPF"`
	ConfigNetActBpf              KernelParam `json:"CONFIG_NET_ACT_BPF"`
	ConfigNetClsAct              KernelParam `json:"CONFIG_NET_CLS_ACT"`
	ConfigNetClsBpf              KernelParam `json:"CONFIG_NET_CLS_BPF"`
	ConfigNetSchIngress          KernelParam `json:"CONFIG_NET_SCH_INGRESS"`
	ConfigSockCgroupData         KernelParam `json:"CONFIG_SOCK_CGROUP_DATA"`
	ConfigTestBpf                KernelParam `json:"CONFIG_TEST_BPF"`
	ConfigTracing                KernelParam `json:"CONFIG_TRACING"`
	ConfigUprobeEvents           KernelParam `json:"CONFIG_UPROBE_EVENTS"`
	ConfigXdpSockets             KernelParam `json:"CONFIG_XDP_SOCKETS"`
	ConfigXfrm                   KernelParam `json:"CONFIG_XFRM"`
	BpfJitEnable                 int         `json:"bpf_jit_enable"`
	BpfJitHarden                 int         `json:"bpf_jit_harden"`
	BpfJitKallsyms               int         `json:"bpf_jit_kallsyms"`
	BpfJitLimit                  int         `json:"bpf_jit_limit"`
	UnprivilegedBpfDisabled      int         `json:"unprivileged_bpf_disabled"`
}

// Features represents information about BPF features returned by libbpf and
// bpftool.
type Features struct {
	Helpers       `json:"helpers"`
	MapTypes      `json:"map_types"`
	ProgramTypes  `json:"program_types"`
	SyscallConfig `json:"syscall_config"`
	SystemConfig  `json:"system_config"`
}

// probeKernelConfig checks required and recommended kernel configuration
// parameters.
func probeKernelConfig(systemConfig SystemConfig) error {
	if !systemConfig.ConfigBpf.Enabled() {
		return fmt.Errorf("CONFIG_BPF kernel parameter is required")
	}
	if !systemConfig.ConfigBpfSyscall.Enabled() {
		return fmt.Errorf("CONFIG_BPF_SYSCALL kernel parameter is required")
	}
	if !systemConfig.ConfigNetSchIngress.EnabledOrModule() {
		return fmt.Errorf("CONFIG_NET_SCH_INGRESS kernel parameter (or module) is required")
	}
	if !systemConfig.ConfigNetClsBpf.EnabledOrModule() {
		return fmt.Errorf("CONFIG_NET_CLS_BPF kernel parameter (or module) is required")
	}
	if !systemConfig.ConfigNetClsAct.Enabled() {
		return fmt.Errorf("CONFIG_NET_CLS_ACT kernel parameter is required")
	}
	if !systemConfig.ConfigBpfJit.Enabled() {
		return fmt.Errorf("CONFIG_BPF_JIR kernel parameter is required")
	}
	if !systemConfig.ConfigHaveEbpfJit.Enabled() {
		return fmt.Errorf("CONFIG_HAVE_EBPF_JIT kernel parameter is required")
	}
	if !systemConfig.ConfigCgroupBpf.Enabled() {
		log.Warning("CONFIG_CGROUP_BPF kernel parameter is not in kernel configuration")
	}
	if !systemConfig.ConfigLwtunnelBpf.Enabled() {
		log.Warning("CONFIG_LWTUNNEL_BPF kernel parameter is not in kernel configuration")
	}
	if !systemConfig.ConfigBpfEvents.Enabled() {
		log.Warning("CONFIG_BPF_EVENTS kernel parameter is not in kernel configuration")
	}
	return nil
}

func probes(features Features) error {
	if err := probeKernelConfig(features.SystemConfig); err != nil {
		return err
	}
	return nil
}

func parseFeatures(out []byte) (*Features, error) {
	var features Features
	if err := json.Unmarshal(out, &features); err != nil {
		return nil, fmt.Errorf("could not parse bpftool output: %s", err)
	}
	return &features, nil
}

// Probes is the main function which involes bpftool feature probes and checks
// features which are required and recommended by Cilium.
func Probes() error {
	out, err := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "-j", "feature").CombinedOutput(
		log, true)
	if err != nil {
		return fmt.Errorf("could not run bpftool: %s", err)
	}

	features, err := parseFeatures(out)
	if err != nil {
		return err
	}

	return probes(*features)
}
