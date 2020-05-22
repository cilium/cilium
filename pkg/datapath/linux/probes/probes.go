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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/pkg/errors"
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
	once         sync.Once
	probeManager *ProbeManager
)

type SyscallConfig struct {
	HaveBPFSyscall bool `json:"have_bpf_syscall"`
}

type ProgramTypes struct {
	HaveCgroupSkbProgType  bool `json:"have_cgroup_skb_prog_type"`
	HaveKprobeProgType     bool `json:"have_kprobe_prog_type"`
	HaveLwtInProgType      bool `json:"have_lwt_in_prog_type"`
	HaveLwtOutProgType     bool `json:"have_lwt_out_prog_type"`
	HaveLwtXmitProgType    bool `json:"have_lwt_xmit_prog_type"`
	HaveSchedActProgType   bool `json:"have_sched_act_prog_type"`
	HaveSchedClsProgType   bool `json:"have_sched_cls_prog_type"`
	HaveTracepointProgType bool `json:"have_tracepoint_prog_type"`
}

// SystemConfig contains kernel configuration and sysctl parameters related to
// BPF functionality.
type SystemConfig struct {
	UnprivilegedBpfDisabled int `json:"unprivileged_bpf_disabled"`
	BpfJitEnable            int `json:"bpf_jit_enable"`
	BpfJitHarden            int `json:"bpf_jit_harden"`
	BpfJitKallsyms          int `json:"bpf_jit_kallsyms"`
	BpfJitLimit             int `json:"bpf_jit_limit"`
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
	SyscallConfig `json:"syscall_config"`
	SystemConfig  `json:"system_config"`
	ProgramTypes  `json:"program_types"`
	MapTypes      `json:"map_types"`
	Helpers       map[string][]string `json:"helpers"`
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
			defaults.ExecTimeout,
			"bpftool", "-j", "feature", "probe",
		).CombinedOutput(log, true)
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
	// Required
	if p.features.SyscallConfig.HaveBPFSyscall {
		return fmt.Errorf("The BPF syscall must be enabled")
	}
	progTypes := p.features.ProgramTypes
	if progTypes.HaveSchedClsProgType {
		return fmt.Errorf("Kernel support for BPF-based classifiers is required")
	}
	if progTypes.HaveSchedActProgType {
		return fmt.Errorf("Kernel support for BPF tc actions is required")
	}
	if p.features.SystemConfig.BpfJitEnable == 0 {
		return fmt.Errorf("The BPF JIT compiler is required")
	}
	// Optional
	if progTypes.HaveCgroupSkbProgType {
		log.Warning("Cannot attach BPF programs to cgroups")
	}
	if progTypes.HaveLwtInProgType && progTypes.HaveLwtOutProgType && progTypes.HaveLwtXmitProgType {
		log.Warning("BPF for lightweight tunneling is disabled")
	}
	if progTypes.HaveKprobeProgType {
		log.Warning("Support for BPF-based kprobes is disabled")
	}
	if progTypes.HaveTracepointProgType {
		log.Warning("Support for BPF-based tracepoints is disabled")
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

// writeHeaders executes bpftool to generate BPF feature C macros and then
// writes them to the given writer.
func (p *ProbeManager) writeHeaders(featuresFile io.Writer) error {
	cmd := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "feature", "probe", "macros")
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return errors.Wrap(err,
			"could not initialize stdout pipe for bpftool feature probe")
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return errors.Wrap(err,
			"could not initialize stderr pipe for bpftool feature probe")
	}
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err,
			"could not start bpftool for bpftool feature probe")
	}

	writer := bufio.NewWriter(featuresFile)
	defer writer.Flush()

	io.WriteString(writer, "#ifndef BPF_FEATURES_H_\n")
	io.WriteString(writer, "#define BPF_FEATURES_H_\n\n")

	io.Copy(writer, stdoutPipe)
	if err := cmd.Wait(); err != nil {
		stderr, err := ioutil.ReadAll(stderrPipe)
		if err != nil {
			return errors.Wrap(err,
				"reading from bpftool feature probe stderr pipe failed")
		}
		return errors.Wrapf(err,
			"bpftool feature probe did not run successfully: %s",
			stderr)
	}

	io.WriteString(writer, "#endif /* BPF_FEATURES_H_ */\n")

	return nil
}

// CreateHeadersFile creates a C header file with macros indicating which BPF
// features are available in the kernel.
func (p *ProbeManager) CreateHeadersFile() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		return errors.Wrapf(err, "could not create runtime directory %s",
			globalsDir)
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	featuresFile, err := os.Create(featuresFilePath)
	if err != nil {
		return errors.Wrapf(err,
			"could not create features header file %s",
			featuresFilePath)
	}
	defer featuresFile.Close()

	if err := p.writeHeaders(featuresFile); err != nil {
		return err
	}
	return nil
}
