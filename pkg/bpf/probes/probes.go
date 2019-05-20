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
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	KeyMapTypes = "map_types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
)

// SupportedMapTypes contains bools indicating which types of BPF maps the
// currently running kernel supports.
type SupportedMapTypes struct {
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

func generateHeaders(featuresFile io.Writer) error {
	cmd := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "feature", "probe", "macros")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start bpftool: %s", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf(
			"could not initialize stout pipe for bpftool: %s", err)
	}

	writer := bufio.NewWriter(featuresFile)
	defer writer.Flush()

	go io.Copy(writer, stdoutPipe)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("bpftool did not run successfully: %s", err)
	}
	return nil
}

func CreateHeadersFile() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	featuresFile, err := os.Create(featuresFilePath)
	if err != nil {
		return fmt.Errorf("could not create features header file %s: %s",
			featuresFilePath, err)
	}
	defer featuresFile.Close()

	if err := generateHeaders(featuresFile); err != nil {
		return err
	}
	return nil
}

func parseSupportedMapTypes(out []byte) (*SupportedMapTypes, error) {
	var probes map[string]interface{}
	if err := json.Unmarshal(out, &probes); err != nil {
		return nil, fmt.Errorf("could not parse bpftool output: %s", err)
	}
	mapTypes := probes[KeyMapTypes].(SupportedMapTypes)
	return &mapTypes, nil
}

func GetSupportedMapTypes() (*SupportedMapTypes, error) {
	out, err := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "-j", "feature").CombinedOutput(
		log, true)
	if err != nil {
		return nil, fmt.Errorf("could not run bpftool: %s", err)
	}
	return parseSupportedMapTypes(out)
}
