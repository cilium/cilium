// Copyright 2016-2018 Authors of Cilium
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

package maps

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-maps")
)

// CollectStaleMapGarbage cleans up stale content in the BPF maps from the
// datapath.
func CollectStaleMapGarbage() {
	if option.Config.DryMode {
		return
	}
	walker := func(path string, _ os.FileInfo, _ error) error {
		return staleMapWalker(path)
	}

	if err := filepath.Walk(bpf.MapPrefixPath(), walker); err != nil {
		log.WithError(err).Warn("Error while scanning for stale maps")
	}
}

func removeStaleMap(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

func removeStaleIDFromPolicyMap(id uint32) {
	gpm, err := policymap.OpenGlobalMap(bpf.MapPath(endpoint.PolicyGlobalMapName))
	if err == nil {
		gpm.Delete(id, policymap.AllPorts, u8proto.All, trafficdirection.Ingress)
		gpm.Delete(id, policymap.AllPorts, u8proto.All, trafficdirection.Egress)
		gpm.Close()
	}
}

func checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if ep := endpointmanager.LookupCiliumID(uint16(tmp)); ep == nil {
			removeStaleIDFromPolicyMap(uint32(tmp))
			removeStaleMap(path)
		}
	}
}

func checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := endpointmanager.HasGlobalCT()

	if !globalCTinUse && ctmap.NameIsGlobal(filename) {
		removeStaleMap(path)
	}
}

func staleMapWalker(path string) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapNamePrefix,
		endpoint.CallsMapName,
	}

	checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if id := strings.TrimPrefix(filename, m); id != filename {
				checkStaleMap(path, filename, id)
			}
		}
	}

	return nil
}
