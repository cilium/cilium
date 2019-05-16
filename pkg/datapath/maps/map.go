// Copyright 2016-2019 Authors of Cilium
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
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-maps")

	globalSweeper = newMapSweeper(&realEPManager{})
)

// endpointManager checks against its list of the current endpoints to determine
// whether map paths should be removed, and implements map removal.
//
// This interface is provided to abstract epmanager/filesystem access for unit
// testing.
type endpointManager interface {
	endpointExists(endpointID uint16) bool
	removeDatapathMapping(endpointID uint16) error
	removeMapPath(path string)
}

// realEPManager provides an implementatino of endpointManager that is backed
// by the endpointmanager and policymap packages, and when removeMapPath is
// invoked, it cleans up paths on the actual filesystem.
type realEPManager struct{}

func (gw *realEPManager) endpointExists(endpointID uint16) bool {
	if ep := endpointmanager.LookupCiliumID(endpointID); ep != nil {
		return true
	}
	return false
}

// removeDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (gw *realEPManager) removeDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(uint32(endpointID))
}

// removeMapPath removes the specified path from the filesystem.
func (gw *realEPManager) removeMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

// mapSweeper is responsible for checking stale map paths on the filesystem
// and garbage collecting the endpoint if the corresponding endpoint no longer
// exists.
type mapSweeper struct {
	endpointManager
}

// newMapSweeper creates an object that walks map paths and garbage-collects
// them.
func newMapSweeper(g endpointManager) *mapSweeper {
	return &mapSweeper{
		endpointManager: g,
	}
}

// deleteMapIfStale uses the endpointManager implementation to determine for
// the given path whether it should be deleted, and if so deletes the path.
func (ms *mapSweeper) deleteMapIfStale(path string, filename string, endpointID string) {
	if tmp, err := strconv.ParseUint(endpointID, 10, 16); err == nil {
		epID := uint16(tmp)
		if ms.endpointExists(epID) {
			prefix := strings.TrimSuffix(filename, endpointID)
			if filename != bpf.LocalMapName(prefix, epID) {
				ms.removeMapPath(path)
			}
		} else {
			err2 := ms.removeDatapathMapping(epID)
			if err2 != nil {
				log.WithError(err2).Debugf("Failed to remove ID %d from global policy map", tmp)
			}
			ms.removeMapPath(path)
		}
	}
}

func (ms *mapSweeper) checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := endpointmanager.HasGlobalCT()

	if !globalCTinUse && ctmap.NameIsGlobal(filename) {
		ms.removeMapPath(path)
	}
}

func (ms *mapSweeper) walk(path string, _ os.FileInfo, _ error) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapNameTCP6,
		ctmap.MapNameTCP4,
		ctmap.MapNameAny6,
		ctmap.MapNameAny4,
		loader.CallsMapName,
		bpfconfig.MapNamePrefix,
		endpoint.IpvlanMapName,
	}

	ms.checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if endpointID := strings.TrimPrefix(filename, m); endpointID != filename {
				ms.deleteMapIfStale(path, filename, endpointID)
			}
		}
	}

	return nil
}

// CollectStaleMapGarbage cleans up stale content in the BPF maps from the
// datapath.
func CollectStaleMapGarbage() {
	if err := filepath.Walk(bpf.MapPrefixPath(), globalSweeper.walk); err != nil {
		log.WithError(err).Warn("Error while scanning for stale maps")
	}
}

// RemoveDisabledMaps removes BPF maps in the filesystem for features that have
// been disabled. The maps may still be in use in which case they will continue
// to live until the BPF program using them is being replaced.
func RemoveDisabledMaps() {
	maps := []string{}

	if !option.Config.EnableIPv6 {
		maps = append(maps, []string{
			"cilium_ct6_global",
			"cilium_ct_any6_global",
			"cilium_lb6_reverse_nat",
			"cilium_lb6_rr_seq",
			"cilium_lb6_services",
			"cilium_lb6_services_v2",
			"cilium_lb6_rr_seq_v2",
			"cilium_lb6_backends_v2",
			"cilium_snat_v6_external",
			"cilium_proxy6"}...)
	}

	if !option.Config.EnableIPv4 {
		maps = append(maps, []string{
			"cilium_ct4_global",
			"cilium_ct_any4_global",
			"cilium_lb4_reverse_nat",
			"cilium_lb4_rr_seq",
			"cilium_lb4_services",
			"cilium_lb4_services_v2",
			"cilium_lb4_rr_seq_v2",
			"cilium_lb4_backends_v2",
			"cilium_snat_v4_external",
			"cilium_proxy4"}...)
	}

	for _, m := range maps {
		p := path.Join(bpf.MapPrefixPath(), m)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			globalSweeper.removeMapPath(p)
		}
	}
}
