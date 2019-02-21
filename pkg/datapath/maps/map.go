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

	globalSweeper = newMapSweeper(&realGarbageWalker{})
)

// garbageWalker checks against its list of the current endpoints to determine
// whether map paths should be removed, and implements map removal.
type garbageWalker interface {
	shouldRemove(id uint16) bool
	removeMapping(id uint32) error
	removePath(path string)
}

type realGarbageWalker struct{}

func (gw *realGarbageWalker) shouldRemove(id uint16) bool {
	if ep := endpointmanager.LookupCiliumID(id); ep != nil {
		return false
	}
	return true
}

func (gw *realGarbageWalker) removeMapping(id uint32) error {
	return policymap.RemoveGlobalMapping(id)
}

func (gw *realGarbageWalker) removePath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

type mapSweeper struct {
	garbageWalker
}

// newMapSweeper creates an object that walks paths and garbage-collects them.
func newMapSweeper(g garbageWalker) *mapSweeper {
	return &mapSweeper{
		garbageWalker: g,
	}
}

// checkStaleMap uses the garbageWalker implementation to determine for the
// given path whether it should be deleted, and if so deletes the path.
func (ms *mapSweeper) checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if ms.shouldRemove(uint16(tmp)) {
			err2 := ms.removeMapping(uint32(tmp))
			if err2 != nil {
				log.WithError(err2).Debugf("Failed to remove ID %d from global policy map", tmp)
			}
			ms.removePath(path)
		}
	}
}

func (ms *mapSweeper) checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := endpointmanager.HasGlobalCT()

	if !globalCTinUse && ctmap.NameIsGlobal(filename) {
		ms.removePath(path)
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
		endpoint.CallsMapName,
		bpfconfig.MapNamePrefix,
		endpoint.IpvlanMapName,
	}

	ms.checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if id := strings.TrimPrefix(filename, m); id != filename {
				ms.checkStaleMap(path, filename, id)
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
			"cilium_proxy6"}...)
	}

	if !option.Config.EnableIPv4 {
		maps = append(maps, []string{
			"cilium_ct4_global",
			"cilium_ct_any4_global",
			"cilium_lb4_reverse_nat",
			"cilium_lb4_rr_seq",
			"cilium_lb4_services",
			"cilium_proxy4"}...)
	}

	for _, m := range maps {
		p := path.Join(bpf.MapPrefixPath(), m)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			globalSweeper.removePath(p)
		}
	}
}
