// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-maps")
)

// endpointManager checks against its list of the current endpoints to determine
// whether map paths should be removed, and implements map removal.
//
// This interface is provided to abstract epmanager/filesystem access for unit
// testing.
type endpointManager interface {
	EndpointExists(endpointID uint16) bool
	RemoveDatapathMapping(endpointID uint16) error
	RemoveMapPath(path string)
	HasGlobalCT() bool
}

// MapSweeper is responsible for checking stale map paths on the filesystem
// and garbage collecting the endpoint if the corresponding endpoint no longer
// exists.
type MapSweeper struct {
	endpointManager
}

// NewMapSweeper creates an object that walks map paths and garbage-collects
// them.
func NewMapSweeper(g endpointManager) *MapSweeper {
	return &MapSweeper{
		endpointManager: g,
	}
}

// deleteMapIfStale uses the endpointManager implementation to determine for
// the given path whether it should be deleted, and if so deletes the path.
func (ms *MapSweeper) deleteMapIfStale(path string, filename string, endpointID string) {
	if tmp, err := strconv.ParseUint(endpointID, 10, 16); err == nil {
		epID := uint16(tmp)
		if ms.EndpointExists(epID) {
			prefix := strings.TrimSuffix(filename, endpointID)
			if filename != bpf.LocalMapName(prefix, epID) {
				ms.RemoveMapPath(path)
			}
		} else {
			err2 := ms.RemoveDatapathMapping(epID)
			if err2 != nil {
				log.WithError(err2).Debugf("Failed to remove ID %d from global policy map", tmp)
			}
			ms.RemoveMapPath(path)
		}
	}
}

func (ms *MapSweeper) checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := ms.HasGlobalCT() || option.Config.EnableNodePort ||
		!option.Config.InstallIptRules && option.Config.MasqueradingEnabled()

	if !globalCTinUse && ctmap.NameIsGlobal(filename) {
		ms.RemoveMapPath(path)
	}
}

func (ms *MapSweeper) walk(path string, _ os.FileInfo, _ error) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapNameTCP6,
		ctmap.MapNameTCP4,
		ctmap.MapNameAny6,
		ctmap.MapNameAny4,
		callsmap.MapName,
		callsmap.CustomCallsMapName,
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
func (ms *MapSweeper) CollectStaleMapGarbage() {
	if err := filepath.Walk(bpf.TCGlobalsPath(), ms.walk); err != nil {
		log.WithError(err).Warn("Error while scanning for stale maps")
	}
}

// RemoveDisabledMaps removes BPF maps in the filesystem for features that have
// been disabled. The maps may still be in use in which case they will continue
// to live until the BPF program using them is being replaced.
func (ms *MapSweeper) RemoveDisabledMaps() {
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
			"cilium_lb6_reverse_sk",
			"cilium_snat_v6_external",
			"cilium_proxy6",
			recorder.MapNameWcard6,
			lbmap.MaglevOuter6MapName,
			lbmap.Affinity6MapName,
			lbmap.SourceRange6MapName,
			lbmap.HealthProbe6MapName,
			cidrmap.MapName + "v6_dyn",
			cidrmap.MapName + "v6_fix",
		}...)
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
			"cilium_lb4_reverse_sk",
			"cilium_snat_v4_external",
			"cilium_proxy4",
			recorder.MapNameWcard4,
			lbmap.MaglevOuter4MapName,
			lbmap.Affinity4MapName,
			lbmap.SourceRange4MapName,
			lbmap.HealthProbe4MapName,
			ipmasq.MapName,
			cidrmap.MapName + "v4_dyn",
			cidrmap.MapName + "v4_fix",
		}...)
	}

	if !option.Config.EnableNodePort {
		maps = append(maps, []string{"cilium_snat_v4_external", "cilium_snat_v6_external"}...)
	}

	if !option.Config.EnableRecorder {
		maps = append(maps, []string{recorder.MapNameWcard4, recorder.MapNameWcard6,
			"cilium_capture_cache", "cilium_ktime_cache"}...)
	}

	if !option.Config.EnableIPv4FragmentsTracking {
		maps = append(maps, "cilium_ipv4_frag_datagrams")
	}

	if !option.Config.EnableBandwidthManager {
		maps = append(maps, "cilium_throttle")
	}

	if !option.Config.EnableHealthDatapath {
		maps = append(maps, lbmap.HealthProbe6MapName, lbmap.HealthProbe4MapName)
	}

	if option.Config.NodePortAlg != option.NodePortAlgMaglev {
		maps = append(maps, lbmap.MaglevOuter6MapName, lbmap.MaglevOuter4MapName)
	}

	if !option.Config.EnableSessionAffinity {
		maps = append(maps, lbmap.Affinity6MapName, lbmap.Affinity4MapName, lbmap.AffinityMatchMapName)
	}

	if !option.Config.EnableSVCSourceRangeCheck {
		maps = append(maps, lbmap.SourceRange6MapName, lbmap.SourceRange4MapName)
	}

	if !option.Config.EnableIPMasqAgent {
		maps = append(maps, ipmasq.MapName)
	}

	if !option.Config.EnableXDPPrefilter {
		maps = append(maps, []string{
			cidrmap.MapName + "v4_dyn",
			cidrmap.MapName + "v4_fix",
			cidrmap.MapName + "v6_dyn",
			cidrmap.MapName + "v6_fix",
		}...)
	}

	for _, m := range maps {
		p := path.Join(bpf.TCGlobalsPath(), m)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			ms.RemoveMapPath(p)
		}
	}
}
