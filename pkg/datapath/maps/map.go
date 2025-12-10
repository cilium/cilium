// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	dptypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
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
	ListMapsDir(path string) []string
}

// PrefixedMap describes a pattern for filtering map files.
// It specifies which files to match via Prefix and which to exclude via Excludes.
type PrefixedMap struct {
	Prefix   string
	Excludes []string
}

// MapSweeper is responsible for checking stale map paths on the filesystem
// and garbage collecting the endpoint if the corresponding endpoint no longer
// exists.
type MapSweeper struct {
	logger *slog.Logger
	endpointManager
	bwManager dptypes.BandwidthManager
	lbConfig  loadbalancer.Config
	kprCfg    kpr.KPRConfig
}

// newMapSweeper creates an object that walks map paths and garbage-collects
// them.
func newMapSweeper(logger *slog.Logger, g endpointManager, bwm dptypes.BandwidthManager, lbConfig loadbalancer.Config, kprCfg kpr.KPRConfig) *MapSweeper {
	return &MapSweeper{
		logger:          logger,
		endpointManager: g,
		bwManager:       bwm,
		lbConfig:        lbConfig,
		kprCfg:          kprCfg,
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
				ms.logger.Debug("Failed to remove ID from global policy map",
					logfields.Error, err2,
					logfields.ID, tmp,
				)
			}
			ms.RemoveMapPath(path)
		}
	}
}

func (ms *MapSweeper) walk(path string, _ os.FileInfo, _ error) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		callsmap.MapName,
	}

	for _, m := range mapPrefix {
		if endpointID, found := strings.CutPrefix(filename, m); found {
			ms.deleteMapIfStale(path, filename, endpointID)
		}
	}

	return nil
}

// CollectStaleMapGarbage cleans up stale content in the BPF maps from the
// datapath.
func (ms *MapSweeper) CollectStaleMapGarbage() {
	if err := filepath.Walk(bpf.TCGlobalsPath(), ms.walk); err != nil {
		ms.logger.Warn("Error while scanning for stale maps", logfields.Error, err)
	}
}

// RemoveDisabledMaps removes BPF maps in the filesystem for features that have
// been disabled. The maps may still be in use in which case they will continue
// to live until the BPF program using them is being replaced.
func (ms *MapSweeper) RemoveDisabledMaps() {
	var (
		mapsDir = bpf.TCGlobalsPath()
		maps    = []string{
			// maps we unconditionally remove, because they no longer exist in modern versions of Cilium at all
			"cilium_proxy4",
			"cilium_proxy6",
			"cilium_capture_cache",
			"cilium_capture4_rules",
			"cilium_capture6_rules",
			"cilium_ktime_cache",
		}
		prefixedMaps = []PrefixedMap{
			{"cilium_policy_", []string{policymap.MapName}},
		}
	)

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
			"cilium_snat_v6_alloc_retries",
			"cilium_l2_responder_v6",
			"cilium_egress_gw_policy_v6",
			lbmaps.MaglevOuter6MapName,
			lbmaps.Affinity6MapName,
			lbmaps.SourceRange6MapName,
			lbmaps.HealthProbe6MapName,
			ipmasq.MapNameIPv6,
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
			"cilium_snat_v4_alloc_retries",
			"cilium_l2_responder_v4",
			"cilium_egress_gw_policy_v4",
			lbmaps.MaglevOuter4MapName,
			lbmaps.Affinity4MapName,
			lbmaps.SourceRange4MapName,
			lbmaps.HealthProbe4MapName,
			ipmasq.MapNameIPv4,
			cidrmap.MapName + "v4_dyn",
			cidrmap.MapName + "v4_fix",
		}...)
	}

	if !ms.kprCfg.KubeProxyReplacement && !option.Config.EnableBPFMasquerade {
		maps = append(maps, []string{
			"cilium_snat_v4_external", "cilium_snat_v6_external",
			"cilium_snat_v4_alloc_retries", "cilium_snat_v6_alloc_retries",
		}...)
	}

	if !option.Config.EnableIPv4FragmentsTracking {
		maps = append(maps, "cilium_ipv4_frag_datagrams")
	}

	if !option.Config.EnableIPv6FragmentsTracking {
		maps = append(maps, "cilium_ipv6_frag_datagrams")
	}

	if !ms.bwManager.Enabled() {
		maps = append(maps, "cilium_throttle")
	}

	if !option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath {
		maps = append(maps, lbmaps.HealthProbe6MapName, lbmaps.HealthProbe4MapName)
	}

	if ms.lbConfig.LBAlgorithm != loadbalancer.LBAlgorithmMaglev &&
		!ms.lbConfig.AlgorithmAnnotation {
		maps = append(maps, lbmaps.MaglevOuter6MapName, lbmaps.MaglevOuter4MapName)
	}

	if !(option.Config.EnableIPMasqAgent && option.Config.EnableIPv4Masquerade) {
		maps = append(maps, ipmasq.MapNameIPv4)
	}

	if !(option.Config.EnableIPMasqAgent && option.Config.EnableIPv6Masquerade) {
		maps = append(maps, ipmasq.MapNameIPv6)
	}

	if !option.Config.EnableSRv6 {
		maps = append(maps,
			"cilium_srv6_sid",
			"cilium_srv6_policy_v4",
			"cilium_srv6_policy_v6",
			"cilium_srv6_vrf_v4",
			"cilium_srv6_vrf_v6",
		)
	}

	if !option.Config.EnableXDPPrefilter {
		maps = append(maps, []string{
			cidrmap.MapName + "v4_dyn",
			cidrmap.MapName + "v4_fix",
			cidrmap.MapName + "v6_dyn",
			cidrmap.MapName + "v6_fix",
		}...)
	}

	// helper func to check if a map name match any excludes
	containsExcluded := func(mapName string, excludes []string) bool {
		for _, ex := range excludes {
			if strings.Contains(mapName, ex) {
				return true
			}
		}
		return false
	}

	// helper func to check if map name matches any prefixedMaps and does not match excludes
	matchesPrefixedMap := func(mapName string) bool {
		for _, pm := range prefixedMaps {
			if !strings.HasPrefix(mapName, pm.Prefix) {
				continue
			}
			if containsExcluded(mapName, pm.Excludes) {
				continue
			}
			return true
		}
		return false
	}

	for _, m := range ms.ListMapsDir(mapsDir) {
		if slices.Contains(maps, m) || matchesPrefixedMap(m) {
			ms.RemoveMapPath(path.Join(mapsDir, m))
		}
	}
}
