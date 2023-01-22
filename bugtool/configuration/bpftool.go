// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configuration

import (
	"fmt"
	"strings"

	dump "github.com/cilium/cilium/bugtool/dump"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	log "github.com/sirupsen/logrus"
)

const bpftoolMapDumpPrefix = "bpftool-map-dump-pinned-"

// GenerateBPFToolTasks returns all tasks related to bpftool, including:
// * Dumping pinned bpf maps (using bpftool).
// * Listing bpf maps/programs/network-iface attachments.
//
// TODO: Convert these to use dump.BPFMap task type.
func GenerateBPFToolTasks() dump.Tasks {
	ts := dump.Tasks{
		newBPFMapTask("map", "show"),
		newBPFMapTask("prog", "show"),
		newBPFMapTask("net", "show"),
	}

	var mountpoint string
	if bpffsMountpoint, err := bpffsMountpoint(); err == nil {
		mountpoint = bpffsMountpoint
		ts = append(ts, mapDumpPinned(mountpoint,
			"cilium_call_policy",
			"cilium_calls_overlay_2",
			"cilium_capture_cache",
			"cilium_lxc",
			"cilium_metrics",
			"cilium_tunnel_map",
			"cilium_signals",
			"cilium_ktime_cache",
			"cilium_ipcache",
			"cilium_events",
			"cilium_sock_ops",
			"cilium_signals",
			"cilium_capture4_rules",
			"cilium_capture6_rules",
			"cilium_call_policy",
			"cilium_nodeport_neigh4",
			"cilium_nodeport_neigh6",
			"cilium_lb4_source_range",
			"cilium_lb6_source_range",
			"cilium_lb4_maglev",
			"cilium_lb6_maglev",
			"cilium_lb6_health",
			"cilium_lb6_reverse_sk",
			"cilium_lb4_health",
			"cilium_lb4_reverse_sk",
			"cilium_ipmasq_v4",
			"cilium_ipv4_frag_datagrams",
			"cilium_ep_to_policy",
			"cilium_throttle",
			"cilium_encrypt_state",
			"cilium_egress_gw_policy_v4",
			"cilium_srv6_vrf_v4",
			"cilium_srv6_vrf_v6",
			"cilium_srv6_policy_v4",
			"cilium_srv6_policy_v6",
			"cilium_srv6_state_v4",
			"cilium_srv6_state_v6",
			"cilium_srv6_sid",
			"cilium_lb4_services_v2",
			"cilium_lb4_services",
			"cilium_lb4_backends_v2",
			"cilium_lb4_backends",
			"cilium_lb4_reverse_nat",
			"cilium_ct4_global",
			"cilium_ct_any4_global",
			"cilium_lb4_affinity",
			"cilium_lb6_affinity",
			"cilium_lb_affinity_match",
			"cilium_lb6_services_v2",
			"cilium_lb6_services",
			"cilium_lb6_backends_v2",
			"cilium_lb6_backends",
			"cilium_lb6_reverse_nat",
			"cilium_ct6_global",
			"cilium_ct_any6_global",
			"cilium_snat_v4_external",
			"cilium_snat_v6_external",
		)...)
	} else {
		log.Errorf("could not detect bpf fs mountpoint: %v, skipping bpf map dumps", err)
	}
	return ts
}

func mapDumpPinned(mountPoint string, mapNames ...string) dump.Tasks {
	rs := dump.Tasks{}
	for _, mapName := range mapNames {
		fname := fmt.Sprintf("%s/tc/globals/%s", mountPoint, mapName)
		rs = append(rs, dump.NewExec(
			bpftoolMapDumpPrefix+mapName,
			"json",
			"bpftool",
			"map", "dump", "pinned", fname, "-j",
		))
	}

	fname := func(mapName string) string {
		if !strings.HasPrefix(mountPoint, "cilium_") {
			mapName = "cilium_" + mapName
		}
		return fmt.Sprintf("%s/tc/globals/%s", mountPoint, mapName)
	}
	// TODO: Convert more maps to use this task type, using correct models.
	rs = append(rs, dump.NewPinnedBPFMap[lxcmap.EndpointKey, lxcmap.EndpointInfo](fname("cilium_call_policy")))
	rs = append(rs, dump.NewPinnedBPFMap[ipcache.Key, ipcache.RemoteEndpointInfo](fname("cilium_ipcache")))
	rs = append(rs, dump.NewPinnedBPFMap[lxcmap.EndpointKey, lxcmap.EndpointInfo](fname("cilium_lxc")))
	rs = append(rs, dump.NewPinnedBPFMap[tunnel.TunnelKey, tunnel.TunnelValue](fname("tunnel_map")))
	return rs
}

func newBPFMapTask(args ...string) dump.Task {
	return dump.NewExec("bpftool-map", "json", "bpftool", append(args, "-j")...)
}
