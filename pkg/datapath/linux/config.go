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

package linux

import (
	"bufio"
	"fmt"
	"io"
	"reflect"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func writeIncludes(w io.Writer) (int, error) {
	return fmt.Fprintf(w, "#include \"lib/utils.h\"\n\n")
}

// WriteNodeConfig writes the local node configuration to the specified writer.
func (l *linuxDatapath) WriteNodeConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration) error {
	fw := bufio.NewWriter(w)

	writeIncludes(w)

	routerIP := node.GetIPv6Router()
	hostIP := node.GetIPv6()

	fmt.Fprintf(fw, ""+
		"/*\n"+
		" * Node-IPv6: %s\n"+
		" * Router-IPv6: %s\n"+
		" * Host-IPv4: %s\n"+
		" */\n\n",
		hostIP.String(), routerIP.String(),
		node.GetInternalIPv4().String())

	if option.Config.EnableIPv6 {
		fw.WriteString(defineIPv6("ROUTER_IP", routerIP))
	}

	if option.Config.EnableIPv4 {
		ipv4GW := node.GetInternalIPv4()
		loopbackIPv4 := node.GetIPv4Loopback()
		ipv4Range := node.GetIPv4AllocRange()
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", byteorder.HostSliceToNetwork(ipv4GW, reflect.Uint32).(uint32))
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", byteorder.HostSliceToNetwork(loopbackIPv4, reflect.Uint32).(uint32))
		fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", byteorder.HostSliceToNetwork(ipv4Range.Mask, reflect.Uint32).(uint32))
	}

	if nat46Range := option.Config.NAT46Prefix; nat46Range != nil {
		fw.WriteString(FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(defineIPv6("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", identity.GetReservedID(labels.IDNameHost))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", identity.GetReservedID(labels.IDNameWorld))
	fmt.Fprintf(fw, "#define HEALTH_ID %d\n", identity.GetReservedID(labels.IDNameHealth))
	fmt.Fprintf(fw, "#define UNMANAGED_ID %d\n", identity.GetReservedID(labels.IDNameUnmanaged))
	fmt.Fprintf(fw, "#define INIT_ID %d\n", identity.GetReservedID(labels.IDNameInit))
	fmt.Fprintf(fw, "#define LB_RR_MAX_SEQ %d\n", lbmap.MaxSeq)
	fmt.Fprintf(fw, "#define CILIUM_LB_MAP_MAX_ENTRIES %d\n", lbmap.MaxEntries)
	fmt.Fprintf(fw, "#define TUNNEL_MAP %s\n", tunnel.MapName)
	fmt.Fprintf(fw, "#define TUNNEL_ENDPOINT_MAP_SIZE %d\n", tunnel.MaxEntries)
	fmt.Fprintf(fw, "#define PROXY_MAP_SIZE %d\n", proxymap.MaxEntries)
	fmt.Fprintf(fw, "#define ENDPOINTS_MAP %s\n", lxcmap.MapName)
	fmt.Fprintf(fw, "#define ENDPOINTS_MAP_SIZE %d\n", lxcmap.MaxEntries)
	fmt.Fprintf(fw, "#define METRICS_MAP %s\n", metricsmap.MapName)
	fmt.Fprintf(fw, "#define METRICS_MAP_SIZE %d\n", metricsmap.MaxEntries)
	fmt.Fprintf(fw, "#define POLICY_MAP_SIZE %d\n", policymap.MaxEntries)
	fmt.Fprintf(fw, "#define IPCACHE_MAP %s\n", ipcachemap.Name)
	fmt.Fprintf(fw, "#define IPCACHE_MAP_SIZE %d\n", ipcachemap.MaxEntries)
	fmt.Fprintf(fw, "#define POLICY_PROG_MAP_SIZE %d\n", policymap.ProgArrayMaxEntries)
	fmt.Fprintf(fw, "#define SOCKOPS_MAP_SIZE %d\n", sockmap.MaxEntries)

	if option.Config.DatapathMode == option.DatapathModeIpvlan {
		fmt.Fprintf(fw, "#define ENABLE_SECCTX_FROM_IPCACHE 1\n")
	}

	if option.Config.PreAllocateMaps {
		fmt.Fprintf(fw, "#define PREALLOCATE_MAPS 1\n")
	}

	fmt.Fprintf(fw, "#define EVENTS_MAP %s\n", "cilium_events")
	fmt.Fprintf(fw, "#define POLICY_CALL_MAP %s\n", policymap.CallMapName)
	fmt.Fprintf(fw, "#define PROXY4_MAP cilium_proxy4\n")
	fmt.Fprintf(fw, "#define PROXY6_MAP cilium_proxy6\n")
	fmt.Fprintf(fw, "#define EP_POLICY_MAP %s\n", eppolicymap.MapName)
	fmt.Fprintf(fw, "#define LB6_REVERSE_NAT_MAP cilium_lb6_reverse_nat\n")
	fmt.Fprintf(fw, "#define LB6_SERVICES_MAP cilium_lb6_services\n")
	fmt.Fprintf(fw, "#define LB6_SERVICES_MAP_V2 cilium_lb6_services_v2\n")
	fmt.Fprintf(fw, "#define LB6_BACKEND_MAP cilium_lb6_backends\n")
	fmt.Fprintf(fw, "#define LB6_RR_SEQ_MAP cilium_lb6_rr_seq\n")
	fmt.Fprintf(fw, "#define LB6_RR_SEQ_MAP_V2 cilium_lb6_rr_seq_v2\n")
	fmt.Fprintf(fw, "#define LB4_REVERSE_NAT_MAP cilium_lb4_reverse_nat\n")
	fmt.Fprintf(fw, "#define LB4_SERVICES_MAP cilium_lb4_services\n")
	fmt.Fprintf(fw, "#define LB4_SERVICES_MAP_V2 cilium_lb4_services_v2\n")
	fmt.Fprintf(fw, "#define LB4_RR_SEQ_MAP cilium_lb4_rr_seq\n")
	fmt.Fprintf(fw, "#define LB4_RR_SEQ_MAP_V2 cilium_lb4_rr_seq_v2\n")
	fmt.Fprintf(fw, "#define LB4_BACKEND_MAP cilium_lb4_backends\n")

	fmt.Fprintf(fw, "#define TRACE_PAYLOAD_LEN %dULL\n", option.Config.TracePayloadlen)
	fmt.Fprintf(fw, "#define MTU %d\n", cfg.MtuConfig.GetDeviceMTU())

	if option.Config.EnableIPv4 {
		fmt.Fprintf(fw, "#define ENABLE_IPV4 1\n")
	}
	if option.Config.EnableIPv6 {
		fmt.Fprintf(fw, "#define ENABLE_IPV6 1\n")
	}
	if option.Config.EnableIPSec {
		fmt.Fprintf(fw, "#define ENABLE_IPSEC 1\n")
	}
	if !option.Config.InstallIptRules && option.Config.Masquerade {
		fmt.Fprintf(fw, "#define ENABLE_MASQUERADE 1\n")
		fmt.Fprintf(fw, "#define SNAT_MAPPING_MIN_PORT %d\n", nat.MinPortSnatDefault)
		fmt.Fprintf(fw, "#define SNAT_MAPPING_MAX_PORT %d\n", nat.MaxPortSnatDefault)
		fmt.Fprintf(fw, "#define SNAT_COLLISION_RETRIES %d\n", nat.CollisionRetriesDefault)
		// SNAT_DIRECTION is defined by init.sh
		if option.Config.EnableIPv4 {
			ipv4Addr := node.GetExternalIPv4()
			fmt.Fprintf(fw, "#define SNAT_IPV4_EXTERNAL %#x\n", byteorder.HostSliceToNetwork(ipv4Addr, reflect.Uint32).(uint32))
			fmt.Fprintf(fw, "#define SNAT_MAPPING_IPV4 %s\n", nat.MapNameSnat4Global)
			fmt.Fprintf(fw, "#define SNAT_MAPPING_IPV4_SIZE %d\n", nat.MaxEntries)
		}
		if option.Config.EnableIPv6 {
			fw.WriteString(defineIPv6("SNAT_IPV6_EXTERNAL", hostIP))
			fmt.Fprintf(fw, "#define SNAT_MAPPING_IPV6 %s\n", nat.MapNameSnat6Global)
			fmt.Fprintf(fw, "#define SNAT_MAPPING_IPV6_SIZE %d\n", nat.MaxEntries)
		}
		ctmap.WriteBPFMacros(fw, nil)
	}

	return fw.Flush()
}

func (l *linuxDatapath) writeNetdevConfig(w io.Writer, cfg datapath.DeviceConfiguration) {
	fmt.Fprint(w, cfg.GetOptions().GetFmtList())
	if option.Config.IsFlannelMasterDeviceSet() {
		fmt.Fprint(w, "#define HOST_REDIRECT_TO_INGRESS 1\n")
	}

	// In case the Linux kernel doesn't support LPM map type, pass the set
	// of prefix length for the datapath to lookup the map.
	if ipcache.IPCache.MapType != bpf.BPF_MAP_TYPE_LPM_TRIE {
		ipcachePrefixes6, ipcachePrefixes4 := cfg.GetCIDRPrefixLengths()

		fmt.Fprint(w, "#define IPCACHE6_PREFIXES ")
		for _, prefix := range ipcachePrefixes6 {
			fmt.Fprintf(w, "%d,", prefix)
		}
		fmt.Fprint(w, "\n")
		fmt.Fprint(w, "#define IPCACHE4_PREFIXES ")
		for _, prefix := range ipcachePrefixes4 {
			fmt.Fprintf(w, "%d,", prefix)
		}
		fmt.Fprint(w, "\n")
	}
}

// WriteNetdevConfig writes the BPF configuration for the endpoint to a writer.
func (l *linuxDatapath) WriteNetdevConfig(w io.Writer, cfg datapath.DeviceConfiguration) error {
	fw := bufio.NewWriter(w)
	l.writeNetdevConfig(fw, cfg)
	return fw.Flush()
}

// writeStaticData writes the endpoint-specific static data defines to the
// specified writer. This must be kept in sync with loader.ELFSubstitutions().
func (l *linuxDatapath) writeStaticData(fw io.Writer, e datapath.EndpointConfiguration) {
	fmt.Fprint(fw, defineIPv6("LXC_IP", e.IPv6Address()))
	fmt.Fprint(fw, defineIPv4("LXC_IPV4", e.IPv4Address()))

	fmt.Fprint(fw, defineMAC("NODE_MAC", e.GetNodeMAC()))
	fmt.Fprint(fw, defineUint32("LXC_ID", uint32(e.GetID())))

	secID := e.GetIdentity().Uint32()
	fmt.Fprintf(fw, defineUint32("SECLABEL", secID))
	fmt.Fprintf(fw, defineUint32("SECLABEL_NB", byteorder.HostToNetwork(secID).(uint32)))

	epID := uint16(e.GetID())
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", bpf.LocalMapName(policymap.MapName, epID))
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", bpf.LocalMapName("cilium_calls_", epID))
	fmt.Fprintf(fw, "#define CONFIG_MAP %s\n", bpf.LocalMapName(bpfconfig.MapNamePrefix, epID))
}

// WriteEndpointConfig writes the BPF configuration for the endpoint to a writer.
func (l *linuxDatapath) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)

	writeIncludes(w)
	l.writeStaticData(fw, e)

	return l.writeTemplateConfig(fw, e)
}

func (l *linuxDatapath) writeTemplateConfig(fw *bufio.Writer, e datapath.EndpointConfiguration) error {
	if !e.HasIpvlanDataPath() {
		fmt.Fprint(fw, "#define ENABLE_ARP_RESPONDER 1\n")
		fmt.Fprint(fw, "#define ENABLE_HOST_REDIRECT 1\n")
		if option.Config.IsFlannelMasterDeviceSet() {
			fmt.Fprint(fw, "#define HOST_REDIRECT_TO_INGRESS 1\n")
		}
	}

	if e.ConntrackLocalLocked() {
		ctmap.WriteBPFMacros(fw, e)
	} else {
		ctmap.WriteBPFMacros(fw, nil)
	}

	// Always enable L4 and L3 load balancer for now
	fmt.Fprint(fw, "#define LB_L3 1\n")
	fmt.Fprint(fw, "#define LB_L4 1\n")

	// Local delivery metrics should always be set for endpoint programs.
	fmt.Fprint(fw, "#define LOCAL_DELIVERY_METRICS 1\n")

	l.writeNetdevConfig(fw, e)

	return fw.Flush()
}

// WriteEndpointConfig writes the BPF configuration for the template to a writer.
func (l *linuxDatapath) WriteTemplateConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)
	return l.writeTemplateConfig(fw, e)
}
