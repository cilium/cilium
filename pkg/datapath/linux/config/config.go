// Copyright 2019-2020 Authors of Cilium
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

package config

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/link"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
)

// HeaderfileWriter is a wrapper type which implements datapath.ConfigWriter.
// It manages writing of configuration of datapath program headerfiles.
type HeaderfileWriter struct{}

func writeIncludes(w io.Writer) (int, error) {
	return fmt.Fprintf(w, "#include \"lib/utils.h\"\n\n")
}

// WriteNodeConfig writes the local node configuration to the specified writer.
func (h *HeaderfileWriter) WriteNodeConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration) error {
	extraMacrosMap := make(map[string]string)
	cDefinesMap := make(map[string]string)

	fw := bufio.NewWriter(w)

	writeIncludes(w)

	routerIP := node.GetIPv6Router()
	hostIP := node.GetIPv6()

	fmt.Fprintf(fw, "/*\n")
	if option.Config.EnableIPv6 {
		fmt.Fprintf(fw, " cilium.v6.external.str %s\n", node.GetIPv6().String())
		fmt.Fprintf(fw, " cilium.v6.internal.str %s\n", node.GetIPv6Router().String())
		fmt.Fprintf(fw, " cilium.v6.nodeport.str %s\n", node.GetNodePortIPv6Addrs())
		fmt.Fprintf(fw, "\n")
	}
	fmt.Fprintf(fw, " cilium.v4.external.str %s\n", node.GetExternalIPv4().String())
	fmt.Fprintf(fw, " cilium.v4.internal.str %s\n", node.GetInternalIPv4().String())
	fmt.Fprintf(fw, " cilium.v4.nodeport.str %s\n", node.GetNodePortIPv4Addrs())
	fmt.Fprintf(fw, "\n")
	if option.Config.EnableIPv6 {
		fw.WriteString(dumpRaw(defaults.RestoreV6Addr, node.GetIPv6Router()))
	}
	fw.WriteString(dumpRaw(defaults.RestoreV4Addr, node.GetInternalIPv4()))
	fmt.Fprintf(fw, " */\n\n")

	cDefinesMap["KERNEL_HZ"] = fmt.Sprintf("%d", option.Config.KernelHz)

	if option.Config.EnableIPv6 {
		extraMacrosMap["ROUTER_IP"] = routerIP.String()
		fw.WriteString(defineIPv6("ROUTER_IP", routerIP))
	}

	if option.Config.EnableIPv4 {
		ipv4GW := node.GetInternalIPv4()
		loopbackIPv4 := node.GetIPv4Loopback()
		ipv4Range := node.GetIPv4AllocRange()
		cDefinesMap["IPV4_GATEWAY"] = fmt.Sprintf("%#x", byteorder.HostSliceToNetwork(ipv4GW, reflect.Uint32).(uint32))
		cDefinesMap["IPV4_LOOPBACK"] = fmt.Sprintf("%#x", byteorder.HostSliceToNetwork(loopbackIPv4, reflect.Uint32).(uint32))
		cDefinesMap["IPV4_MASK"] = fmt.Sprintf("%#x", byteorder.HostSliceToNetwork(ipv4Range.Mask, reflect.Uint32).(uint32))

		if option.Config.EnableIPv4FragmentsTracking {
			cDefinesMap["ENABLE_IPV4_FRAGMENTS"] = "1"
			cDefinesMap["IPV4_FRAG_DATAGRAMS_MAP"] = fragmap.MapName
			cDefinesMap["CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", option.Config.FragmentsMapEntries)
		}
	}

	if nat46Range := option.Config.NAT46Prefix; nat46Range != nil {
		fw.WriteString(FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	if option.Config.EnableIPv6 {
		extraMacrosMap["HOST_IP"] = hostIP.String()
		fw.WriteString(defineIPv6("HOST_IP", hostIP))
	}

	cDefinesMap["HOST_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHost))
	cDefinesMap["WORLD_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorld))
	cDefinesMap["HEALTH_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHealth))
	cDefinesMap["UNMANAGED_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameUnmanaged))
	cDefinesMap["INIT_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameInit))
	cDefinesMap["REMOTE_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameRemoteNode))
	cDefinesMap["CILIUM_LB_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.MaxEntries)
	cDefinesMap["TUNNEL_MAP"] = tunnel.MapName
	cDefinesMap["TUNNEL_ENDPOINT_MAP_SIZE"] = fmt.Sprintf("%d", tunnel.MaxEntries)
	cDefinesMap["ENDPOINTS_MAP"] = lxcmap.MapName
	cDefinesMap["ENDPOINTS_MAP_SIZE"] = fmt.Sprintf("%d", lxcmap.MaxEntries)
	cDefinesMap["METRICS_MAP"] = metricsmap.MapName
	cDefinesMap["METRICS_MAP_SIZE"] = fmt.Sprintf("%d", metricsmap.MaxEntries)
	cDefinesMap["POLICY_MAP_SIZE"] = fmt.Sprintf("%d", policymap.MaxEntries)
	cDefinesMap["IPCACHE_MAP"] = ipcachemap.Name
	cDefinesMap["IPCACHE_MAP_SIZE"] = fmt.Sprintf("%d", ipcachemap.MaxEntries)
	cDefinesMap["POLICY_PROG_MAP_SIZE"] = fmt.Sprintf("%d", policymap.PolicyCallMaxEntries)
	cDefinesMap["SOCKOPS_MAP_SIZE"] = fmt.Sprintf("%d", sockmap.MaxEntries)
	cDefinesMap["ENCRYPT_MAP"] = encrypt.MapName
	cDefinesMap["CT_CONNECTION_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutTCP.Seconds()))
	cDefinesMap["CT_CONNECTION_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutAny.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCP.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCAny.Seconds()))
	cDefinesMap["CT_SYN_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSYN.Seconds()))
	cDefinesMap["CT_CLOSE_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutFIN.Seconds()))
	cDefinesMap["CT_REPORT_INTERVAL"] = fmt.Sprintf("%d", int64(option.Config.MonitorAggregationInterval.Seconds()))
	cDefinesMap["CT_REPORT_FLAGS"] = fmt.Sprintf("%#04x", int64(option.Config.MonitorAggregationFlags))

	if option.Config.DatapathMode == datapathOption.DatapathModeIpvlan {
		cDefinesMap["ENABLE_SECCTX_FROM_IPCACHE"] = "1"
		cDefinesMap["ENABLE_EXTRA_HOST_DEV"] = "1"
	}

	if option.Config.PreAllocateMaps {
		cDefinesMap["PREALLOCATE_MAPS"] = "1"
	}

	cDefinesMap["EVENTS_MAP"] = eventsmap.MapName
	cDefinesMap["SIGNAL_MAP"] = signalmap.MapName
	cDefinesMap["POLICY_CALL_MAP"] = policymap.PolicyCallMapName
	cDefinesMap["EP_POLICY_MAP"] = eppolicymap.MapName
	cDefinesMap["LB6_REVERSE_NAT_MAP"] = "cilium_lb6_reverse_nat"
	cDefinesMap["LB6_SERVICES_MAP_V2"] = "cilium_lb6_services_v2"
	cDefinesMap["LB6_BACKEND_MAP"] = "cilium_lb6_backends"
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat6MapName
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat6MapEntries)
	cDefinesMap["LB4_REVERSE_NAT_MAP"] = "cilium_lb4_reverse_nat"
	cDefinesMap["LB4_SERVICES_MAP_V2"] = "cilium_lb4_services_v2"
	cDefinesMap["LB4_BACKEND_MAP"] = "cilium_lb4_backends"
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat4MapName
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat4MapEntries)

	if option.Config.EnableSessionAffinity {
		cDefinesMap["ENABLE_SESSION_AFFINITY"] = "1"
		cDefinesMap["LB_AFFINITY_MATCH_MAP"] = lbmap.AffinityMatchMapName
		if option.Config.EnableIPv4 {
			cDefinesMap["LB4_AFFINITY_MAP"] = lbmap.Affinity4MapName
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["LB6_AFFINITY_MAP"] = lbmap.Affinity6MapName
		}
	}

	cDefinesMap["TRACE_PAYLOAD_LEN"] = fmt.Sprintf("%dULL", option.Config.TracePayloadlen)
	cDefinesMap["MTU"] = fmt.Sprintf("%d", cfg.MtuConfig.GetDeviceMTU())

	if option.Config.EnableIPv4 {
		cDefinesMap["ENABLE_IPV4"] = "1"
	}

	if option.Config.EnableIPv6 {
		cDefinesMap["ENABLE_IPV6"] = "1"
	}

	if option.Config.EnableIPSec {
		cDefinesMap["ENABLE_IPSEC"] = "1"
	}

	if option.Config.InstallIptRules || iptables.KernelHasNetfilter() {
		cDefinesMap["NO_REDIRECT"] = "1"
	}

	if option.Config.EncryptNode {
		cDefinesMap["ENCRYPT_NODE"] = "1"
	}

	if option.Config.DevicePreFilter != "undefined" {
		cDefinesMap["ENABLE_PREFILTER"] = "1"
	}

	if !option.Config.DisableK8sServices {
		cDefinesMap["ENABLE_SERVICES"] = "1"
	}

	if option.Config.EnableHostReachableServices {
		if option.Config.EnableHostServicesTCP {
			cDefinesMap["ENABLE_HOST_SERVICES_TCP"] = "1"
		}
		if option.Config.EnableHostServicesUDP {
			cDefinesMap["ENABLE_HOST_SERVICES_UDP"] = "1"
		}
		if option.Config.EnableHostServicesTCP && option.Config.EnableHostServicesUDP {
			cDefinesMap["ENABLE_HOST_SERVICES_FULL"] = "1"
		}
		if option.Config.EnableHostServicesPeer {
			cDefinesMap["ENABLE_HOST_SERVICES_PEER"] = "1"
		}
	}

	if option.Config.EnableNodePort {
		cDefinesMap["ENABLE_NODEPORT"] = "1"
		cDefinesMap["ENABLE_LOADBALANCER"] = "1"

		if option.Config.EnableIPv4 {
			cDefinesMap["NODEPORT_NEIGH4"] = neighborsmap.Map4Name
			cDefinesMap["NODEPORT_NEIGH4_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["NODEPORT_NEIGH6"] = neighborsmap.Map6Name
			cDefinesMap["NODEPORT_NEIGH6_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
		}
		if option.Config.NodePortMode == option.NodePortModeDSR ||
			option.Config.NodePortMode == option.NodePortModeHybrid {
			cDefinesMap["ENABLE_DSR"] = "1"
			if option.Config.NodePortMode == option.NodePortModeHybrid {
				cDefinesMap["ENABLE_DSR_HYBRID"] = "1"
			}
		}
		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			cDefinesMap["ENABLE_NODEPORT_ACCELERATION"] = "1"
		}
		if option.Config.NodePortHairpin {
			cDefinesMap["ENABLE_NODEPORT_HAIRPIN"] = "1"
		}
		if option.Config.EnableExternalIPs {
			cDefinesMap["ENABLE_EXTERNAL_IP"] = "1"
		}
		if option.Config.EnableHostPort {
			cDefinesMap["ENABLE_HOSTPORT"] = "1"
		}

		cDefinesMap["NODEPORT_PORT_MIN"] = fmt.Sprintf("%d", option.Config.NodePortMin)
		cDefinesMap["NODEPORT_PORT_MAX"] = fmt.Sprintf("%d", option.Config.NodePortMax)
		cDefinesMap["NODEPORT_PORT_MIN_NAT"] = fmt.Sprintf("%d", option.Config.NodePortMax+1)
		cDefinesMap["NODEPORT_PORT_MAX_NAT"] = "65535"
	}

	if option.Config.EnableNodePort {
		directRoutingIface := option.Config.DirectRoutingDevice
		directRoutingIfIndex, err := link.GetIfIndex(directRoutingIface)
		if err != nil {
			return err
		}
		cDefinesMap["DIRECT_ROUTING_DEV_IFINDEX"] = fmt.Sprintf("%d", directRoutingIfIndex)

		if option.Config.EnableIPv4 {
			nodePortIPv4Addrs := node.GetNodePortIPv4AddrsWithDevices()
			ipv4 := byteorder.HostSliceToNetwork(nodePortIPv4Addrs[directRoutingIface], reflect.Uint32).(uint32)
			cDefinesMap["IPV4_DIRECT_ROUTING"] = fmt.Sprintf("%d", ipv4)
		}

		if option.Config.EnableIPv6 {
			directRoutingIPv6 := node.GetNodePortIPv6AddrsWithDevices()[directRoutingIface]
			extraMacrosMap["IPV6_DIRECT_ROUTING"] = directRoutingIPv6.String()
			fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", directRoutingIPv6))
		}
	} else {
		var directRoutingIPv6 net.IP
		cDefinesMap["DIRECT_ROUTING_DEV_IFINDEX"] = "0"
		if option.Config.EnableIPv4 {
			cDefinesMap["IPV4_DIRECT_ROUTING"] = "0"
		}
		if option.Config.EnableIPv6 {
			extraMacrosMap["IPV6_DIRECT_ROUTING"] = directRoutingIPv6.String()
			fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", directRoutingIPv6))
		}
	}

	if option.Config.EnableHostFirewall {
		cDefinesMap["ENABLE_HOST_FIREWALL"] = "1"
	}

	if option.Config.EncryptInterface != "" {
		link, err := netlink.LinkByName(option.Config.EncryptInterface)
		if err == nil {
			cDefinesMap["ENCRYPT_IFACE"] = fmt.Sprintf("%d", link.Attrs().Index)

			addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil {
				a := byteorder.HostSliceToNetwork(addr[0].IPNet.IP, reflect.Uint32).(uint32)
				cDefinesMap["IPV4_ENCRYPT_IFACE"] = fmt.Sprintf("%d", a)
			}
		}
	}
	if option.Config.IsPodSubnetsDefined() {
		cDefinesMap["IP_POOLS"] = "1"
	}
	if option.Config.EnableNodePort {
		if option.Config.EnableIPv4 {
			cDefinesMap["SNAT_MAPPING_IPV4"] = nat.MapNameSnat4Global
			cDefinesMap["SNAT_MAPPING_IPV4_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
		}

		if option.Config.EnableIPv6 {
			cDefinesMap["SNAT_MAPPING_IPV6"] = nat.MapNameSnat6Global
			cDefinesMap["SNAT_MAPPING_IPV6_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
		}

		if option.Config.EnableBPFMasquerade && option.Config.EnableIPv4 {
			cDefinesMap["ENABLE_MASQUERADE"] = "1"
			cidr := datapath.RemoteSNATDstAddrExclusionCIDR()
			cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR"] =
				fmt.Sprintf("%#x", byteorder.HostSliceToNetwork(cidr.IP, reflect.Uint32).(uint32))
			ones, _ := cidr.Mask.Size()
			cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR_LEN"] = fmt.Sprintf("%d", ones)

			// ip-masq-agent depends on bpf-masq
			if option.Config.EnableIPMasqAgent {
				cDefinesMap["ENABLE_IP_MASQ_AGENT"] = "1"
				cDefinesMap["IP_MASQ_AGENT_IPV4"] = ipmasq.MapName
			}
		}

		ctmap.WriteBPFMacros(fw, nil)
	}

	if option.Config.PolicyAuditMode {
		cDefinesMap["POLICY_AUDIT_MODE"] = "1"
	}

	if option.Config.AllowICMPFragNeeded {
		cDefinesMap["ALLOW_ICMP_FRAG_NEEDED"] = "1"
	}

	if option.Config.ClockSource == option.ClockSourceJiffies {
		cDefinesMap["ENABLE_JIFFIES"] = "1"
	}

	if option.Config.EnableIdentityMark {
		cDefinesMap["ENABLE_IDENTITY_MARK"] = "1"
	}

	// Since golang maps are unordered, we sort the keys in the map
	// to get a consistent writtern format to the writer. This maintains
	// the consistency when we try to calculate hash for a datapath after
	// writing the config.
	keys := []string{}
	for key := range cDefinesMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		fmt.Fprintf(fw, "#define %s %s\n", key, cDefinesMap[key])
	}

	// Populate cDefinesMap with extraMacrosMap to get all the configuration
	// in the cDefinesMap itself.
	for key, value := range extraMacrosMap {
		cDefinesMap[key] = value
	}

	// Write the JSON encoded config as base64 encoded commented string to
	// the header file.
	jsonBytes, err := json.Marshal(cDefinesMap)
	if err == nil {
		// We don't care if some error occurs while marshaling the map.
		// In such cases we skip embedding the base64 encoded JSON configuration
		// to the writer.
		encodedConfig := base64.StdEncoding.EncodeToString(jsonBytes)
		fmt.Fprintf(fw, "\n// JSON_OUTPUT: %s\n", encodedConfig)
	}

	return fw.Flush()
}

func (h *HeaderfileWriter) writeNetdevConfig(w io.Writer, cfg datapath.DeviceConfiguration) {
	fmt.Fprint(w, cfg.GetOptions().GetFmtList())
	if option.Config.IsFlannelMasterDeviceSet() {
		fmt.Fprint(w, "#define HOST_REDIRECT_TO_INGRESS 1\n")
	}

	// In case the Linux kernel doesn't support LPM map type, pass the set
	// of prefix length for the datapath to lookup the map.
	if !ipcachemap.BackedByLPM() {
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
func (h *HeaderfileWriter) WriteNetdevConfig(w io.Writer, cfg datapath.DeviceConfiguration) error {
	fw := bufio.NewWriter(w)
	h.writeNetdevConfig(fw, cfg)
	return fw.Flush()
}

// writeStaticData writes the endpoint-specific static data defines to the
// specified writer. This must be kept in sync with loader.ELFSubstitutions().
func (h *HeaderfileWriter) writeStaticData(fw io.Writer, e datapath.EndpointConfiguration) {
	if e.IsHost() {
		if option.Config.EnableNodePort {
			// Values defined here are for the host datapath attached to the
			// host device and therefore won't be used. We however need to set
			// non-zero values to prevent the compiler from optimizing them
			// out, because we need to substitute them for host datapaths
			// attached to native devices.
			// When substituting symbols in the object file, we will replace
			// these values with zero for the host device and with the actual
			// values for the native devices.
			fmt.Fprint(fw, "/* Fake values, replaced by 0 for host device and by actual values for native devices. */\n")
			fmt.Fprint(fw, defineUint32("NATIVE_DEV_IFINDEX", 1))
			if option.Config.EnableIPv6 {
				placeholderIPv6 := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
				fmt.Fprint(fw, defineIPv6("IPV6_NODEPORT", placeholderIPv6))
			}
			if option.Config.EnableIPv4 {
				placeholderIPv4 := []byte{1, 1, 1, 1}
				fmt.Fprint(fw, defineIPv4("IPV4_NODEPORT", placeholderIPv4))
			}
			fmt.Fprint(fw, "\n")
		}

		fmt.Fprint(fw, defineUint32("HOST_EP_ID", uint32(e.GetID())))
	} else {
		// We want to ensure that the template BPF program always has "LXC_IP"
		// defined and present as a symbol in the resulting object file after
		// compilation, regardless of whether IPv6 is disabled. Because the type
		// templateCfg hardcodes a dummy IPv6 address (and adheres to the
		// datapath.EndpointConfiguration interface), we can rely on it always
		// having an IPv6 addr. Endpoints however may not have IPv6 addrs if IPv6
		// is disabled. Hence this check prevents us from omitting the "LXC_IP"
		// symbol from the template BPF program. Without this, the following
		// scenario is possible:
		//   1) Enable IPv6 in cilium
		//   2) Create an endpoint (ensure endpoint has an IPv6 addr)
		//   3) Disable IPv6 and restart cilium
		// This results in a template BPF object without an "LXC_IP" defined,
		// __but__ the endpoint still has "LXC_IP" defined. This causes a later
		// call to loader.ELFSubstitutions() to fail on missing a symbol "LXC_IP".
		if e.IPv6Address() != nil {
			fmt.Fprint(fw, defineIPv6("LXC_IP", e.IPv6Address()))
		}

		fmt.Fprint(fw, defineIPv4("LXC_IPV4", e.IPv4Address()))
		fmt.Fprint(fw, defineUint32("LXC_ID", uint32(e.GetID())))
	}

	fmt.Fprint(fw, defineMAC("NODE_MAC", e.GetNodeMAC()))

	secID := e.GetIdentityLocked().Uint32()
	fmt.Fprintf(fw, defineUint32("SECLABEL", secID))
	fmt.Fprintf(fw, defineUint32("SECLABEL_NB", byteorder.HostToNetwork(secID).(uint32)))
	fmt.Fprintf(fw, defineUint32("POLICY_VERDICT_LOG_FILTER", e.GetPolicyVerdictLogFilter()))

	epID := uint16(e.GetID())
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", bpf.LocalMapName(policymap.MapName, epID))
	callsMapName := callsmap.MapName
	if e.IsHost() {
		callsMapName = callsmap.HostMapName
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", bpf.LocalMapName(callsMapName, epID))
}

// WriteEndpointConfig writes the BPF configuration for the endpoint to a writer.
func (h *HeaderfileWriter) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)

	writeIncludes(w)
	h.writeStaticData(fw, e)

	return h.writeTemplateConfig(fw, e)
}

func (h *HeaderfileWriter) writeTemplateConfig(fw *bufio.Writer, e datapath.EndpointConfiguration) error {
	if e.RequireEgressProg() {
		fmt.Fprintf(fw, "#define USE_BPF_PROG_FOR_INGRESS_POLICY 1\n")
	}

	if option.Config.ForceLocalPolicyEvalAtSource {
		fmt.Fprintf(fw, "#define FORCE_LOCAL_POLICY_EVAL_AT_SOURCE 1\n")
	}

	if e.RequireRouting() {
		fmt.Fprintf(fw, "#define ENABLE_ROUTING 1\n")
	}

	if e.IsHost() {
		// Only used to differentiate between host endpoint template and other templates.
		fmt.Fprintf(fw, "#define HOST_ENDPOINT 1\n")
		if option.Config.EnableNodePort {
			fmt.Fprintf(fw, "#define DISABLE_LOOPBACK_LB 1\n")
		}
	}

	if !e.HasIpvlanDataPath() {
		if e.RequireARPPassthrough() {
			fmt.Fprint(fw, "#define ENABLE_ARP_PASSTHROUGH 1\n")
		} else {
			fmt.Fprint(fw, "#define ENABLE_ARP_RESPONDER 1\n")
		}

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

	// Local delivery metrics should always be set for endpoint programs.
	fmt.Fprint(fw, "#define LOCAL_DELIVERY_METRICS 1\n")

	h.writeNetdevConfig(fw, e)

	return fw.Flush()
}

// WriteTemplateConfig writes the BPF configuration for the template to a writer.
func (h *HeaderfileWriter) WriteTemplateConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)
	return h.writeTemplateConfig(fw, e)
}
