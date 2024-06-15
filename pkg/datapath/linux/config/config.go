// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/link"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmetricsmap"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const NodePortMaxNAT = 65535

// HeaderfileWriter is a wrapper type which implements datapath.ConfigWriter.
// It manages writing of configuration of datapath program headerfiles.
type HeaderfileWriter struct {
	log                *slog.Logger
	nodeMap            nodemap.MapV2
	nodeAddressing     datapath.NodeAddressing
	nodeExtraDefines   dpdef.Map
	nodeExtraDefineFns []dpdef.Fn
	sysctl             sysctl.Sysctl
}

func NewHeaderfileWriter(p WriterParams) (datapath.ConfigWriter, error) {
	merged := make(dpdef.Map)
	for _, defines := range p.NodeExtraDefines {
		if err := merged.Merge(defines); err != nil {
			return nil, err
		}
	}
	return &HeaderfileWriter{
		nodeMap:            p.NodeMap,
		nodeAddressing:     p.NodeAddressing,
		nodeExtraDefines:   merged,
		nodeExtraDefineFns: p.NodeExtraDefineFns,
		log:                p.Log,
		sysctl:             p.Sysctl,
	}, nil
}

func writeIncludes(w io.Writer) (int, error) {
	return fmt.Fprintf(w, "#include \"lib/utils.h\"\n\n")
}

// WriteNodeConfig writes the local node configuration to the specified writer.
func (h *HeaderfileWriter) WriteNodeConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration) error {
	extraMacrosMap := make(dpdef.Map)
	cDefinesMap := make(dpdef.Map)

	nativeDevices := cfg.Devices

	fw := bufio.NewWriter(w)

	writeIncludes(w)

	routerIP := cfg.CiliumInternalIPv6
	hostIP := cfg.NodeIPv6

	var ipv4NodePortAddrs, ipv6NodePortAddrs []netip.Addr
	for _, addr := range cfg.NodeAddresses {
		if !addr.NodePort {
			continue
		}
		if addr.Addr.Is4() {
			ipv4NodePortAddrs = append(ipv4NodePortAddrs, addr.Addr)
		} else {
			ipv6NodePortAddrs = append(ipv6NodePortAddrs, addr.Addr)
		}
	}

	fmt.Fprintf(fw, "/*\n")
	if option.Config.EnableIPv6 {
		fmt.Fprintf(fw, " cilium.v6.external.str %s\n", cfg.NodeIPv6.String())
		fmt.Fprintf(fw, " cilium.v6.internal.str %s\n", cfg.CiliumInternalIPv6.String())
		fmt.Fprintf(fw, " cilium.v6.nodeport.str %v\n", ipv6NodePortAddrs)
		fmt.Fprintf(fw, "\n")
	}
	fmt.Fprintf(fw, " cilium.v4.external.str %s\n", cfg.NodeIPv4.String())
	fmt.Fprintf(fw, " cilium.v4.internal.str %s\n", cfg.CiliumInternalIPv4.String())
	fmt.Fprintf(fw, " cilium.v4.nodeport.str %v\n", ipv4NodePortAddrs)
	fmt.Fprintf(fw, "\n")
	if option.Config.EnableIPv6 {
		fw.WriteString(dumpRaw(defaults.RestoreV6Addr, cfg.CiliumInternalIPv6))
	}
	fw.WriteString(dumpRaw(defaults.RestoreV4Addr, cfg.CiliumInternalIPv4))
	fmt.Fprintf(fw, " */\n\n")

	cDefinesMap["KERNEL_HZ"] = fmt.Sprintf("%d", option.Config.KernelHz)

	if option.Config.EnableIPv6 {
		extraMacrosMap["ROUTER_IP"] = routerIP.String()
		fw.WriteString(defineIPv6("ROUTER_IP", routerIP))
	}

	if option.Config.EnableIPv4 {
		ipv4GW := cfg.CiliumInternalIPv4
		loopbackIPv4 := cfg.LoopbackIPv4
		ipv4Range := cfg.AllocCIDRIPv4
		cDefinesMap["IPV4_GATEWAY"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(ipv4GW))
		cDefinesMap["IPV4_LOOPBACK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(loopbackIPv4))
		cDefinesMap["IPV4_MASK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(net.IP(ipv4Range.Mask)))

		if option.Config.EnableIPv4FragmentsTracking {
			cDefinesMap["ENABLE_IPV4_FRAGMENTS"] = "1"
			cDefinesMap["IPV4_FRAG_DATAGRAMS_MAP"] = fragmap.MapName
			cDefinesMap["CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", option.Config.FragmentsMapEntries)
		}
	}

	if option.Config.EnableIPv6 {
		extraMacrosMap["HOST_IP"] = hostIP.String()
		fw.WriteString(defineIPv6("HOST_IP", hostIP))
	}

	cDefinesMap["UNKNOWN_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameUnknown))
	cDefinesMap["HOST_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHost))
	cDefinesMap["WORLD_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorld))
	if option.Config.IsDualStack() {
		cDefinesMap["WORLD_IPV4_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorldIPv4))
		cDefinesMap["WORLD_IPV6_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameWorldIPv6))
	} else {
		worldID := identity.GetReservedID(labels.IDNameWorld)
		cDefinesMap["WORLD_IPV4_ID"] = fmt.Sprintf("%d", worldID)
		cDefinesMap["WORLD_IPV6_ID"] = fmt.Sprintf("%d", worldID)
	}
	cDefinesMap["HEALTH_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameHealth))
	cDefinesMap["UNMANAGED_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameUnmanaged))
	cDefinesMap["INIT_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameInit))
	cDefinesMap["LOCAL_NODE_ID"] = fmt.Sprintf("%d", identity.GetLocalNodeID())
	cDefinesMap["REMOTE_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameRemoteNode))
	cDefinesMap["KUBE_APISERVER_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameKubeAPIServer))
	cDefinesMap["ENCRYPTED_OVERLAY_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameEncryptedOverlay))
	cDefinesMap["CILIUM_LB_SERVICE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.ServiceMapMaxEntries)
	cDefinesMap["CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.ServiceBackEndMapMaxEntries)
	cDefinesMap["CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.RevNatMapMaxEntries)
	cDefinesMap["CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.AffinityMapMaxEntries)
	cDefinesMap["CILIUM_LB_SOURCE_RANGE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.SourceRangeMapMaxEntries)
	cDefinesMap["CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.MaglevMapMaxEntries)
	cDefinesMap["CILIUM_LB_SKIP_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmap.SkipLBMapMaxEntries)

	cDefinesMap["TUNNEL_MAP"] = tunnel.MapName
	cDefinesMap["TUNNEL_ENDPOINT_MAP_SIZE"] = fmt.Sprintf("%d", tunnel.MaxEntries)
	cDefinesMap["ENDPOINTS_MAP"] = lxcmap.MapName
	cDefinesMap["ENDPOINTS_MAP_SIZE"] = fmt.Sprintf("%d", lxcmap.MaxEntries)
	cDefinesMap["METRICS_MAP"] = metricsmap.MapName
	cDefinesMap["METRICS_MAP_SIZE"] = fmt.Sprintf("%d", metricsmap.MaxEntries)
	cDefinesMap["POLICY_MAP_SIZE"] = fmt.Sprintf("%d", policymap.MaxEntries)
	cDefinesMap["AUTH_MAP"] = authmap.MapName
	cDefinesMap["AUTH_MAP_SIZE"] = fmt.Sprintf("%d", option.Config.AuthMapEntries)
	cDefinesMap["CONFIG_MAP"] = configmap.MapName
	cDefinesMap["CONFIG_MAP_SIZE"] = fmt.Sprintf("%d", configmap.MaxEntries)
	cDefinesMap["IPCACHE_MAP"] = ipcachemap.Name
	cDefinesMap["IPCACHE_MAP_SIZE"] = fmt.Sprintf("%d", ipcachemap.MaxEntries)
	cDefinesMap["NODE_MAP"] = nodemap.MapName
	cDefinesMap["NODE_MAP_V2"] = nodemap.MapNameV2
	cDefinesMap["NODE_MAP_SIZE"] = fmt.Sprintf("%d", h.nodeMap.Size())
	cDefinesMap["WORLD_CIDRS4_MAP"] = worldcidrsmap.MapName4
	cDefinesMap["WORLD_CIDRS4_MAP_SIZE"] = fmt.Sprintf("%d", worldcidrsmap.MapMaxEntries)
	cDefinesMap["POLICY_PROG_MAP_SIZE"] = fmt.Sprintf("%d", policymap.PolicyCallMaxEntries)
	cDefinesMap["L2_RESPONSER_MAP4_SIZE"] = fmt.Sprintf("%d", l2respondermap.DefaultMaxEntries)

	if option.Config.EnableIPSec {
		cDefinesMap["ENCRYPT_MAP"] = encrypt.MapName
	}

	cDefinesMap["L2_RESPONDER_MAP4"] = l2respondermap.MapName
	cDefinesMap["CT_CONNECTION_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutTCP.Seconds()))
	cDefinesMap["CT_CONNECTION_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutAny.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCP.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCAny.Seconds()))
	cDefinesMap["CT_SERVICE_CLOSE_REBALANCE"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCPGrace.Seconds()))
	cDefinesMap["CT_SYN_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSYN.Seconds()))
	cDefinesMap["CT_CLOSE_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutFIN.Seconds()))
	cDefinesMap["CT_REPORT_INTERVAL"] = fmt.Sprintf("%d", int64(option.Config.MonitorAggregationInterval.Seconds()))
	cDefinesMap["CT_REPORT_FLAGS"] = fmt.Sprintf("%#04x", int64(option.Config.MonitorAggregationFlags))
	cDefinesMap["RATELIMIT_MAP"] = "cilium_ratelimit"
	cDefinesMap["RATELIMIT_METRICS_MAP"] = ratelimitmetricsmap.MapName
	cDefinesMap["CT_TAIL_CALL_BUFFER4"] = "cilium_tail_call_buffer4"
	cDefinesMap["CT_TAIL_CALL_BUFFER6"] = "cilium_tail_call_buffer6"
	cDefinesMap["PER_CLUSTER_CT_TCP4"] = "cilium_per_cluster_ct_tcp4"
	cDefinesMap["PER_CLUSTER_CT_TCP6"] = "cilium_per_cluster_ct_tcp6"
	cDefinesMap["PER_CLUSTER_CT_ANY4"] = "cilium_per_cluster_ct_any4"
	cDefinesMap["PER_CLUSTER_CT_ANY6"] = "cilium_per_cluster_ct_any6"
	cDefinesMap["PER_CLUSTER_SNAT_MAPPING_IPV4"] = "cilium_per_cluster_snat_v4_external"
	cDefinesMap["PER_CLUSTER_SNAT_MAPPING_IPV6"] = "cilium_per_cluster_snat_v6_external"

	if option.Config.PreAllocateMaps {
		cDefinesMap["PREALLOCATE_MAPS"] = "1"
	}

	cDefinesMap["EVENTS_MAP"] = eventsmap.MapName
	cDefinesMap["EVENTS_MAP_RATE_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultRateLimit)
	cDefinesMap["EVENTS_MAP_BURST_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultBurstLimit)
	cDefinesMap["SIGNAL_MAP"] = signalmap.MapName
	cDefinesMap["POLICY_CALL_MAP"] = policymap.PolicyCallMapName
	if option.Config.EnableEnvoyConfig {
		cDefinesMap["POLICY_EGRESSCALL_MAP"] = policymap.PolicyEgressCallMapName
	}
	cDefinesMap["LB6_REVERSE_NAT_MAP"] = "cilium_lb6_reverse_nat"
	cDefinesMap["LB6_SERVICES_MAP_V2"] = "cilium_lb6_services_v2"
	cDefinesMap["LB6_BACKEND_MAP"] = "cilium_lb6_backends_v3"
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat6MapName
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat6MapEntries)
	cDefinesMap["LB4_REVERSE_NAT_MAP"] = "cilium_lb4_reverse_nat"
	cDefinesMap["LB4_SERVICES_MAP_V2"] = "cilium_lb4_services_v2"
	cDefinesMap["LB4_BACKEND_MAP"] = "cilium_lb4_backends_v3"
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP"] = lbmap.SockRevNat4MapName
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", lbmap.MaxSockRevNat4MapEntries)
	cDefinesMap["LB4_SKIP_MAP"] = lbmap.SkipLB4MapName

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
	cDefinesMap["MTU"] = fmt.Sprintf("%d", cfg.DeviceMTU)

	if option.Config.EnableIPv4 {
		cDefinesMap["ENABLE_IPV4"] = "1"
	}

	if option.Config.EnableIPv6 {
		cDefinesMap["ENABLE_IPV6"] = "1"
	}

	if option.Config.EnableSRv6 {
		cDefinesMap["ENABLE_SRV6"] = "1"
		if option.Config.SRv6EncapMode != "reduced" {
			cDefinesMap["ENABLE_SRV6_SRH_ENCAP"] = "1"
		}
	}

	if option.Config.EnableSCTP {
		cDefinesMap["ENABLE_SCTP"] = "1"
	}

	if option.Config.EnableIPSec {
		cDefinesMap["ENABLE_IPSEC"] = "1"

		if option.Config.EnableIPSecEncryptedOverlay {
			cDefinesMap["ENABLE_ENCRYPTED_OVERLAY"] = "1"
		}
	}

	if option.Config.EnableWireguard {
		cDefinesMap["ENABLE_WIREGUARD"] = "1"
		ifindex, err := link.GetIfIndex(wgtypes.IfaceName)
		if err != nil {
			return err
		}
		cDefinesMap["WG_IFINDEX"] = fmt.Sprintf("%d", ifindex)

		if option.Config.EncryptNode {
			cDefinesMap["ENABLE_NODE_ENCRYPTION"] = "1"
		}
	}

	if option.Config.ServiceNoBackendResponse == option.ServiceNoBackendResponseReject {
		cDefinesMap["SERVICE_NO_BACKEND_RESPONSE"] = "1"
	}

	if option.Config.EnableL2Announcements {
		cDefinesMap["ENABLE_L2_ANNOUNCEMENTS"] = "1"
		// If the agent is down for longer than the lease duration, stop responding
		cDefinesMap["L2_ANNOUNCEMENTS_MAX_LIVENESS"] = fmt.Sprintf("%dULL", option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	if option.Config.EnableEncryptionStrictMode {
		cDefinesMap["ENCRYPTION_STRICT_MODE"] = "1"

		// when parsing the user input we only accept ipv4 addresses
		cDefinesMap["STRICT_IPV4_NET"] = fmt.Sprintf("%#x", byteorder.NetIPAddrToHost32(option.Config.EncryptionStrictModeCIDR.Addr()))
		cDefinesMap["STRICT_IPV4_NET_SIZE"] = fmt.Sprintf("%d", option.Config.EncryptionStrictModeCIDR.Bits())

		cDefinesMap["IPV4_ENCRYPT_IFACE"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(cfg.NodeIPv4))

		ipv4Interface, ok := netip.AddrFromSlice(cfg.NodeIPv4.To4())
		if !ok {
			return fmt.Errorf("unable to parse node IPv4 address %s", cfg.NodeIPv4)
		}

		if option.Config.EncryptionStrictModeCIDR.Contains(ipv4Interface) {
			if !option.Config.EncryptionStrictModeAllowRemoteNodeIdentities {
				return fmt.Errorf(`encryption strict mode is enabled but the node's IPv4 address is within the strict CIDR range.
				This will cause the node to drop all traffic.
				Please either disable encryption or set --encryption-strict-mode-allow-dynamic-lookup=true`)
			}
			cDefinesMap["STRICT_IPV4_OVERLAPPING_CIDR"] = "1"
		}
	}

	if option.Config.EnableBPFTProxy {
		cDefinesMap["ENABLE_TPROXY"] = "1"
	}

	if option.Config.EnableXDPPrefilter {
		cDefinesMap["ENABLE_PREFILTER"] = "1"
	}

	if option.Config.EnableEndpointRoutes {
		cDefinesMap["ENABLE_ENDPOINT_ROUTES"] = "1"
	}

	if option.Config.EnableEnvoyConfig {
		cDefinesMap["ENABLE_L7_LB"] = "1"
	}

	if option.Config.EnableSocketLB {
		if option.Config.BPFSocketLBHostnsOnly {
			cDefinesMap["ENABLE_SOCKET_LB_HOST_ONLY"] = "1"
		} else {
			cDefinesMap["ENABLE_SOCKET_LB_FULL"] = "1"
		}
		if option.Config.EnableSocketLBPeer {
			cDefinesMap["ENABLE_SOCKET_LB_PEER"] = "1"
		}
		if option.Config.EnableSocketLBTracing {
			cDefinesMap["TRACE_SOCK_NOTIFY"] = "1"
		}

		if cookie, err := netns.GetNetNSCookie(); err == nil {
			// When running in nested environments (e.g. Kind), cilium-agent does
			// not run in the host netns. So, in such cases the cookie comparison
			// based on bpf_get_netns_cookie(NULL) for checking whether a socket
			// belongs to a host netns does not work.
			//
			// To fix this, we derive the cookie of the netns in which cilium-agent
			// runs via getsockopt(...SO_NETNS_COOKIE...) and then use it in the
			// check above. This is based on an assumption that cilium-agent
			// always runs with "hostNetwork: true".
			cDefinesMap["HOST_NETNS_COOKIE"] = fmt.Sprintf("%d", cookie)
		}

		if option.Config.EnableLocalRedirectPolicy {
			cDefinesMap["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
		}
	}

	cDefinesMap["NAT_46X64_PREFIX_0"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_1"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_2"] = "0"
	cDefinesMap["NAT_46X64_PREFIX_3"] = "0"

	if option.Config.EnableNodePort {
		if option.Config.EnableHealthDatapath {
			cDefinesMap["ENABLE_HEALTH_CHECK"] = "1"
		}
		if option.Config.EnableMKE && option.Config.EnableSocketLB {
			cDefinesMap["ENABLE_MKE"] = "1"
			cDefinesMap["MKE_HOST"] = fmt.Sprintf("%d", option.HostExtensionMKE)
		}
		if option.Config.EnableRecorder {
			cDefinesMap["ENABLE_CAPTURE"] = "1"
			if option.Config.EnableIPv4 {
				cDefinesMap["CAPTURE4_RULES"] = recorder.MapNameWcard4
				cDefinesMap["CAPTURE4_SIZE"] = fmt.Sprintf("%d", recorder.MapSize)
			}
			if option.Config.EnableIPv6 {
				cDefinesMap["CAPTURE6_RULES"] = recorder.MapNameWcard6
				cDefinesMap["CAPTURE6_SIZE"] = fmt.Sprintf("%d", recorder.MapSize)
			}
		}
		cDefinesMap["ENABLE_NODEPORT"] = "1"
		if option.Config.EnableIPv4 {
			cDefinesMap["NODEPORT_NEIGH4"] = neighborsmap.Map4Name
			cDefinesMap["NODEPORT_NEIGH4_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
			if option.Config.EnableHealthDatapath {
				cDefinesMap["LB4_HEALTH_MAP"] = lbmap.HealthProbe4MapName
			}
		}
		if option.Config.EnableIPv6 {
			cDefinesMap["NODEPORT_NEIGH6"] = neighborsmap.Map6Name
			cDefinesMap["NODEPORT_NEIGH6_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
			if option.Config.EnableHealthDatapath {
				cDefinesMap["LB6_HEALTH_MAP"] = lbmap.HealthProbe6MapName
			}
		}
		if option.Config.EnableNat46X64Gateway {
			cDefinesMap["ENABLE_NAT_46X64_GATEWAY"] = "1"
			base := option.Config.IPv6NAT46x64CIDRBase.AsSlice()
			cDefinesMap["NAT_46X64_PREFIX_0"] = fmt.Sprintf("%d", base[0])
			cDefinesMap["NAT_46X64_PREFIX_1"] = fmt.Sprintf("%d", base[1])
			cDefinesMap["NAT_46X64_PREFIX_2"] = fmt.Sprintf("%d", base[2])
			cDefinesMap["NAT_46X64_PREFIX_3"] = fmt.Sprintf("%d", base[3])
		}
		if option.Config.NodePortNat46X64 {
			cDefinesMap["ENABLE_NAT_46X64"] = "1"
		}
		const (
			dsrEncapInv = iota
			dsrEncapNone
			dsrEncapIPIP
			dsrEncapGeneve
		)
		const (
			dsrL4XlateInv = iota
			dsrL4XlateFrontend
			dsrL4XlateBackend
		)
		cDefinesMap["DSR_ENCAP_IPIP"] = fmt.Sprintf("%d", dsrEncapIPIP)
		cDefinesMap["DSR_ENCAP_GENEVE"] = fmt.Sprintf("%d", dsrEncapGeneve)
		cDefinesMap["DSR_ENCAP_NONE"] = fmt.Sprintf("%d", dsrEncapNone)
		cDefinesMap["DSR_XLATE_FRONTEND"] = fmt.Sprintf("%d", dsrL4XlateFrontend)
		cDefinesMap["DSR_XLATE_BACKEND"] = fmt.Sprintf("%d", dsrL4XlateBackend)
		if option.Config.LoadBalancerUsesDSR() {
			cDefinesMap["ENABLE_DSR"] = "1"
			if option.Config.EnablePMTUDiscovery {
				cDefinesMap["ENABLE_DSR_ICMP_ERRORS"] = "1"
			}
			if option.Config.NodePortMode == option.NodePortModeHybrid {
				cDefinesMap["ENABLE_DSR_HYBRID"] = "1"
			}
			if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchOption {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapNone)
			} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapIPIP)
			} else if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchGeneve {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapGeneve)
			}
			if option.Config.LoadBalancerDSRDispatch == option.DSRDispatchIPIP {
				if option.Config.LoadBalancerDSRL4Xlate == option.DSRL4XlateFrontend {
					cDefinesMap["DSR_XLATE_MODE"] = fmt.Sprintf("%d", dsrL4XlateFrontend)
				} else if option.Config.LoadBalancerDSRL4Xlate == option.DSRL4XlateBackend {
					cDefinesMap["DSR_XLATE_MODE"] = fmt.Sprintf("%d", dsrL4XlateBackend)
				}
			} else {
				cDefinesMap["DSR_XLATE_MODE"] = fmt.Sprintf("%d", dsrL4XlateInv)
			}
		} else {
			cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapInv)
			cDefinesMap["DSR_XLATE_MODE"] = fmt.Sprintf("%d", dsrL4XlateInv)
		}
		if option.Config.EnableIPv4 {
			if option.Config.LoadBalancerRSSv4CIDR != "" {
				ipv4 := byteorder.NetIPv4ToHost32(option.Config.LoadBalancerRSSv4.IP)
				ones, _ := option.Config.LoadBalancerRSSv4.Mask.Size()
				cDefinesMap["IPV4_RSS_PREFIX"] = fmt.Sprintf("%d", ipv4)
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = fmt.Sprintf("%d", ones)
			} else {
				cDefinesMap["IPV4_RSS_PREFIX"] = "IPV4_DIRECT_ROUTING"
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = "32"
			}
		}
		if option.Config.EnableIPv6 {
			if option.Config.LoadBalancerRSSv6CIDR != "" {
				ipv6 := option.Config.LoadBalancerRSSv6.IP
				ones, _ := option.Config.LoadBalancerRSSv6.Mask.Size()
				extraMacrosMap["IPV6_RSS_PREFIX"] = ipv6.String()
				fw.WriteString(FmtDefineAddress("IPV6_RSS_PREFIX", ipv6))
				cDefinesMap["IPV6_RSS_PREFIX_BITS"] = fmt.Sprintf("%d", ones)
			} else {
				cDefinesMap["IPV6_RSS_PREFIX"] = "IPV6_DIRECT_ROUTING"
				cDefinesMap["IPV6_RSS_PREFIX_BITS"] = "128"
			}
		}
		if option.Config.NodePortAcceleration != option.NodePortAccelerationDisabled {
			cDefinesMap["ENABLE_NODEPORT_ACCELERATION"] = "1"
		}
		if !option.Config.EnableHostLegacyRouting {
			cDefinesMap["ENABLE_HOST_ROUTING"] = "1"
		}
		if option.Config.EnableSVCSourceRangeCheck {
			cDefinesMap["ENABLE_SRC_RANGE_CHECK"] = "1"
			if option.Config.EnableIPv4 {
				cDefinesMap["LB4_SRC_RANGE_MAP"] = lbmap.SourceRange4MapName
				cDefinesMap["LB4_SRC_RANGE_MAP_SIZE"] =
					fmt.Sprintf("%d", lbmap.SourceRange4Map.MaxEntries())
			}
			if option.Config.EnableIPv6 {
				cDefinesMap["LB6_SRC_RANGE_MAP"] = lbmap.SourceRange6MapName
				cDefinesMap["LB6_SRC_RANGE_MAP_SIZE"] =
					fmt.Sprintf("%d", lbmap.SourceRange6Map.MaxEntries())
			}
		}

		cDefinesMap["NODEPORT_PORT_MIN"] = fmt.Sprintf("%d", option.Config.NodePortMin)
		cDefinesMap["NODEPORT_PORT_MAX"] = fmt.Sprintf("%d", option.Config.NodePortMax)
		cDefinesMap["NODEPORT_PORT_MIN_NAT"] = fmt.Sprintf("%d", option.Config.NodePortMax+1)
		cDefinesMap["NODEPORT_PORT_MAX_NAT"] = strconv.Itoa(NodePortMaxNAT)
	}

	macByIfIndexMacro, isL3DevMacro, err := devMacros(nativeDevices)
	if err != nil {
		return err
	}
	cDefinesMap["NATIVE_DEV_MAC_BY_IFINDEX(IFINDEX)"] = macByIfIndexMacro
	cDefinesMap["IS_L3_DEV(ifindex)"] = isL3DevMacro

	const (
		selectionRandom = iota + 1
		selectionMaglev
	)
	cDefinesMap["LB_SELECTION_RANDOM"] = fmt.Sprintf("%d", selectionRandom)
	cDefinesMap["LB_SELECTION_MAGLEV"] = fmt.Sprintf("%d", selectionMaglev)
	if option.Config.NodePortAlg == option.NodePortAlgRandom {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionRandom)
	} else if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionMaglev)
		cDefinesMap["LB_MAGLEV_LUT_SIZE"] = fmt.Sprintf("%d", option.Config.MaglevTableSize)
		if option.Config.EnableIPv6 {
			cDefinesMap["LB6_MAGLEV_MAP_OUTER"] = lbmap.MaglevOuter6MapName
		}
		if option.Config.EnableIPv4 {
			cDefinesMap["LB4_MAGLEV_MAP_OUTER"] = lbmap.MaglevOuter4MapName
		}
	}
	cDefinesMap["HASH_INIT4_SEED"] = fmt.Sprintf("%d", maglev.SeedJhash0)
	cDefinesMap["HASH_INIT6_SEED"] = fmt.Sprintf("%d", maglev.SeedJhash1)

	if option.Config.DirectRoutingDeviceRequired() {
		drd := cfg.DirectRoutingDevice
		if option.Config.EnableIPv4 {
			if drd == nil {
				return fmt.Errorf("IPv4 direct routing device not found")
			}
			var ipv4 uint32
			for _, addr := range drd.Addrs {
				if addr.Addr.Is4() {
					ipv4 = byteorder.NetIPv4ToHost32(addr.AsIP())
					break
				}
			}
			if ipv4 == 0 {
				return fmt.Errorf("IPv4 direct routing device IP not found")
			}
			cDefinesMap["IPV4_DIRECT_ROUTING"] = fmt.Sprintf("%d", ipv4)
			cDefinesMap["DIRECT_ROUTING_DEV_IFINDEX"] = fmt.Sprintf("%d", drd.Index)
		}
		if option.Config.EnableIPv6 {
			if drd == nil {
				return fmt.Errorf("IPv6 direct routing device not found")
			}

			var ip net.IP
			for _, addr := range drd.Addrs {
				if addr.Addr.Is6() {
					ip = addr.AsIP()
					break
				}
			}
			if ip.IsUnspecified() {
				return fmt.Errorf("IPv6 direct routing device IP not found")
			}
			extraMacrosMap["IPV6_DIRECT_ROUTING"] = ip.String()
			fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", ip))
			cDefinesMap["DIRECT_ROUTING_DEV_IFINDEX"] = fmt.Sprintf("%d", drd.Index)
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

	if option.Config.EnableIPSec {
		nodeAddress := cfg.NodeIPv4
		if nodeAddress == nil {
			return errors.New("external IPv4 node address is required when IPSec is enabled, but none found")
		}

		a := byteorder.NetIPv4ToHost32(nodeAddress)
		cDefinesMap["IPV4_ENCRYPT_IFACE"] = fmt.Sprintf("%d", a)
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

		if option.Config.EnableBPFMasquerade {
			if option.Config.EnableIPv4Masquerade {
				cDefinesMap["ENABLE_MASQUERADE_IPV4"] = "1"

				// ip-masq-agent depends on bpf-masq
				var excludeCIDR *cidr.CIDR
				if option.Config.EnableIPMasqAgent {
					cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV4"] = "1"
					cDefinesMap["IP_MASQ_AGENT_IPV4"] = ipmasq.MapNameIPv4

					// native-routing-cidr is optional with ip-masq-agent and may be nil
					excludeCIDR = option.Config.IPv4NativeRoutingCIDR
				} else {
					excludeCIDR = datapath.RemoteSNATDstAddrExclusionCIDRv4()
				}

				if excludeCIDR != nil {
					cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR"] =
						fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(excludeCIDR.IP))
					ones, _ := excludeCIDR.Mask.Size()
					cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR_LEN"] = fmt.Sprintf("%d", ones)
				}
			}
			if option.Config.EnableIPv6Masquerade {
				cDefinesMap["ENABLE_MASQUERADE_IPV6"] = "1"

				var excludeCIDR *cidr.CIDR
				if option.Config.EnableIPMasqAgent {
					cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV6"] = "1"
					cDefinesMap["IP_MASQ_AGENT_IPV6"] = ipmasq.MapNameIPv6

					excludeCIDR = option.Config.IPv6NativeRoutingCIDR
				} else {
					excludeCIDR = datapath.RemoteSNATDstAddrExclusionCIDRv6()
				}

				if excludeCIDR != nil {
					extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR"] = excludeCIDR.IP.String()
					fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR", excludeCIDR.IP))
					extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR_MASK"] = excludeCIDR.Mask.String()
					fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR_MASK", excludeCIDR.Mask))
				}
			}
		}

		ctmap.WriteBPFMacros(fw, nil)
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

	if option.Config.EnableHighScaleIPcache {
		cDefinesMap["ENABLE_HIGH_SCALE_IPCACHE"] = "1"
	}

	if option.Config.EnableCustomCalls {
		cDefinesMap["ENABLE_CUSTOM_CALLS"] = "1"
	}

	if option.Config.EnableVTEP {
		cDefinesMap["ENABLE_VTEP"] = "1"
		cDefinesMap["VTEP_MAP"] = vtep.Name
		cDefinesMap["VTEP_MAP_SIZE"] = fmt.Sprintf("%d", vtep.MaxEntries)
		cDefinesMap["VTEP_MASK"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask)))

	}

	vlanFilter, err := vlanFilterMacros(nativeDevices)
	if err != nil {
		return err
	}
	cDefinesMap["VLAN_FILTER(ifindex, vlan_id)"] = vlanFilter

	if option.Config.DisableExternalIPMitigation {
		cDefinesMap["DISABLE_EXTERNAL_IP_MITIGATION"] = "1"
	}

	if option.Config.EnableICMPRules {
		cDefinesMap["ENABLE_ICMP_RULE"] = "1"
	}

	cDefinesMap["CIDR_IDENTITY_RANGE_START"] = fmt.Sprintf("%d", identity.MinLocalIdentity)
	cDefinesMap["CIDR_IDENTITY_RANGE_END"] = fmt.Sprintf("%d", identity.MaxLocalIdentity)

	if option.Config.TunnelingEnabled() {
		cDefinesMap["TUNNEL_MODE"] = "1"
	}

	ciliumNetLink, err := netlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return fmt.Errorf("failed to look up link '%s': %w", defaults.SecondHostDevice, err)
	}
	cDefinesMap["CILIUM_NET_MAC"] = fmt.Sprintf("{.addr=%s}", mac.CArrayString(ciliumNetLink.Attrs().HardwareAddr))
	cDefinesMap["HOST_IFINDEX"] = fmt.Sprintf("%d", ciliumNetLink.Attrs().Index)

	ciliumHostLink, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return fmt.Errorf("failed to look up link '%s': %w", defaults.HostDevice, err)
	}
	cDefinesMap["HOST_IFINDEX_MAC"] = fmt.Sprintf("{.addr=%s}", mac.CArrayString(ciliumHostLink.Attrs().HardwareAddr))
	cDefinesMap["CILIUM_IFINDEX"] = fmt.Sprintf("%d", ciliumHostLink.Attrs().Index)

	ephemeralMin, err := getEphemeralPortRangeMin(h.sysctl)
	if err != nil {
		return err
	}
	cDefinesMap["EPHEMERAL_MIN"] = fmt.Sprintf("%d", ephemeralMin)

	if err := cDefinesMap.Merge(h.nodeExtraDefines); err != nil {
		return err
	}

	for _, fn := range h.nodeExtraDefineFns {
		defines, err := fn()
		if err != nil {
			return err
		}

		if err := cDefinesMap.Merge(defines); err != nil {
			return err
		}
	}

	if option.Config.EnableHealthDatapath {
		if option.Config.IPv4Enabled() {
			ipip4, err := netlink.LinkByName(defaults.IPIPv4Device)
			if err != nil {
				return err
			}
			cDefinesMap["ENCAP4_IFINDEX"] = fmt.Sprintf("%d", ipip4.Attrs().Index)
		}
		if option.Config.IPv6Enabled() {
			ipip6, err := netlink.LinkByName(defaults.IPIPv6Device)
			if err != nil {
				return err
			}
			cDefinesMap["ENCAP6_IFINDEX"] = fmt.Sprintf("%d", ipip6.Attrs().Index)
		}
	}

	// Write Identity and ClusterID related macros.
	cDefinesMap["CLUSTER_ID_MAX"] = fmt.Sprintf("%d", option.Config.MaxConnectedClusters)

	fmt.Fprint(fw, declareConfig("identity_length", identity.GetClusterIDShift(), "Identity length in bits"))
	fmt.Fprint(fw, assignConfig("identity_length", identity.GetClusterIDShift()))

	// Since golang maps are unordered, we sort the keys in the map
	// to get a consistent written format to the writer. This maintains
	// the consistency when we try to calculate hash for a datapath after
	// writing the config.
	keys := make([]string, 0, len(cDefinesMap))
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

func getEphemeralPortRangeMin(sysctl sysctl.Sysctl) (int, error) {
	ephemeralPortRangeStr, err := sysctl.Read("net.ipv4.ip_local_port_range")
	if err != nil {
		return 0, fmt.Errorf("unable to read net.ipv4.ip_local_port_range: %w", err)
	}
	ephemeralPortRange := strings.Split(ephemeralPortRangeStr, "\t")
	if len(ephemeralPortRange) != 2 {
		return 0, fmt.Errorf("invalid ephemeral port range: %s", ephemeralPortRangeStr)
	}
	ephemeralPortMin, err := strconv.Atoi(ephemeralPortRange[0])
	if err != nil {
		return 0, fmt.Errorf("unable to parse min port value %s for ephemeral range: %w",
			ephemeralPortRange[0], err)
	}

	return ephemeralPortMin, nil
}

// vlanFilterMacros generates VLAN_FILTER macros which
// are written to node_config.h
func vlanFilterMacros(nativeDevices []*tables.Device) (string, error) {
	devices := make(map[int]bool)
	for _, device := range nativeDevices {
		devices[device.Index] = true
	}

	allowedVlans := make(map[int]bool)
	for _, vlanId := range option.Config.VLANBPFBypass {
		allowedVlans[vlanId] = true
	}

	// allow all vlan id's
	if allowedVlans[0] {
		return "return true", nil
	}

	vlansByIfIndex := make(map[int][]int)

	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, l := range links {
		vlan, ok := l.(*netlink.Vlan)
		// if it's vlan device and we're controlling vlan main device
		// and either all vlans are allowed, or we're controlling vlan device or vlan is explicitly allowed
		if ok && devices[vlan.ParentIndex] && (devices[vlan.Index] || allowedVlans[vlan.VlanId]) {
			vlansByIfIndex[vlan.ParentIndex] = append(vlansByIfIndex[vlan.ParentIndex], vlan.VlanId)
		}
	}

	vlansCount := 0
	for _, v := range vlansByIfIndex {
		vlansCount += len(v)
		sort.Ints(v) // sort Vlanids in-place since netlink.LinkList() may return them in any order
	}

	if vlansCount == 0 {
		return "return false", nil
	} else if vlansCount > 5 {
		return "", fmt.Errorf("allowed VLAN list is too big - %d entries, please use '--vlan-bpf-bypass 0' in order to allow all available VLANs", vlansCount)
	} else {
		vlanFilterTmpl := template.Must(template.New("vlanFilter").Parse(
			`switch (ifindex) { \
{{range $ifindex,$vlans := . -}} case {{$ifindex}}: \
switch (vlan_id) { \
{{range $vlan := $vlans -}} case {{$vlan}}: \
{{end}}return true; \
} \
break; \
{{end}}} \
return false;`))

		var vlanFilterMacro bytes.Buffer
		if err := vlanFilterTmpl.Execute(&vlanFilterMacro, vlansByIfIndex); err != nil {
			return "", fmt.Errorf("failed to execute template: %w", err)
		}

		return vlanFilterMacro.String(), nil
	}
}

// devMacros generates NATIVE_DEV_MAC_BY_IFINDEX and IS_L3_DEV macros which
// are written to node_config.h.
func devMacros(devs []*tables.Device) (string, string, error) {
	var (
		macByIfIndexMacro, isL3DevMacroBuf bytes.Buffer
		isL3DevMacro                       string
	)
	macByIfIndex := make(map[int]string)
	l3DevIfIndices := make([]int, 0)

	for _, dev := range devs {
		if len(dev.HardwareAddr) != 6 {
			l3DevIfIndices = append(l3DevIfIndices, dev.Index)
		}
		macByIfIndex[dev.Index] = mac.CArrayString(net.HardwareAddr(dev.HardwareAddr))
	}

	macByIfindexTmpl := template.Must(template.New("macByIfIndex").Parse(
		`({ \
union macaddr __mac = {.addr = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}; \
switch (IFINDEX) { \
{{range $idx,$mac := .}} case {{$idx}}: {union macaddr __tmp = {.addr = {{$mac}}}; __mac=__tmp;} break; \
{{end}}} \
__mac; })`))

	if err := macByIfindexTmpl.Execute(&macByIfIndexMacro, macByIfIndex); err != nil {
		return "", "", fmt.Errorf("failed to execute template: %w", err)
	}

	if len(l3DevIfIndices) == 0 {
		isL3DevMacro = "false"
	} else {
		isL3DevTmpl := template.Must(template.New("isL3Dev").Parse(
			`({ \
bool is_l3 = false; \
switch (ifindex) { \
{{range $idx := .}} case {{$idx}}: is_l3 = true; break; \
{{end}}} \
is_l3; })`))
		if err := isL3DevTmpl.Execute(&isL3DevMacroBuf, l3DevIfIndices); err != nil {
			return "", "", fmt.Errorf("failed to execute template: %w", err)
		}
		isL3DevMacro = isL3DevMacroBuf.String()
	}

	return macByIfIndexMacro.String(), isL3DevMacro, nil
}

func (h *HeaderfileWriter) writeNetdevConfig(w io.Writer, opts *option.IntOptions) {
	fmt.Fprint(w, opts.GetFmtList())

	if option.Config.EnableEndpointRoutes {
		fmt.Fprint(w, "#define USE_BPF_PROG_FOR_INGRESS_POLICY 1\n")
	}
}

// WriteNetdevConfig writes the BPF configuration for the endpoint to a writer.
func (h *HeaderfileWriter) WriteNetdevConfig(w io.Writer, opts *option.IntOptions) error {
	fw := bufio.NewWriter(w)
	h.writeNetdevConfig(fw, opts)
	return fw.Flush()
}

// writeStaticData writes the endpoint-specific static data defines to the
// specified writer. This must be kept in sync with loader.ELFSubstitutions().
func (h *HeaderfileWriter) writeStaticData(devices []string, fw io.Writer, e datapath.EndpointConfiguration) {
	if e.IsHost() {
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
		fmt.Fprint(fw, "\n")

		if option.Config.EnableBPFMasquerade {
			if option.Config.EnableIPv4Masquerade {
				// NodePort comment above applies to IPV4_MASQUERADE too
				placeholderIPv4 := []byte{1, 1, 1, 1}
				fmt.Fprint(fw, defineIPv4("IPV4_MASQUERADE", placeholderIPv4))
			}
			if option.Config.EnableIPv6Masquerade {
				// NodePort comment above applies to IPV6_MASQUERADE too
				placeholderIPv6 := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
				fmt.Fprint(fw, defineIPv6("IPV6_MASQUERADE", placeholderIPv6))
			}
		}
		// Dummy value to avoid being optimized when 0
		fmt.Fprint(fw, defineUint32("SECCTX_FROM_IPCACHE", 1))

		// Use templating for ETH_HLEN only if there is any L2-less device
		if !mac.HaveMACAddrs(devices) {
			// L2 hdr len (for L2-less devices it will be replaced with "0")
			fmt.Fprint(fw, defineUint16("ETH_HLEN", mac.EthHdrLen))
		}
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
		if ipv6 := e.IPv6Address(); ipv6.IsValid() {
			fmt.Fprint(fw, defineIPv6("LXC_IP", ipv6.AsSlice()))
		}

		fmt.Fprint(fw, defineIPv4("LXC_IPV4", e.IPv4Address().AsSlice()))
		fmt.Fprint(fw, defineUint16("LXC_ID", uint16(e.GetID())))
	}

	fmt.Fprint(fw, defineMAC("THIS_INTERFACE_MAC", e.GetNodeMAC()))
	fmt.Fprint(fw, defineUint32("THIS_INTERFACE_IFINDEX", uint32(e.GetIfIndex())))

	secID := e.GetIdentityLocked().Uint32()
	fmt.Fprint(fw, defineUint32("SECLABEL", secID))
	fmt.Fprint(fw, defineUint32("SECLABEL_IPV4", secID))
	fmt.Fprint(fw, defineUint32("SECLABEL_IPV6", secID))
	fmt.Fprint(fw, defineUint32("POLICY_VERDICT_LOG_FILTER", e.GetPolicyVerdictLogFilter()))

	epID := uint16(e.GetID())
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", bpf.LocalMapName(policymap.MapName, epID))
	callsMapName := callsmap.MapName
	if e.IsHost() {
		callsMapName = callsmap.HostMapName
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", bpf.LocalMapName(callsMapName, epID))
	if option.Config.EnableCustomCalls && !e.IsHost() {
		fmt.Fprintf(fw, "#define CUSTOM_CALLS_MAP %s\n", bpf.LocalMapName(callsmap.CustomCallsMapName, epID))
	}
}

// WriteEndpointConfig writes the BPF configuration for the endpoint to a writer.
func (h *HeaderfileWriter) WriteEndpointConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)

	deviceNames := cfg.DeviceNames()

	// Add cilium_wg0 if necessary.
	if option.Config.NeedBPFHostOnWireGuardDevice() {
		deviceNames = append(slices.Clone(deviceNames), wgtypes.IfaceName)
	}

	writeIncludes(w)
	h.writeStaticData(deviceNames, fw, e)

	return h.writeTemplateConfig(fw, deviceNames, cfg.HostEndpointID, e, cfg.DirectRoutingDevice)
}

func (h *HeaderfileWriter) writeTemplateConfig(fw *bufio.Writer, devices []string, hostEndpointID uint64, e datapath.EndpointConfiguration, drd *tables.Device) error {
	if e.RequireEgressProg() {
		fmt.Fprintf(fw, "#define USE_BPF_PROG_FOR_INGRESS_POLICY 1\n")
	}

	if e.RequireRouting() {
		fmt.Fprintf(fw, "#define ENABLE_ROUTING 1\n")
	}

	if !option.Config.EnableHostLegacyRouting {
		if drd != nil {
			fmt.Fprintf(fw, "#define DIRECT_ROUTING_DEV_IFINDEX %d\n", drd.Index)
			if len(devices) == 1 {
				if e.IsHost() || !option.Config.EnforceLXCFibLookup() {
					fmt.Fprintf(fw, "#define ENABLE_SKIP_FIB 1\n")
				}
			}
		}
	}

	if e.IsHost() {
		// Only used to differentiate between host endpoint template and other templates.
		fmt.Fprintf(fw, "#define HOST_ENDPOINT 1\n")
		if option.Config.EnableNodePort {
			fmt.Fprintf(fw, "#define DISABLE_LOOPBACK_LB 1\n")
		}
	}

	fmt.Fprintf(fw, "#define HOST_EP_ID %d\n", uint32(hostEndpointID))

	if option.Config.DatapathMode != datapathOption.DatapathModeNetkit {
		if e.RequireARPPassthrough() {
			fmt.Fprint(fw, "#define ENABLE_ARP_PASSTHROUGH 1\n")
		} else {
			fmt.Fprint(fw, "#define ENABLE_ARP_RESPONDER 1\n")
		}
	}

	if e.ConntrackLocalLocked() {
		ctmap.WriteBPFMacros(fw, e)
	} else {
		ctmap.WriteBPFMacros(fw, nil)
	}

	// Local delivery metrics should always be set for endpoint programs.
	fmt.Fprint(fw, "#define LOCAL_DELIVERY_METRICS 1\n")

	h.writeNetdevConfig(fw, e.GetOptions())

	return fw.Flush()
}

// WriteTemplateConfig writes the BPF configuration for the template to a writer.
func (h *HeaderfileWriter) WriteTemplateConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)
	return h.writeTemplateConfig(fw, cfg.DeviceNames(), cfg.HostEndpointID, e, cfg.DirectRoutingDevice)
}
