// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"text/template"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/configmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/maps/l2v6respondermap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
)

// HeaderfileWriter is a wrapper type which implements datapath.ConfigWriter.
// It manages writing of configuration of datapath program headerfiles.
type HeaderfileWriter struct {
	log                *slog.Logger
	nodeMap            nodemap.MapV2
	nodeAddressing     datapath.NodeAddressing
	nodeExtraDefines   dpdef.Map
	nodeExtraDefineFns []dpdef.Fn
	sysctl             sysctl.Sysctl
	kprCfg             kpr.KPRConfig
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
		kprCfg:             p.KPRConfig,
	}, nil
}

func writeIncludes(w io.Writer) (int, error) {
	return fmt.Fprintf(w, "#include \"lib/utils.h\"\n\n")
}

// WriteNodeConfig writes the local node configuration to the specified writer.
//
// Deprecated: Future additions to this function will be rejected. The docs at
// https://docs.cilium.io/en/latest/contributing/development/datapath_config
// will guide you through adding new configuration.
func (h *HeaderfileWriter) WriteNodeConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration) error {
	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	extraMacrosMap := make(dpdef.Map)
	cDefinesMap := make(dpdef.Map)

	nativeDevices := cfg.Devices

	fw := bufio.NewWriter(w)

	writeIncludes(w)

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

	if option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking {
		cDefinesMap["ENABLE_IPV6_FRAGMENTS"] = "1"
	}

	cDefinesMap["CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", option.Config.FragmentsMapEntries)

	if option.Config.EnableIPv4 {
		ipv4GW := cfg.CiliumInternalIPv4
		cDefinesMap["IPV4_GATEWAY"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(ipv4GW))

		if option.Config.EnableIPv4FragmentsTracking {
			cDefinesMap["ENABLE_IPV4_FRAGMENTS"] = "1"
		}
	}

	cDefinesMap["CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", option.Config.FragmentsMapEntries)

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

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
	cDefinesMap["LOCAL_NODE_ID"] = fmt.Sprintf("%d", identity.ReservedIdentityRemoteNode)
	cDefinesMap["REMOTE_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameRemoteNode))
	cDefinesMap["KUBE_APISERVER_NODE_ID"] = fmt.Sprintf("%d", identity.GetReservedID(labels.IDNameKubeAPIServer))
	cDefinesMap["CILIUM_LB_SERVICE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBServiceMapEntries)
	cDefinesMap["CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBBackendMapEntries)
	cDefinesMap["CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBRevNatEntries)
	cDefinesMap["CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBAffinityMapEntries)
	cDefinesMap["CILIUM_LB_SOURCE_RANGE_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBSourceRangeMapEntries)
	cDefinesMap["CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", cfg.LBConfig.LBMaglevMapEntries)
	cDefinesMap["CILIUM_LB_SKIP_MAP_MAX_ENTRIES"] = fmt.Sprintf("%d", lbmaps.SkipLBMapMaxEntries)

	cDefinesMap["ENDPOINTS_MAP_SIZE"] = fmt.Sprintf("%d", lxcmap.MaxEntries)
	cDefinesMap["METRICS_MAP_SIZE"] = fmt.Sprintf("%d", metricsmap.MaxEntries)
	cDefinesMap["AUTH_MAP_SIZE"] = fmt.Sprintf("%d", option.Config.AuthMapEntries)
	cDefinesMap["CONFIG_MAP_SIZE"] = fmt.Sprintf("%d", configmap.MaxEntries)
	cDefinesMap["IPCACHE_MAP_SIZE"] = fmt.Sprintf("%d", ipcachemap.MaxEntries)
	cDefinesMap["NODE_MAP_SIZE"] = fmt.Sprintf("%d", h.nodeMap.Size())
	cDefinesMap["POLICY_PROG_MAP_SIZE"] = fmt.Sprintf("%d", policymap.PolicyCallMaxEntries)
	cDefinesMap["L2_RESPONDER_MAP4_SIZE"] = fmt.Sprintf("%d", l2respondermap.DefaultMaxEntries)
	cDefinesMap["L2_RESPONDER_MAP6_SIZE"] = fmt.Sprintf("%d", l2v6respondermap.DefaultMaxEntries)
	cDefinesMap["CT_CONNECTION_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutTCP.Seconds()))
	cDefinesMap["CT_CONNECTION_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutAny.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_TCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCP.Seconds()))
	cDefinesMap["CT_SERVICE_LIFETIME_NONTCP"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCAny.Seconds()))
	cDefinesMap["CT_SERVICE_CLOSE_REBALANCE"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSVCTCPGrace.Seconds()))
	cDefinesMap["CT_SYN_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutSYN.Seconds()))
	cDefinesMap["CT_CLOSE_TIMEOUT"] = fmt.Sprintf("%d", int64(option.Config.CTMapEntriesTimeoutFIN.Seconds()))
	cDefinesMap["CT_REPORT_INTERVAL"] = fmt.Sprintf("%d", int64(option.Config.MonitorAggregationInterval.Seconds()))
	cDefinesMap["CT_REPORT_FLAGS"] = fmt.Sprintf("%#04x", int64(option.Config.MonitorAggregationFlags))

	if option.Config.PreAllocateMaps {
		cDefinesMap["PREALLOCATE_MAPS"] = "1"
	}
	if option.Config.BPFDistributedLRU {
		cDefinesMap["NO_COMMON_MEM_MAPS"] = "1"
	}

	cDefinesMap["EVENTS_MAP_RATE_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultRateLimit)
	cDefinesMap["EVENTS_MAP_BURST_LIMIT"] = fmt.Sprintf("%d", option.Config.BPFEventsDefaultBurstLimit)
	cDefinesMap["LB6_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", cfg.LBConfig.LBSockRevNatEntries)
	cDefinesMap["LB4_REVERSE_NAT_SK_MAP_SIZE"] = fmt.Sprintf("%d", cfg.LBConfig.LBSockRevNatEntries)
	cDefinesMap["MTU"] = fmt.Sprintf("%d", cfg.DeviceMTU)

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

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

	if option.Config.ServiceNoBackendResponse == option.ServiceNoBackendResponseReject {
		cDefinesMap["SERVICE_NO_BACKEND_RESPONSE"] = "1"
	}

	if option.Config.EnableEncryptionStrictModeEgress {
		cDefinesMap["ENCRYPTION_STRICT_MODE_EGRESS"] = "1"

		// when parsing the user input we only accept ipv4 addresses
		cDefinesMap["STRICT_IPV4_NET"] = fmt.Sprintf("%#x", byteorder.NetIPAddrToHost32(option.Config.EncryptionStrictEgressCIDR.Addr()))
		cDefinesMap["STRICT_IPV4_NET_SIZE"] = fmt.Sprintf("%d", option.Config.EncryptionStrictEgressCIDR.Bits())

		cDefinesMap["IPV4_ENCRYPT_IFACE"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(cfg.NodeIPv4))

		ipv4Interface, ok := netip.AddrFromSlice(cfg.NodeIPv4.To4())
		if !ok {
			return fmt.Errorf("unable to parse node IPv4 address %s", cfg.NodeIPv4)
		}

		if option.Config.EncryptionStrictEgressCIDR.Contains(ipv4Interface) {
			if !option.Config.EncryptionStrictEgressAllowRemoteNodeIdentities {
				return fmt.Errorf(`encryption strict mode is enabled but the node's IPv4 address is within the strict CIDR range.
				This will cause the node to drop all traffic.
				Please either disable encryption or set --encryption-strict-egress-allow-remote-node-identities=true`)
			}
			cDefinesMap["STRICT_IPV4_OVERLAPPING_CIDR"] = "1"
		}
	}

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	if option.Config.EnableBPFTProxy {
		cDefinesMap["ENABLE_TPROXY"] = "1"
	}

	if option.Config.EnableEndpointRoutes {
		cDefinesMap["ENABLE_ENDPOINT_ROUTES"] = "1"
	}

	if option.Config.EnableEnvoyConfig {
		cDefinesMap["ENABLE_L7_LB"] = "1"
	}

	if h.kprCfg.EnableSocketLB {
		if option.Config.UnsafeDaemonConfigOption.BPFSocketLBHostnsOnly {
			cDefinesMap["ENABLE_SOCKET_LB_HOST_ONLY"] = "1"
		} else {
			cDefinesMap["ENABLE_SOCKET_LB_FULL"] = "1"
		}
		if option.Config.UnsafeDaemonConfigOption.EnableSocketLBPeer {
			cDefinesMap["ENABLE_SOCKET_LB_PEER"] = "1"
		}
		if option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing {
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
	}

	cDefinesMap["NODEPORT_NEIGH6_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)
	cDefinesMap["NODEPORT_NEIGH4_SIZE"] = fmt.Sprintf("%d", option.Config.NeighMapEntriesGlobal)

	if h.kprCfg.KubeProxyReplacement {
		if option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath {
			cDefinesMap["ENABLE_HEALTH_CHECK"] = "1"
		}
		if option.Config.EnableMKE && h.kprCfg.EnableSocketLB {
			cDefinesMap["ENABLE_MKE"] = "1"
			cDefinesMap["MKE_HOST"] = fmt.Sprintf("%d", option.HostExtensionMKE)
		}
		cDefinesMap["ENABLE_NODEPORT"] = "1"

		if option.Config.EnableNat46X64Gateway {
			cDefinesMap["ENABLE_NAT_46X64_GATEWAY"] = "1"
		}
		if option.Config.NodePortNat46X64 {
			cDefinesMap["ENABLE_NAT_46X64"] = "1"
		}

		// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

		const (
			dsrEncapInv = iota
			dsrEncapNone
			dsrEncapIPIP
			dsrEncapGeneve
		)
		cDefinesMap["DSR_ENCAP_IPIP"] = fmt.Sprintf("%d", dsrEncapIPIP)
		cDefinesMap["DSR_ENCAP_GENEVE"] = fmt.Sprintf("%d", dsrEncapGeneve)
		cDefinesMap["DSR_ENCAP_NONE"] = fmt.Sprintf("%d", dsrEncapNone)
		if cfg.LBConfig.LoadBalancerUsesDSR() {
			cDefinesMap["ENABLE_DSR"] = "1"
			if option.Config.EnablePMTUDiscovery {
				cDefinesMap["ENABLE_DSR_ICMP_ERRORS"] = "1"
			}
			if cfg.LBConfig.LBMode == loadbalancer.LBModeHybrid || cfg.LBConfig.LBModeAnnotation {
				cDefinesMap["ENABLE_DSR_BYUSER"] = "1"
			}
			if cfg.LBConfig.DSRDispatch == loadbalancer.DSRDispatchOption {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapNone)
			} else if cfg.LBConfig.DSRDispatch == loadbalancer.DSRDispatchIPIP {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapIPIP)
			} else if cfg.LBConfig.DSRDispatch == loadbalancer.DSRDispatchGeneve {
				cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapGeneve)
			}
		} else {
			cDefinesMap["DSR_ENCAP_MODE"] = fmt.Sprintf("%d", dsrEncapInv)
		}
		if option.Config.EnableIPv4 {
			if option.Config.LoadBalancerRSSv4CIDR != "" {
				ipv4 := byteorder.NetIPv4ToHost32(option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4.IP)
				ones, _ := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv4.Mask.Size()
				cDefinesMap["IPV4_RSS_PREFIX"] = fmt.Sprintf("%d", ipv4)
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = fmt.Sprintf("%d", ones)
			} else {
				cDefinesMap["IPV4_RSS_PREFIX"] = "IPV4_DIRECT_ROUTING"
				cDefinesMap["IPV4_RSS_PREFIX_BITS"] = "32"
			}
		}
		if option.Config.EnableIPv6 {
			if option.Config.LoadBalancerRSSv6CIDR != "" {
				ipv6 := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6.IP
				ones, _ := option.Config.UnsafeDaemonConfigOption.LoadBalancerRSSv6.Mask.Size()
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
		if !option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting {
			cDefinesMap["ENABLE_HOST_ROUTING"] = "1"
		}
	}

	cDefinesMap["LB4_SRC_RANGE_MAP_SIZE"] = fmt.Sprintf("%d", cfg.LBConfig.LBSourceRangeMapEntries)
	cDefinesMap["LB6_SRC_RANGE_MAP_SIZE"] = fmt.Sprintf("%d", cfg.LBConfig.LBSourceRangeMapEntries)

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	const (
		selectionRandom = iota + 1
		selectionMaglev
	)
	cDefinesMap["LB_SELECTION_RANDOM"] = fmt.Sprintf("%d", selectionRandom)
	cDefinesMap["LB_SELECTION_MAGLEV"] = fmt.Sprintf("%d", selectionMaglev)
	if cfg.LBConfig.AlgorithmAnnotation {
		cDefinesMap["LB_SELECTION_PER_SERVICE"] = "1"
	}
	if cfg.LBConfig.LBAlgorithm == loadbalancer.LBAlgorithmRandom {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionRandom)
	} else if cfg.LBConfig.LBAlgorithm == loadbalancer.LBAlgorithmMaglev {
		cDefinesMap["LB_SELECTION"] = fmt.Sprintf("%d", selectionMaglev)
	}

	// define maglev tables when loadbalancer algorith is maglev or config can
	// be set by the Service annotation
	cDefinesMap["LB_MAGLEV_LUT_SIZE"] = fmt.Sprintf("%d", cfg.MaglevConfig.TableSize)

	// We assume that validation for DirectRoutingDevice requirement and presence is already done
	// upstream when constructing the LocalNodeConfiguration.
	// See orchestrator/localnodeconfig.go
	drd := cfg.DirectRoutingDevice
	if drd != nil {
		if option.Config.EnableIPv4 {
			var ipv4 uint32
			for _, addr := range drd.Addrs {
				if addr.Addr.Is4() {
					ipv4 = byteorder.NetIPAddrToHost32(addr.Addr)
					break
				}
			}
			if ipv4 == 0 {
				return fmt.Errorf("IPv4 direct routing device IP not found")
			}
			cDefinesMap["IPV4_DIRECT_ROUTING"] = fmt.Sprintf("%d", ipv4)
		}
		if option.Config.EnableIPv6 {
			ip := preferredIPv6Address(drd.Addrs)
			if ip.IsUnspecified() {
				return fmt.Errorf("IPv6 direct routing device IP not found")
			}
			extraMacrosMap["IPV6_DIRECT_ROUTING"] = ip.String()
			fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", ip.AsSlice()))
		}
	} else {
		var directRoutingIPv6 net.IP
		if option.Config.EnableIPv4 {
			cDefinesMap["IPV4_DIRECT_ROUTING"] = "0"
		}
		if option.Config.EnableIPv6 {
			extraMacrosMap["IPV6_DIRECT_ROUTING"] = directRoutingIPv6.String()
			fw.WriteString(FmtDefineAddress("IPV6_DIRECT_ROUTING", directRoutingIPv6))
		}
	}

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	if option.Config.EnableHostFirewall {
		cDefinesMap["ENABLE_HOST_FIREWALL"] = "1"
	}

	cDefinesMap["SNAT_MAPPING_IPV4_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
	cDefinesMap["SNAT_MAPPING_IPV6_SIZE"] = fmt.Sprintf("%d", option.Config.NATMapEntriesGlobal)
	cDefinesMap["SNAT_COLLISION_RETRIES"] = fmt.Sprintf("%d", nat.SnatCollisionRetries)

	if option.Config.EnableBPFMasquerade {
		cDefinesMap["ENABLE_NODEPORT"] = "1"

		if option.Config.EnableIPv4Masquerade {
			cDefinesMap["ENABLE_MASQUERADE_IPV4"] = "1"

			// ip-masq-agent depends on bpf-masq
			var excludeCIDR *cidr.CIDR
			if option.Config.EnableIPMasqAgent {
				cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV4"] = "1"

				// native-routing-cidr is optional with ip-masq-agent and may be nil
				excludeCIDR = option.Config.IPv4NativeRoutingCIDR
			} else {
				excludeCIDR = cfg.NativeRoutingCIDRIPv4
			}

			if excludeCIDR != nil {
				cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR"] = fmt.Sprintf("%#x", byteorder.NetIPv4ToHost32(excludeCIDR.IP))
				ones, _ := excludeCIDR.Mask.Size()
				cDefinesMap["IPV4_SNAT_EXCLUSION_DST_CIDR_LEN"] = fmt.Sprintf("%d", ones)
			}
		}
		if option.Config.EnableIPv6Masquerade {
			cDefinesMap["ENABLE_MASQUERADE_IPV6"] = "1"

			var excludeCIDR *cidr.CIDR
			if option.Config.EnableIPMasqAgent {
				cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV6"] = "1"

				excludeCIDR = option.Config.IPv6NativeRoutingCIDR
			} else {
				excludeCIDR = cfg.NativeRoutingCIDRIPv6
			}

			if excludeCIDR != nil {
				extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR"] = excludeCIDR.IP.String()
				fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR", excludeCIDR.IP))
				extraMacrosMap["IPV6_SNAT_EXCLUSION_DST_CIDR_MASK"] = excludeCIDR.Mask.String()
				fw.WriteString(FmtDefineAddress("IPV6_SNAT_EXCLUSION_DST_CIDR_MASK", excludeCIDR.Mask))
			}
		}
	}

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	fmt.Fprintf(fw, "#define CT_MAP_SIZE_TCP %d\n", cmp.Or(option.Config.CTMapEntriesGlobalTCP, option.CTMapEntriesGlobalTCPDefault))
	fmt.Fprintf(fw, "#define CT_MAP_SIZE_ANY %d\n", cmp.Or(option.Config.CTMapEntriesGlobalAny, option.CTMapEntriesGlobalAnyDefault))

	if option.Config.EnableIdentityMark {
		cDefinesMap["ENABLE_IDENTITY_MARK"] = "1"
	}

	if option.Config.IPv4Enabled() && option.Config.EnableVTEP {
		cDefinesMap["ENABLE_VTEP"] = "1"
	}

	cDefinesMap["VTEP_MAP_SIZE"] = fmt.Sprintf("%d", vtep.MaxEntries)

	vlanFilter, err := vlanFilterMacros(nativeDevices)
	if err != nil {
		return fmt.Errorf("rendering vlan filter macros: %w", err)
	}
	cDefinesMap["VLAN_FILTER(ifindex, vlan_id)"] = vlanFilter

	if option.Config.DisableExternalIPMitigation {
		cDefinesMap["DISABLE_EXTERNAL_IP_MITIGATION"] = "1"
	}

	cDefinesMap["CIDR_IDENTITY_RANGE_START"] = fmt.Sprintf("%d", identity.MinLocalIdentity)
	cDefinesMap["CIDR_IDENTITY_RANGE_END"] = fmt.Sprintf("%d", identity.MaxLocalIdentity)

	if option.Config.TunnelingEnabled() {
		cDefinesMap["TUNNEL_MODE"] = "1"
	}

	ciliumNetLink, err := safenetlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return fmt.Errorf("failed to look up link '%s': %w", defaults.SecondHostDevice, err)
	}
	cDefinesMap["CILIUM_NET_MAC"] = fmt.Sprintf("{.addr=%s}", mac.CArrayString(ciliumNetLink.Attrs().HardwareAddr))
	cDefinesMap["CILIUM_NET_IFINDEX"] = fmt.Sprintf("%d", ciliumNetLink.Attrs().Index)

	ciliumHostLink, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return fmt.Errorf("failed to look up link '%s': %w", defaults.HostDevice, err)
	}
	cDefinesMap["CILIUM_HOST_MAC"] = fmt.Sprintf("{.addr=%s}", mac.CArrayString(ciliumHostLink.Attrs().HardwareAddr))
	cDefinesMap["CILIUM_HOST_IFINDEX"] = fmt.Sprintf("%d", ciliumHostLink.Attrs().Index)

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	if err := cDefinesMap.Merge(h.nodeExtraDefines); err != nil {
		return fmt.Errorf("merging extra node defines: %w", err)
	}

	for _, fn := range h.nodeExtraDefineFns {
		defines, err := fn()
		if err != nil {
			return err
		}

		if err := cDefinesMap.Merge(defines); err != nil {
			return fmt.Errorf("merging extra node define func results: %w", err)
		}
	}

	if option.Config.UnsafeDaemonConfigOption.EnableIPIPDevices {
		if option.Config.IPv4Enabled() {
			ipip4, err := safenetlink.LinkByName(defaults.IPIPv4Device)
			if err != nil {
				return fmt.Errorf("looking up link %s: %w", defaults.IPIPv4Device, err)
			}
			cDefinesMap["ENCAP4_IFINDEX"] = fmt.Sprintf("%d", ipip4.Attrs().Index)
		}
		if option.Config.IPv6Enabled() {
			ipip6, err := safenetlink.LinkByName(defaults.IPIPv6Device)
			if err != nil {
				return fmt.Errorf("looking up link %s: %w", defaults.IPIPv6Device, err)
			}
			cDefinesMap["ENCAP6_IFINDEX"] = fmt.Sprintf("%d", ipip6.Attrs().Index)
		}
	} else {
		cDefinesMap["ENCAP4_IFINDEX"] = "0"
		cDefinesMap["ENCAP6_IFINDEX"] = "0"
	}

	fmt.Fprint(fw, declareConfig("interface_ifindex", uint32(0), "ifindex of the interface the bpf program is attached to"))

	// --- WARNING: THIS CONFIGURATION METHOD IS DEPRECATED, SEE FUNCTION DOC ---

	// Since golang maps are unordered, we sort the keys in the map
	// to get a consistent written format to the writer. This maintains
	// the consistency when we try to calculate hash for a datapath after
	// writing the config.
	for _, key := range slices.Sorted(maps.Keys(cDefinesMap)) {
		fmt.Fprintf(fw, "#define %s %s\n", key, cDefinesMap[key])
	}

	// Populate cDefinesMap with extraMacrosMap to get all the configuration
	// in the cDefinesMap itself.
	maps.Copy(cDefinesMap, extraMacrosMap)

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

	links, err := safenetlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("listing network interfaces: %w", err)
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
		slices.Sort(v) // sort Vlanids in-place since safenetlink.LinkList() may return them in any order
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

// WriteEndpointConfig writes the BPF configuration for the endpoint to a writer.
func (h *HeaderfileWriter) WriteEndpointConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)

	writeIncludes(w)

	return h.writeTemplateConfig(fw, cfg, e)
}

func (h *HeaderfileWriter) writeTemplateConfig(fw *bufio.Writer, cfg *datapath.LocalNodeConfiguration, e datapath.EndpointConfiguration) error {
	if e.RequireEgressProg() {
		fmt.Fprintf(fw, "#define USE_BPF_PROG_FOR_INGRESS_POLICY 1\n")
	}

	if e.RequireRouting() {
		fmt.Fprintf(fw, "#define ENABLE_ROUTING 1\n")
	}

	if e.IsHost() {
		// Only used to differentiate between host endpoint template and other templates.
		fmt.Fprintf(fw, "#define HOST_ENDPOINT 1\n")
	}

	// Local delivery metrics should always be set for endpoint programs.
	fmt.Fprint(fw, "#define LOCAL_DELIVERY_METRICS 1\n")

	h.writeNetdevConfig(fw, e.GetOptions())

	return fw.Flush()
}

// WriteTemplateConfig writes the BPF configuration for the template to a writer.
func (h *HeaderfileWriter) WriteTemplateConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration, e datapath.EndpointConfiguration) error {
	fw := bufio.NewWriter(w)
	return h.writeTemplateConfig(fw, cfg, e)
}

func preferredIPv6Address(deviceAddresses []tables.DeviceAddress) netip.Addr {
	var ip netip.Addr
	for _, addr := range deviceAddresses {
		if addr.Addr.Is6() {
			ip = addr.Addr
			if !ip.IsLinkLocalUnicast() {
				break
			}
		}
	}
	return ip
}
