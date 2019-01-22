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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// WriteNodeConfig writes the local node configuration to the specified writer.
func (l *linuxDatapath) WriteNodeConfig(w io.Writer, cfg *datapath.LocalNodeConfiguration) error {
	fw := bufio.NewWriter(w)

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
		fw.WriteString(common.FmtDefineComma("ROUTER_IP", routerIP))
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
		fw.WriteString(common.FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineComma("HOST_IP", hostIP))
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
	fmt.Fprintf(fw, "#define LB6_RR_SEQ_MAP cilium_lb6_rr_seq\n")
	fmt.Fprintf(fw, "#define LB4_REVERSE_NAT_MAP cilium_lb4_reverse_nat\n")
	fmt.Fprintf(fw, "#define LB4_SERVICES_MAP cilium_lb4_services\n")
	fmt.Fprintf(fw, "#define LB4_RR_SEQ_MAP cilium_lb4_rr_seq\n")

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

	return fw.Flush()
}
