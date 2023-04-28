// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	templateSecurityID          = identity.ReservedIdentityWorld
	templateLxcID               = uint16(65535)
	templatePolicyVerdictFilter = uint32(0xffff)
)

var (
	templateIPv4 = [4]byte{192, 0, 2, 3}
	templateIPv6 = [16]byte{0x20, 0x01, 0xdb, 0x8, 0x0b, 0xad, 0xca, 0xfe, 0x60, 0x0d, 0xbe, 0xe2, 0x0b, 0xad, 0xca, 0xfe}

	templateMAC = mac.MAC([]byte{0x02, 0x00, 0x60, 0x0D, 0xF0, 0x0D})

	elfMapPrefixes = []string{
		policymap.MapName,
		callsmap.MapName,
		callsmap.CustomCallsMapName,
	}
	elfCtMapPrefixes = []string{
		ctmap.MapNameTCP4,
		ctmap.MapNameAny4,
		ctmap.MapNameTCP6,
		ctmap.MapNameAny6,
	}
)

// templateCfg wraps a real configuration from an endpoint to pass through its
// configuration of conditional branches in the datapath, but to mock out dummy
// values for static data.
//
// Note that the static data dummy values must be non-zero in every 32-bit
// section of the data to ensure that during compilation, the compiler reserves
// space in the .data section of the ELF for the value of the data, rather than
// generating a reference to the .bss section (which is what it will typically
// do if a static integer is initialized to zero).
//
// Ideally we also statically configure the values used in the template in such
// a way that if ever someone managed to inadvertently attach the template
// program directly to a device, that there are no unintended consequences such
// as allowing traffic to leak out with routable addresses.
type templateCfg struct {
	// CompileTimeConfiguration passes through directly to the underlying
	// endpoint configuration, while the rest of the EndpointConfiguration
	// interface is implemented directly here through receiver functions.
	datapath.CompileTimeConfiguration
	stats *metrics.SpanStat
}

// GetID returns a uint64, but in practice on the datapath side it is
// guaranteed to be 16-bit; it is used to generate map names, so we need to
// ensure that the template generates map names that are as long as the longest
// possible name, which would be guaranteed with a 5-digit output.
//
// In practice, attempts to load an endpoint with the ID 65535 will fail which
// means that the calling code must approprately substitute the ID in the ELF
// prior to load, or it will fail with a relatively obvious error.
func (t *templateCfg) GetID() uint64 {
	return uint64(templateLxcID)
}

// StringID returns the string form of the ID returned by GetID().
func (t *templateCfg) StringID() string {
	return fmt.Sprintf("%d", t.GetID())
}

// GetIdentity treats the template program as part of the world, so if there's
// ever some weird bug that causes the template value here to be used, it will
// be in the least privileged security context.
func (t *templateCfg) GetIdentity() identity.NumericIdentity {
	return templateSecurityID
}

// GetIdentityLocked is identical to GetIdentity(). This is a temporary
// function until WriteEndpointConfig() no longer assumes that the endpoint is
// locked.
func (t *templateCfg) GetIdentityLocked() identity.NumericIdentity {
	return templateSecurityID
}

// GetNodeMAC returns a well-known dummy MAC address which may be later
// substituted in the ELF.
func (t *templateCfg) GetNodeMAC() mac.MAC {
	return templateMAC
}

// IPv4Address always returns an IP in the documentation prefix (RFC5737) as
// a nonsense address that should typically not be routable.
func (t *templateCfg) IPv4Address() netip.Addr {
	return netip.AddrFrom4(templateIPv4)
}

// IPv6Address returns an IP in the documentation prefix (RFC3849) to ensure
// that each 32-bit segment of the address is non-zero as per the requirements
// described in the structure definition. This can't be guaranteed while using
// a more appropriate prefix such as the discard prefix (RFC6666).
func (t *templateCfg) IPv6Address() netip.Addr {
	return netip.AddrFrom16(templateIPv6)
}

// GetPolicyVerdictLogFilter returns an uint32 filter to ensure
// that the filter is non-zero as per the requirements
// described in the structure definition.
func (t *templateCfg) GetPolicyVerdictLogFilter() uint32 {
	return templatePolicyVerdictFilter
}

// wrap takes an endpoint configuration and optional stats tracker and wraps
// it inside a templateCfg which hides static data from callers that wish to
// generate header files based on the configuration, substituting it for
// template data.
func wrap(cfg datapath.CompileTimeConfiguration, stats *metrics.SpanStat) *templateCfg {
	if stats == nil {
		stats = &metrics.SpanStat{}
	}
	return &templateCfg{
		CompileTimeConfiguration: cfg,
		stats:                    stats,
	}
}

// elfMapSubstitutions returns the set of map substitutions that must occur in
// an ELF template object file to update map references for the specified
// endpoint.
func elfMapSubstitutions(ep datapath.Endpoint) map[string]string {
	result := make(map[string]string)
	epID := uint16(ep.GetID())

	for _, name := range elfMapPrefixes {
		if ep.IsHost() && name == callsmap.MapName {
			name = callsmap.HostMapName
		}
		// Custom calls for hosts are not supported yet.
		if name == callsmap.CustomCallsMapName &&
			(!option.Config.EnableCustomCalls || ep.IsHost()) {
			continue
		}
		templateStr := bpf.LocalMapName(name, templateLxcID)
		desiredStr := bpf.LocalMapName(name, epID)
		result[templateStr] = desiredStr
	}
	if ep.ConntrackLocalLocked() {
		for _, name := range elfCtMapPrefixes {
			templateStr := bpf.LocalMapName(name, templateLxcID)
			desiredStr := bpf.LocalMapName(name, epID)
			result[templateStr] = desiredStr
		}
	}

	// Populate the policy map if the host firewall is enabled regardless of the per-endpoint route setting
	// because all routing is performed by the Linux stack with the chaining mode
	// even if the per-endpoint route is disabled in the agent
	if !ep.IsHost() || option.Config.EnableHostFirewall {
		result[policymap.CallString(templateLxcID)] = policymap.CallString(epID)
	}
	// Egress policy map is only used when Envoy Config CRDs are enabled.
	// Currently the Host EP does not use this.
	if !ep.IsHost() && option.Config.EnableEnvoyConfig {
		result[policymap.EgressCallString(templateLxcID)] = policymap.EgressCallString(epID)
	}

	return result
}

// sliceToU16 converts the input slice of two bytes to a uint16.
func sliceToU16(input []byte) uint16 {
	result := uint16(input[0]) << 8
	result |= uint16(input[1])
	return result
}

// sliceToBe16 converts the input slice of two bytes to a big-endian uint16.
func sliceToBe16(input []byte) uint16 {
	return byteorder.HostToNetwork16(sliceToU16(input))
}

// sliceToU32 converts the input slice of four bytes to a uint32.
func sliceToU32(input []byte) uint32 {
	result := uint32(input[0]) << 24
	result |= uint32(input[1]) << 16
	result |= uint32(input[2]) << 8
	result |= uint32(input[3])
	return result
}

// sliceToBe32 converts the input slice of four bytes to a big-endian uint32.
func sliceToBe32(input []byte) uint32 {
	return byteorder.HostToNetwork32(sliceToU32(input))
}

// sliceToU64 converts the input slice of eight bytes to a uint64.
func sliceToU64(input []byte) uint64 {
	result := uint64(input[0]) << 56
	result |= uint64(input[1]) << 48
	result |= uint64(input[2]) << 40
	result |= uint64(input[3]) << 32
	result |= uint64(input[4]) << 24
	result |= uint64(input[5]) << 16
	result |= uint64(input[6]) << 8
	result |= uint64(input[7])
	return result
}

// sliceToBe64 converts the input slice of eight bytes to a big-endian uint64.
func sliceToBe64(input []byte) uint64 {
	return byteorder.HostToNetwork64(sliceToU64(input))
}

// elfVariableSubstitutions returns the set of data substitutions that must
// occur in an ELF template object file to update static data for the specified
// endpoint.
func elfVariableSubstitutions(ep datapath.Endpoint) map[string]uint64 {
	result := make(map[string]uint64)

	if ipv6 := ep.IPv6Address().AsSlice(); ipv6 != nil {
		// Corresponds to DEFINE_IPV6() in bpf/lib/utils.h
		result["LXC_IP_1"] = sliceToBe64(ipv6[0:8])
		result["LXC_IP_2"] = sliceToBe64(ipv6[8:16])
	}
	if ipv4 := ep.IPv4Address().AsSlice(); ipv4 != nil {
		result["LXC_IPV4"] = uint64(byteorder.NetIPv4ToHost32(net.IP(ipv4)))
	}

	mac := ep.GetNodeMAC()
	result["NODE_MAC_1"] = uint64(sliceToBe32(mac[0:4]))
	result["NODE_MAC_2"] = uint64(sliceToBe16(mac[4:6]))

	if ep.IsHost() {
		if option.Config.EnableNodePort {
			result["NATIVE_DEV_IFINDEX"] = 0
		}
		if option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade {
			if option.Config.EnableIPv4 {
				result["IPV4_MASQUERADE"] = 0
			}
		}
		result["SECCTX_FROM_IPCACHE"] = uint64(SecctxFromIpcacheDisabled)
	} else {
		result["LXC_ID"] = uint64(ep.GetID())
	}

	identity := ep.GetIdentity().Uint32()
	result["SECLABEL"] = uint64(identity)
	result["SECLABEL_NB"] = uint64(byteorder.HostToNetwork32(identity))
	result["POLICY_VERDICT_LOG_FILTER"] = uint64(ep.GetPolicyVerdictLogFilter())
	return result

}

// ELFSubstitutions fetches the set of variable and map substitutions that
// must be implemented against an ELF template to configure the datapath for
// the specified endpoint.
func ELFSubstitutions(ep datapath.Endpoint) (map[string]uint64, map[string]string) {
	return elfVariableSubstitutions(ep), elfMapSubstitutions(ep)
}
