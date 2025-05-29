// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"
	"log/slog"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName4 = "cilium_egress_gw_policy_v4"
	PolicyMapName6 = "cilium_egress_gw_policy_v6"
	// PolicyStaticPrefixBits4 represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits4 = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
	PolicyStaticPrefixBits6 = uint32(unsafe.Sizeof(types.IPv6{}) * 8)
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyKey4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm_key"`

	SourceIP types.IPv4 `align:"saddr"`
	DestCIDR types.IPv4 `align:"daddr"`
}

// EgressPolicyVal4 is the value of an egress policy map.
type EgressPolicyVal4 struct {
	EgressIP  types.IPv4 `align:"egress_ip"`
	GatewayIP types.IPv4 `align:"gateway_ip"`
}

// EgressPolicyKey6 is the key of an egress policy map.
type EgressPolicyKey6 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32 `align:"lpm_key"`

	SourceIP types.IPv6 `align:"saddr"`
	DestCIDR types.IPv6 `align:"daddr"`
}

// EgressPolicyVal6 is the value of an egress policy map.
type EgressPolicyVal6 struct {
	EgressIP      types.IPv6 `align:"egress_ip"`
	GatewayIP     types.IPv4 `align:"gateway_ip"`
	Reserved      [3]uint32  `align:"reserved"`
	EgressIfindex uint32     `align:"egress_ifindex"`
	Reserved2     uint32     `align:"reserved2"`
}

type PolicyConfig struct {
	// EgressGatewayPolicyMapMax is the maximum number of entries
	// allowed in the BPF egress gateway policy map.
	EgressGatewayPolicyMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	EgressGatewayPolicyMapMax: 1 << 14,
}

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("egress-gateway-policy-map-max", def.EgressGatewayPolicyMapMax, "Maximum number of entries in egress gateway policy map")
}

// PolicyMap4 is used to communicate ipv4 EGW policies to the datapath.
type PolicyMap4 policyMap

// PolicyMap6 is used to communicate ipv6 EGW policies to the datapath.
type PolicyMap6 policyMap

// policyMap is the internal representation of an egress policy map.
type policyMap struct {
	m *bpf.Map
}

func createPolicyMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
	PolicyConfig
	MetricsRegistry *metrics.Registry
}) (out struct {
	cell.Out

	IPv4Map bpf.MapOut[*PolicyMap4]
	IPv6Map bpf.MapOut[*PolicyMap6]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_POLICY_MAP_SIZE": fmt.Sprint(in.EgressGatewayPolicyMapMax),
	}

	if !in.EnableIPv4EgressGateway {
		return
	}

	if in.EnableIPv4 {
		out.IPv4Map = bpf.NewMapOut(createPolicyMap4(in.Lifecycle, in.MetricsRegistry, in.PolicyConfig, ebpf.PinByName))
	}

	if in.EnableIPv6 {
		out.IPv6Map = bpf.NewMapOut(createPolicyMap6(in.Lifecycle, in.MetricsRegistry, in.PolicyConfig, ebpf.PinByName))
	}

	return
}

// CreatePrivatePolicyMap4 creates an unpinned IPv4 policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap4(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig) *PolicyMap4 {
	return createPolicyMap4(lc, registry, cfg, ebpf.PinNone)
}

// CreatePrivatePolicyMap6 creates an unpinned IPv6 policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap6(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig) *PolicyMap6 {
	return createPolicyMap6(lc, registry, cfg, ebpf.PinNone)
}

func createPolicyMap4(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig, pinning ebpf.PinType) *PolicyMap4 {
	m := bpf.NewMap(
		PolicyMapName4,
		ebpf.LPMTrie,
		&EgressPolicyKey4{},
		&EgressPolicyVal4{},
		cfg.EgressGatewayPolicyMapMax,
		0,
	).WithPressureMetric(registry)

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &PolicyMap4{m}
}

func createPolicyMap6(lc cell.Lifecycle, registry *metrics.Registry, cfg PolicyConfig, pinning ebpf.PinType) *PolicyMap6 {
	m := bpf.NewMap(
		PolicyMapName6,
		ebpf.LPMTrie,
		&EgressPolicyKey6{},
		&EgressPolicyVal6{},
		cfg.EgressGatewayPolicyMapMax,
		0,
	).WithPressureMetric(registry)

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			switch pinning {
			case ebpf.PinNone:
				return m.CreateUnpinned()
			case ebpf.PinByName:
				return m.OpenOrCreate()
			}
			return fmt.Errorf("received unexpected pin type: %d", pinning)
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &PolicyMap6{m}
}

// OpenPinnedPolicyMap4 opens an existing pinned IPv4 policy map.
func OpenPinnedPolicyMap4(logger *slog.Logger) (*PolicyMap4, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, PolicyMapName4), &EgressPolicyKey4{}, &EgressPolicyVal4{})
	if err != nil {
		return nil, err
	}

	return &PolicyMap4{m}, nil
}

// OpenPinnedPolicyMap6 opens an existing pinned IPv6 policy map.
func OpenPinnedPolicyMap6(logger *slog.Logger) (*PolicyMap6, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, PolicyMapName6), &EgressPolicyKey6{}, &EgressPolicyVal6{})
	if err != nil {
		return nil, err
	}

	return &PolicyMap6{m}, nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey4(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey4 {
	key := EgressPolicyKey4{}

	ones := destPrefix.Bits()
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits4 + uint32(ones)

	return key
}

// NewEgressPolicyVal4 returns a new EgressPolicyVal4 object representing for
// the given egress IP and gateway IPs
func NewEgressPolicyVal4(egressIP, gatewayIP netip.Addr) EgressPolicyVal4 {
	val := EgressPolicyVal4{}

	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)

	return val
}

// String returns the string representation of an egress policy key.
func (k *EgressPolicyKey4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-PolicyStaticPrefixBits4)
}

// New returns an egress policy key
func (k *EgressPolicyKey4) New() bpf.MapKey { return &EgressPolicyKey4{} }

// Match returns true if the sourceIP and destCIDR parameters match the egress
// policy key.
func (k *EgressPolicyKey4) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP &&
		k.GetDestCIDR() == destCIDR
}

// GetSourceIP returns the egress policy key's source IP.
func (k *EgressPolicyKey4) GetSourceIP() netip.Addr {
	addr, _ := netipx.FromStdIP(k.SourceIP.IP())
	return addr
}

// GetDestCIDR returns the egress policy key's destination CIDR.
func (k *EgressPolicyKey4) GetDestCIDR() netip.Prefix {
	addr, _ := netipx.FromStdIP(k.DestCIDR.IP())
	return netip.PrefixFrom(addr, int(k.PrefixLen-PolicyStaticPrefixBits4))
}

// New returns an egress policy value
func (v *EgressPolicyVal4) New() bpf.MapValue { return &EgressPolicyVal4{} }

// Match returns true if the egressIP and gatewayIP parameters match the egress
// policy value.
func (v *EgressPolicyVal4) Match(egressIP, gatewayIP netip.Addr) bool {
	return v.GetEgressAddr() == egressIP &&
		v.GetGatewayAddr() == gatewayIP
}

// GetEgressIP returns the egress policy value's egress IP.
func (v *EgressPolicyVal4) GetEgressAddr() netip.Addr {
	return v.EgressIP.Addr()
}

// GetGatewayIP returns the egress policy value's gateway IP.
func (v *EgressPolicyVal4) GetGatewayAddr() netip.Addr {
	return v.GatewayIP.Addr()
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyVal4) String() string {
	return fmt.Sprintf("%s %s", v.GetGatewayAddr(), v.GetEgressAddr())
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *PolicyMap4) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val, err := m.m.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*EgressPolicyVal4), err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *PolicyMap4) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := NewEgressPolicyVal4(egressIP, gatewayIP)

	return m.m.Update(&key, &val)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *PolicyMap4) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)

	return m.m.Delete(&key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m *PolicyMap4) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EgressPolicyKey4)
		value := v.(*EgressPolicyVal4)

		cb(key, value)
	})
}

// NewEgressPolicyKey6 returns a new EgressPolicyKey6 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey6(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey6 {
	key := EgressPolicyKey6{}

	ones := destPrefix.Bits()
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits6 + uint32(ones)

	return key
}

// NewEgressPolicyVal6 returns a new EgressPolicyVal6 object representing for
// the given egress IP and gateway IPs
func NewEgressPolicyVal6(egressIP, gatewayIP netip.Addr) EgressPolicyVal6 {
	val := EgressPolicyVal6{}

	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)

	return val
}

// String returns the string representation of an egress policy key.
func (k *EgressPolicyKey6) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-PolicyStaticPrefixBits6)
}

// New returns an egress policy key
func (k *EgressPolicyKey6) New() bpf.MapKey { return &EgressPolicyKey6{} }

// Match returns true if the sourceIP and destCIDR parameters match the egress
// policy key.
func (k *EgressPolicyKey6) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP &&
		k.GetDestCIDR() == destCIDR
}

// GetSourceIP returns the egress policy key's source IP.
func (k *EgressPolicyKey6) GetSourceIP() netip.Addr {
	addr, _ := netipx.FromStdIP(k.SourceIP.IP())
	return addr
}

// GetDestCIDR returns the egress policy key's destination CIDR.
func (k *EgressPolicyKey6) GetDestCIDR() netip.Prefix {
	addr, _ := netipx.FromStdIP(k.DestCIDR.IP())
	return netip.PrefixFrom(addr, int(k.PrefixLen-PolicyStaticPrefixBits6))
}

// New returns an egress policy value
func (v *EgressPolicyVal6) New() bpf.MapValue { return &EgressPolicyVal6{} }

// Match returns true if the egressIP and gatewayIP parameters match the egress
// policy value.
func (v *EgressPolicyVal6) Match(egressIP, gatewayIP netip.Addr) bool {
	return v.GetEgressAddr() == egressIP &&
		v.GetGatewayAddr() == gatewayIP
}

// GetEgressIP returns the egress policy value's egress IP.
func (v *EgressPolicyVal6) GetEgressAddr() netip.Addr {
	return v.EgressIP.Addr()
}

// GetGatewayIP returns the egress policy value's gateway IP.
func (v *EgressPolicyVal6) GetGatewayAddr() netip.Addr {
	return v.GatewayIP.Addr()
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyVal6) String() string {
	return fmt.Sprintf("%s %s", v.GetGatewayAddr(), v.GetEgressAddr())
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *PolicyMap6) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal6, error) {
	key := NewEgressPolicyKey6(sourceIP, destCIDR)
	val, err := m.m.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*EgressPolicyVal6), err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *PolicyMap6) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error {
	key := NewEgressPolicyKey6(sourceIP, destCIDR)
	val := NewEgressPolicyVal6(egressIP, gatewayIP)

	return m.m.Update(&key, &val)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *PolicyMap6) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey6(sourceIP, destCIDR)

	return m.m.Delete(&key)
}

// EgressPolicyIterateCallback6 represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback6 func(*EgressPolicyKey6, *EgressPolicyVal6)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m *PolicyMap6) IterateWithCallback(cb EgressPolicyIterateCallback6) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*EgressPolicyKey6)
		value := v.(*EgressPolicyVal6)

		cb(key, value)
	})
}
