// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/spf13/pflag"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName = "cilium_egress_gw_policy_v4"
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
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

// PolicyMap is used to communicate EGW policies to the datapath.
type PolicyMap interface {
	Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error)
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
	IterateWithCallback(EgressPolicyIterateCallback) error
}

// policyMap is the internal representation of an egress policy map.
type policyMap struct {
	m *ebpf.Map
}

func createPolicyMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	*option.DaemonConfig
	PolicyConfig
}) (out struct {
	cell.Out

	bpf.MapOut[PolicyMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_POLICY_MAP":      PolicyMapName,
		"EGRESS_POLICY_MAP_SIZE": fmt.Sprint(in.EgressGatewayPolicyMapMax),
	}

	if !in.EnableIPv4EgressGateway {
		return
	}

	out.MapOut = bpf.NewMapOut(PolicyMap(createPolicyMap(in.Lifecycle, in.PolicyConfig, ebpf.PinByName)))
	return
}

// CreatePrivatePolicyMap creates an unpinned policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap(lc cell.Lifecycle, cfg PolicyConfig) PolicyMap {
	return createPolicyMap(lc, cfg, ebpf.PinNone)
}

func createPolicyMap(lc cell.Lifecycle, cfg PolicyConfig, pinning ebpf.PinType) *policyMap {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       PolicyMapName,
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(EgressPolicyKey4{})),
		ValueSize:  uint32(unsafe.Sizeof(EgressPolicyVal4{})),
		MaxEntries: uint32(cfg.EgressGatewayPolicyMapMax),
		Pinning:    pinning,
	})

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	return &policyMap{m}
}

func OpenPinnedPolicyMap() (PolicyMap, error) {
	m, err := ebpf.LoadRegisterMap(PolicyMapName)
	if err != nil {
		return nil, err
	}

	return &policyMap{m}, nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey4(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey4 {
	key := EgressPolicyKey4{}

	ones := destPrefix.Bits()
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits + uint32(ones)

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
	return netip.PrefixFrom(addr, int(k.PrefixLen-PolicyStaticPrefixBits))
}

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
func (m *policyMap) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := EgressPolicyVal4{}

	err := m.m.Lookup(&key, &val)

	return &val, err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *policyMap) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := NewEgressPolicyVal4(egressIP, gatewayIP)

	return m.m.Update(key, val, 0)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *policyMap) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)

	return m.m.Delete(key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m policyMap) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	return m.m.IterateWithCallback(&EgressPolicyKey4{}, &EgressPolicyVal4{},
		func(k, v interface{}) {
			key := k.(*EgressPolicyKey4)
			value := v.(*EgressPolicyVal4)

			cb(key, value)
		})
}
