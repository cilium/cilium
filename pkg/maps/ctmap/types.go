// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
)

// mapType is a type of connection tracking map.
type mapType int

const (
	// mapTypeIPv4TCPLocal and friends are map types which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * TCP or non-TCP (shortened to Any)
	// * Local (endpoint-specific) or global (endpoint-oblivious).
	mapTypeIPv4TCPLocal mapType = iota
	mapTypeIPv6TCPLocal
	mapTypeIPv4TCPGlobal
	mapTypeIPv6TCPGlobal
	mapTypeIPv4AnyLocal
	mapTypeIPv6AnyLocal
	mapTypeIPv4AnyGlobal
	mapTypeIPv6AnyGlobal
	mapTypeMax
)

// String renders the map type into a user-readable string.
func (m mapType) String() string {
	switch m {
	case mapTypeIPv4TCPLocal:
		return "Local IPv4 TCP CT map"
	case mapTypeIPv6TCPLocal:
		return "Local IPv6 TCP CT map"
	case mapTypeIPv4TCPGlobal:
		return "Global IPv4 TCP CT map"
	case mapTypeIPv6TCPGlobal:
		return "Global IPv6 TCP CT map"
	case mapTypeIPv4AnyLocal:
		return "Local IPv4 non-TCP CT map"
	case mapTypeIPv6AnyLocal:
		return "Local IPv6 non-TCP CT map"
	case mapTypeIPv4AnyGlobal:
		return "Global IPv4 non-TCP CT map"
	case mapTypeIPv6AnyGlobal:
		return "Global IPv6 non-TCP CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m mapType) isIPv4() bool {
	switch m {
	case mapTypeIPv4TCPLocal, mapTypeIPv4TCPGlobal, mapTypeIPv4AnyLocal, mapTypeIPv4AnyGlobal:
		return true
	}
	return false
}

func (m mapType) isIPv6() bool {
	switch m {
	case mapTypeIPv6TCPLocal, mapTypeIPv6TCPGlobal, mapTypeIPv6AnyLocal, mapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m mapType) isLocal() bool {
	switch m {
	case mapTypeIPv4TCPLocal, mapTypeIPv6TCPLocal, mapTypeIPv4AnyLocal, mapTypeIPv6AnyLocal:
		return true
	}
	return false
}

func (m mapType) isGlobal() bool {
	switch m {
	case mapTypeIPv4TCPGlobal, mapTypeIPv6TCPGlobal, mapTypeIPv4AnyGlobal, mapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m mapType) isTCP() bool {
	switch m {
	case mapTypeIPv4TCPLocal, mapTypeIPv6TCPLocal, mapTypeIPv4TCPGlobal, mapTypeIPv6TCPGlobal:
		return true
	}
	return false
}

type CTMapIPVersion int

const (
	CTMapIPv4 CTMapIPVersion = iota
	CTMapIPv6
)

// FilterMapsByProto filters the given CT maps by the given IP version, and
// returns two maps - one for TCP and one for any protocol.
func FilterMapsByProto(maps []*Map, ipVsn CTMapIPVersion) (ctMapTCP *Map, ctMapAny *Map) {
	for _, m := range maps {
		switch ipVsn {
		case CTMapIPv4:
			switch m.mapType {
			case mapTypeIPv4TCPLocal, mapTypeIPv4TCPGlobal:
				ctMapTCP = m
			case mapTypeIPv4AnyLocal, mapTypeIPv4AnyGlobal:
				ctMapAny = m
			}
		case CTMapIPv6:
			switch m.mapType {
			case mapTypeIPv6TCPLocal, mapTypeIPv6TCPGlobal:
				ctMapTCP = m
			case mapTypeIPv6AnyLocal, mapTypeIPv6AnyGlobal:
				ctMapAny = m
			}
		}
	}
	return
}

type CtKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() CtKey

	// ToHost converts fields to host byte order.
	ToHost() CtKey

	// Dump contents of key to sb. Returns true if successful.
	Dump(sb *strings.Builder, reverse bool) bool

	// GetFlags flags containing the direction of the CtKey.
	GetFlags() uint8

	GetTupleKey() tuple.TupleKey
}

// CtKey4 is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey4 struct {
	tuple.TupleKey4
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey4) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4 ports to network byte order.
func (k *CtKey4) ToNetwork() CtKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork16(n.SourcePort)
	n.DestPort = byteorder.HostToNetwork16(n.DestPort)
	return &n
}

// ToHost converts CtKey ports to host byte order.
func (k *CtKey4) ToHost() CtKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost16(n.SourcePort)
	n.DestPort = byteorder.NetworkToHost16(n.DestPort)
	return &n
}

// GetFlags returns the tuple's flags.
func (k *CtKey4) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey4) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey4) Dump(sb *strings.Builder, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.String()
	} else {
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

func (k *CtKey4) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey4
}

// CtKey4Global is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey4Global struct {
	tuple.TupleKey4Global
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey4Global) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey4Global type here into a local key type in the nested
// TupleKey4Global field.
func (k *CtKey4Global) ToNetwork() CtKey {
	return &CtKey4Global{
		TupleKey4Global: *k.TupleKey4Global.ToNetwork().(*tuple.TupleKey4Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey4Global type here into a local key type in the nested
// TupleKey4Global field.
func (k *CtKey4Global) ToHost() CtKey {
	return &CtKey4Global{
		TupleKey4Global: *k.TupleKey4Global.ToHost().(*tuple.TupleKey4Global),
	}
}

// GetFlags returns the tuple's flags.
func (k *CtKey4Global) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey4Global) String() string {
	return fmt.Sprintf("%s:%d --> %s:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey4Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey4Global) Dump(sb *strings.Builder, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.String()
		addrDest = k.SourceAddr.String()
	} else {
		addrSource = k.SourceAddr.String()
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

func (k *CtKey4Global) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey4Global
}

// CtKey6 is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey6 struct {
	tuple.TupleKey6
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey6) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey6 ports to network byte order.
func (k *CtKey6) ToNetwork() CtKey {
	return &CtKey6{
		TupleKey6: *k.TupleKey6.ToNetwork().(*tuple.TupleKey6),
	}
}

// ToHost converts CtKey ports to host byte order.
func (k *CtKey6) ToHost() CtKey {
	return &CtKey6{
		TupleKey6: *k.TupleKey6.ToHost().(*tuple.TupleKey6),
	}
}

// GetFlags returns the tuple's flags.
func (k *CtKey6) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey6) String() string {
	return fmt.Sprintf("[%s]:%d, %d, %d, %d", k.DestAddr, k.SourcePort, k.DestPort, k.NextHeader, k.Flags)
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey6) Dump(sb *strings.Builder, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.String()
	} else {
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

func (k *CtKey6) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey6
}

// CtKey6Global is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey6Global struct {
	tuple.TupleKey6Global
}

const SizeofCtKey6Global = int(unsafe.Sizeof(CtKey6Global{}))

// NewValue creates a new bpf.MapValue.
func (k *CtKey6Global) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey6Global type here into a local key type in the nested
// TupleKey6Global field.
func (k *CtKey6Global) ToNetwork() CtKey {
	return &CtKey6Global{
		TupleKey6Global: *k.TupleKey6Global.ToNetwork().(*tuple.TupleKey6Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the CtKey6Global type here into a local key type in the nested
// TupleKey6Global field.
func (k *CtKey6Global) ToHost() CtKey {
	return &CtKey6Global{
		TupleKey6Global: *k.TupleKey6Global.ToHost().(*tuple.TupleKey6Global),
	}
}

// GetFlags returns the tuple's flags.
func (k *CtKey6Global) GetFlags() uint8 {
	return k.Flags
}

func (k *CtKey6Global) String() string {
	return fmt.Sprintf("[%s]:%d --> [%s]:%d, %d, %d", k.SourceAddr, k.SourcePort, k.DestAddr, k.DestPort, k.NextHeader, k.Flags)
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *CtKey6Global) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// Dump writes the contents of key to sb and returns true if the value for next
// header in the key is nonzero.
func (k *CtKey6Global) Dump(sb *strings.Builder, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.String()
		addrDest = k.SourceAddr.String()
	} else {
		addrSource = k.SourceAddr.String()
		addrDest = k.DestAddr.String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		sb.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		sb.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		sb.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		sb.WriteString("service ")
	}

	return true
}

func (k *CtKey6Global) GetTupleKey() tuple.TupleKey {
	return &k.TupleKey6Global
}

// CtEntry represents an entry in the connection tracking table.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type CtEntry struct {
	RxPackets uint64 `align:"rx_packets"`
	RxBytes   uint64 `align:"$union0"`
	TxPackets uint64 `align:"tx_packets"`
	TxBytes   uint64 `align:"tx_bytes"`
	Lifetime  uint32 `align:"lifetime"`
	Flags     uint16 `align:"rx_closing"`
	// RevNAT is in network byte order
	RevNAT           uint16 `align:"rev_nat_index"`
	IfIndex          uint16 `align:"ifindex"`
	TxFlagsSeen      uint8  `align:"tx_flags_seen"`
	RxFlagsSeen      uint8  `align:"rx_flags_seen"`
	SourceSecurityID uint32 `align:"src_sec_id"`
	LastTxReport     uint32 `align:"last_tx_report"`
	LastRxReport     uint32 `align:"last_rx_report"`
}

const SizeofCtEntry = int(unsafe.Sizeof(CtEntry{}))

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

const (
	RxClosing = 1 << iota
	TxClosing
	Nat64
	LBLoopback
	SeenNonSyn
	NodePort
	ProxyRedirect
	DSR
	FromL7LB
	Reserved1
	FromTunnel
	MaxFlags
)

func (c *CtEntry) flagsString() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Flags=%#04x [ ", c.Flags))
	if (c.Flags & RxClosing) != 0 {
		sb.WriteString("RxClosing ")
	}
	if (c.Flags & TxClosing) != 0 {
		sb.WriteString("TxClosing ")
	}
	if (c.Flags & Nat64) != 0 {
		sb.WriteString("Nat64 ")
	}
	if (c.Flags & LBLoopback) != 0 {
		sb.WriteString("LBLoopback ")
	}
	if (c.Flags & SeenNonSyn) != 0 {
		sb.WriteString("SeenNonSyn ")
	}
	if (c.Flags & NodePort) != 0 {
		sb.WriteString("NodePort ")
	}
	if (c.Flags & ProxyRedirect) != 0 {
		sb.WriteString("ProxyRedirect ")
	}
	if (c.Flags & DSR) != 0 {
		sb.WriteString("DSR ")
	}
	if (c.Flags & FromL7LB) != 0 {
		sb.WriteString("FromL7LB ")
	}
	if (c.Flags & FromTunnel) != 0 {
		sb.WriteString("FromTunnel ")
	}

	unknownFlags := c.Flags
	unknownFlags &^= MaxFlags - 1
	if unknownFlags != 0 {
		sb.WriteString(fmt.Sprintf("Unknown=%#04x ", unknownFlags))
	}
	sb.WriteString("]")
	return sb.String()
}

func (c *CtEntry) StringWithTimeDiff(toRemSecs func(uint32) string) string {

	var timeDiff string
	if toRemSecs != nil {
		timeDiff = fmt.Sprintf(" (%s)", toRemSecs(c.Lifetime))
	} else {
		timeDiff = ""
	}

	return fmt.Sprintf("expires=%d%s RxPackets=%d RxBytes=%d RxFlagsSeen=%#02x LastRxReport=%d TxPackets=%d TxBytes=%d TxFlagsSeen=%#02x LastTxReport=%d %s RevNAT=%d SourceSecurityID=%d IfIndex=%d \n",
		c.Lifetime,
		timeDiff,
		c.RxPackets,
		c.RxBytes,
		c.RxFlagsSeen,
		c.LastRxReport,
		c.TxPackets,
		c.TxBytes,
		c.TxFlagsSeen,
		c.LastTxReport,
		c.flagsString(),
		byteorder.NetworkToHost16(c.RevNAT),
		c.SourceSecurityID,
		c.IfIndex)
}

// String returns the readable format
func (c *CtEntry) String() string {
	return c.StringWithTimeDiff(nil)
}
