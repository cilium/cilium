// Copyright 2016-2019 Authors of Cilium
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

package ctmap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
)

const (
	// MapTypeIPv4TCPLocal and friends are MapTypes which correspond to a
	// combination of the following attributes:
	// * IPv4 or IPv6;
	// * TCP or non-TCP (shortened to Any)
	// * Local (endpoint-specific) or global (endpoint-oblivious).
	MapTypeIPv4TCPLocal = iota
	MapTypeIPv6TCPLocal
	MapTypeIPv4TCPGlobal
	MapTypeIPv6TCPGlobal
	MapTypeIPv4AnyLocal
	MapTypeIPv6AnyLocal
	MapTypeIPv4AnyGlobal
	MapTypeIPv6AnyGlobal
	MapTypeMax
)

// MapType is a type of connection tracking map.
type MapType int

// String renders the map type into a user-readable string.
func (m MapType) String() string {
	switch m {
	case MapTypeIPv4TCPLocal:
		return "Local IPv4 TCP CT map"
	case MapTypeIPv6TCPLocal:
		return "Local IPv6 TCP CT map"
	case MapTypeIPv4TCPGlobal:
		return "Global IPv4 TCP CT map"
	case MapTypeIPv6TCPGlobal:
		return "Global IPv6 TCP CT map"
	case MapTypeIPv4AnyLocal:
		return "Local IPv4 non-TCP CT map"
	case MapTypeIPv6AnyLocal:
		return "Local IPv6 non-TCP CT map"
	case MapTypeIPv4AnyGlobal:
		return "Global IPv4 non-TCP CT map"
	case MapTypeIPv6AnyGlobal:
		return "Global IPv6 non-TCP CT map"
	}
	return fmt.Sprintf("Unknown (%d)", int(m))
}

func (m MapType) isIPv4() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv4TCPGlobal, MapTypeIPv4AnyLocal, MapTypeIPv4AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isIPv6() bool {
	switch m {
	case MapTypeIPv6TCPLocal, MapTypeIPv6TCPGlobal, MapTypeIPv6AnyLocal, MapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isLocal() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv6TCPLocal, MapTypeIPv4AnyLocal, MapTypeIPv6AnyLocal:
		return true
	}
	return false
}

func (m MapType) isGlobal() bool {
	switch m {
	case MapTypeIPv4TCPGlobal, MapTypeIPv6TCPGlobal, MapTypeIPv4AnyGlobal, MapTypeIPv6AnyGlobal:
		return true
	}
	return false
}

func (m MapType) isTCP() bool {
	switch m {
	case MapTypeIPv4TCPLocal, MapTypeIPv6TCPLocal, MapTypeIPv4TCPGlobal, MapTypeIPv6TCPGlobal:
		return true
	}
	return false
}

type CtKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() CtKey

	// ToHost converts fields to host byte order.
	ToHost() CtKey

	// Dump contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer, reverse bool) bool

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
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// ToHost converts CtKey ports to host byte order.
func (k *CtKey4) ToHost() CtKey {
	n := *k
	n.SourcePort = byteorder.NetworkToHost(n.SourcePort).(uint16)
	n.DestPort = byteorder.NetworkToHost(n.DestPort).(uint16)
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

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k *CtKey4) Dump(buffer *bytes.Buffer, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
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

// Dump writes the contents of key to buffer and returns true if the
// value for next header in the key is nonzero.
func (k *CtKey4Global) Dump(buffer *bytes.Buffer, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.IP().String()
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrSource = k.SourceAddr.IP().String()
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
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

// Dump writes the contents of key to buffer and returns true if the value for
// next header in the key is nonzero.
func (k *CtKey6) Dump(buffer *bytes.Buffer, reverse bool) bool {
	var addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			k.NextHeader.String(), addrDest, k.SourcePort,
			k.DestPort),
		)
	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			k.NextHeader.String(), addrDest, k.DestPort,
			k.SourcePort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
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

// Dump writes the contents of key to buffer and returns true if the
// value for next header in the key is nonzero.
func (k *CtKey6Global) Dump(buffer *bytes.Buffer, reverse bool) bool {
	var addrSource, addrDest string

	if k.NextHeader == 0 {
		return false
	}

	// Addresses swapped, see issue #5848
	if reverse {
		addrSource = k.DestAddr.IP().String()
		addrDest = k.SourceAddr.IP().String()
	} else {
		addrSource = k.SourceAddr.IP().String()
		addrDest = k.DestAddr.IP().String()
	}

	if k.Flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s:%d -> %s:%d ",
			k.NextHeader.String(), addrSource, k.SourcePort,
			addrDest, k.DestPort),
		)
	}

	if k.Flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	if k.Flags&TUPLE_F_SERVICE != 0 {
		buffer.WriteString("service ")
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
	RxBytes   uint64 `align:"rx_bytes"`
	TxPackets uint64 `align:"tx_packets"`
	TxBytes   uint64 `align:"tx_bytes"`
	Lifetime  uint32 `align:"lifetime"`
	Flags     uint16 `align:"rx_closing"`
	// RevNAT is in network byte order
	RevNAT           uint16 `align:"rev_nat_index"`
	_                uint16 `align:"backend_id"`
	TxFlagsSeen      uint8  `align:"tx_flags_seen"`
	RxFlagsSeen      uint8  `align:"rx_flags_seen"`
	SourceSecurityID uint32 `align:"src_sec_id"`
	LastTxReport     uint32 `align:"last_tx_report"`
	LastRxReport     uint32 `align:"last_rx_report"`
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

const (
	RxClosing  = 1 << 0
	TxClosing  = 1 << 1
	Nat64      = 1 << 2
	LBLoopback = 1 << 3
	SeenNonSyn = 1 << 4
	NodePort   = 1 << 5
)

func (c *CtEntry) flagsString() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Flags=%#04x [ ", c.Flags))
	if (c.Flags & RxClosing) != 0 {
		buffer.WriteString("RxClosing ")
	}
	if (c.Flags & TxClosing) != 0 {
		buffer.WriteString("TxClosing ")
	}
	if (c.Flags & Nat64) != 0 {
		buffer.WriteString("Nat64 ")
	}
	if (c.Flags & LBLoopback) != 0 {
		buffer.WriteString("LBLoopback ")
	}
	if (c.Flags & SeenNonSyn) != 0 {
		buffer.WriteString("SeenNonSyn ")
	}
	if (c.Flags & NodePort) != 0 {
		buffer.WriteString("NodePort ")
	}
	buffer.WriteString("]")
	return buffer.String()
}

// String returns the readable format
func (c *CtEntry) String() string {
	return fmt.Sprintf("expires=%d RxPackets=%d RxBytes=%d RxFlagsSeen=%#02x LastRxReport=%d TxPackets=%d TxBytes=%d TxFlagsSeen=%#02x LastTxReport=%d %s RevNAT=%d SourceSecurityID=%d \n",
		c.Lifetime,
		c.RxPackets,
		c.RxBytes,
		c.RxFlagsSeen,
		c.LastRxReport,
		c.TxPackets,
		c.TxBytes,
		c.TxFlagsSeen,
		c.LastTxReport,
		c.flagsString(),
		byteorder.NetworkToHost(c.RevNAT),
		c.SourceSecurityID)
}
