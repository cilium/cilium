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
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/byteorder"
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
	Slave            uint16 `align:"slave"`
	TxFlagsSeen      uint8  `align:"tx_flags_seen"`
	RxFlagsSeen      uint8  `align:"rx_flags_seen"`
	SourceSecurityID uint32 `align:"src_sec_id"`
	LastTxReport     uint32 `align:"last_tx_report"`
	LastRxReport     uint32 `align:"last_rx_report"`
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// String returns the readable format
func (c *CtEntry) String() string {
	return fmt.Sprintf("expires=%d RxPackets=%d RxBytes=%d RxFlagsSeen=%#02x LastRxReport=%d TxPackets=%d TxBytes=%d TxFlagsSeen=%#02x LastTxReport=%d Flags=%#04x RevNAT=%d Slave=%d SourceSecurityID=%d \n",
		c.Lifetime,
		c.RxPackets,
		c.RxBytes,
		c.RxFlagsSeen,
		c.LastRxReport,
		c.TxPackets,
		c.TxBytes,
		c.TxFlagsSeen,
		c.LastTxReport,
		c.Flags,
		byteorder.NetworkToHost(c.RevNAT),
		c.Slave,
		c.SourceSecurityID)
}
