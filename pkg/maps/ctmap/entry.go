// Copyright 2016-2018 Authors of Cilium
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

// CtEntry represents an entry in the connection tracking table.
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

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}
