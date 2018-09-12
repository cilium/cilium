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
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
	Lifetime  uint32
	Flags     uint16
	// RevNAT is in network byte order
	RevNAT           uint16
	Slave            uint16
	TxFlagsSeen      uint8
	RxFlagsSeen      uint8
	SourceSecurityID uint32
	LastTxReport     uint32
	LastRxReport     uint32
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// String returns the readable format
func (c *CtEntry) String() string {
	return fmt.Sprintf("expires=%d RxPackets=%d RxBytes=%d TxPackets=%d TxBytes=%d Flags=%x RevNAT=%d SourceSecurityID=%d\n",
		c.Lifetime,
		c.RxPackets,
		c.RxBytes,
		c.TxPackets,
		c.TxBytes,
		c.Flags,
		byteorder.NetworkToHost(c.RevNAT),
		c.SourceSecurityID)
}

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}
