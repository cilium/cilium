// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package types

import "github.com/cilium/cilium/pkg/tuple"

type CtKey4 struct {
	tuple.TupleKey4
}

type CtKey4Global struct {
	tuple.TupleKey4Global
}

type CtKey6 struct {
	tuple.TupleKey6
}

type CtKey6Global struct {
	tuple.TupleKey6Global
}

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

type PerClusterCTMapVal struct {
	Fd uint32
}
