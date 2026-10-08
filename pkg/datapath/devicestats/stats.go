// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicestats

// Stats holds the generic link counters collected for a network device.
type Stats struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
}

// Reader fetches statistics for a network device
type Reader interface {
	Stats(iface string) (Stats, error)
}
