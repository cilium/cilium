// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicestats

import (
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

type netlinkReader struct{}

// NewNetlinkReader returns a Reader backed by rtnl_link_stats64, the
// generic per-device counters available on every link type.
func NewNetlinkReader() Reader {
	return netlinkReader{}
}

func (netlinkReader) Stats(iface string) (Stats, error) {
	link, err := safenetlink.LinkByName(iface)
	if err != nil {
		return Stats{}, err
	}

	s := link.Attrs().Statistics
	if s == nil {
		return Stats{}, nil
	}

	return Stats{
		RxPackets: s.RxPackets,
		TxPackets: s.TxPackets,
		RxBytes:   s.RxBytes,
		TxBytes:   s.TxBytes,
	}, nil
}
