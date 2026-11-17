// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// BenchmarkDNSCacheRestoreFanout keeps the number of names fixed and varies
// the number of IPs they resolve to.
func BenchmarkDNSCacheRestoreFanout(b *testing.B) {
	const nameCount = 320_000

	for _, ipCount := range []int{1, 64, 20_000, nameCount} {
		b.Run(fmt.Sprintf("names=%d/ips=%d", nameCount, ipCount), func(b *testing.B) {
			global, endpoint := NewDNSCache(0), NewDNSCache(0)
			global.DisableCleanupTrack()
			names := make([]string, nameCount)
			now := time.Now()
			for i := range names {
				names[i] = fmt.Sprintf("name-%06d.example.test.", i)
				ipIndex := i % ipCount
				ip := netip.AddrFrom4([4]byte{10, byte(ipIndex >> 16), byte(ipIndex >> 8), byte(ipIndex)})
				endpoint.Update(now, names[i], []netip.Addr{ip}, 3600)
				global.Update(now, names[i], []netip.Addr{ip}, 3600)
			}

			b.ReportAllocs()
			for b.Loop() {
				global.ReplaceFromCacheByNames(names, endpoint)
			}
			if len(global.forward) != nameCount || len(global.reverse) != ipCount {
				b.Fatal("restoration changed the number of names or IPs")
			}
		})
	}
}
