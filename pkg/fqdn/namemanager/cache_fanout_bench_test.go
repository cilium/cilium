// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"fmt"
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/time"
)

// BenchmarkDNSCacheRestoreFanout measures candidate removal with different
// numbers of names per IP. The endpoint caches share mappings but have different TTLs.
// Live zombie accumulation and endpoint cache setup are outside timing.
func BenchmarkDNSCacheRestoreFanout(b *testing.B) {
	const nameCount = 320_000

	for _, ipCount := range []int{1, 64, 20_000, nameCount} {
		for _, source := range []string{"zombies", "endpoint"} {
			b.Run(fmt.Sprintf("names=%d/ips=%d/source=%s", nameCount, ipCount, source), func(b *testing.B) {
				first, second := fqdn.NewDNSCache(0), fqdn.NewDNSCache(0)
				n := manager{cache: newNameCache(), updatedCaches: sets.New(first, second)}
				names := sets.New[string]()
				alive := newNameIPSet()
				now := time.Now()
				for i := range nameCount {
					name := fmt.Sprintf("name-%06d.example.test.", i)
					names.Insert(name)
					ipIndex := i % ipCount
					ip := netip.AddrFrom4([4]byte{10, byte(ipIndex >> 16), byte(ipIndex >> 8), byte(ipIndex)})
					if source == "zombies" {
						alive.add(name, ip)
					} else {
						first.Update(now, name, []netip.Addr{ip}, 3600)
						second.Update(now, name, []netip.Addr{ip}, 7200)
					}
					n.cache.add(name, ip)
				}

				var removed map[string]set.Set[netip.Addr]
				b.ReportAllocs()
				for b.Loop() {
					n.Lock()
					removed = n.removeStaleIPs(names, &alive)
					n.Unlock()
				}
				if len(removed) != 0 || len(n.cache.entries.byName) != nameCount {
					b.Fatal("restoration removed live mappings")
				}
				ips := sets.New[netip.Addr]()
				for _, addresses := range n.cache.entries.byName {
					if addresses.Len() != 1 {
						b.Fatal("restoration changed the number of IPs for a name")
					}
					for ip := range addresses.Members() {
						ips.Insert(ip)
					}
				}
				if len(ips) != ipCount {
					b.Fatal("restoration changed the number of IPs")
				}
			})
		}
	}
}
