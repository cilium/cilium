// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/statedb"
)

// BenchmarkFQDNStateUpdates measures writes with the indexes used by the FQDN
// table. Each DNS response contains eight addresses; a transaction can contain
// one or eight responses. The table starts with 512 names and 4,096 mappings.
func BenchmarkFQDNStateUpdates(b *testing.B) {
	const (
		names      = 512
		ipsPerName = 8
		lookupTTL  = time.Minute
	)
	db := statedb.New()
	table, err := NewFQDNStateTable(db)
	if err != nil {
		b.Fatal(err)
	}
	rows := make([]FQDNMapping, 0, names*ipsPerName)
	lookupTime := time.Unix(1_700_000_000, 0)
	for nameIndex := range names {
		name := fmt.Sprintf("service-%d.example.com.", nameIndex)
		for ipIndex := range ipsPerName {
			rows = append(rows, FQDNMapping{
				Name: name,
				IP: netip.AddrFrom4([4]byte{
					10, byte(nameIndex >> 8), byte(nameIndex), byte(ipIndex + 1),
				}),
				LookupTime:     lookupTime,
				TTL:            uint32(lookupTTL / time.Second),
				ExpirationTime: lookupTime.Add(lookupTTL),
			})
		}
	}
	txn := db.WriteTxn(table)
	for _, row := range rows {
		if _, _, err := table.Insert(txn, row); err != nil {
			b.Fatal(err)
		}
	}
	txn.Commit()

	for _, responsesPerTxn := range []int{1, 8} {
		b.Run(fmt.Sprintf("responses_per_txn=%d", responsesPerTxn), func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(responsesPerTxn*ipsPerName), "rows/op")
			for iteration := range b.N {
				txn := db.WriteTxn(table)
				for response := range responsesPerTxn {
					nameIndex := (iteration*responsesPerTxn + response) % names
					for _, original := range rows[nameIndex*ipsPerName : (nameIndex+1)*ipsPerName] {
						row := original
						row.LookupTime = lookupTime.Add(time.Duration(iteration+1) * time.Second)
						row.ExpirationTime = row.LookupTime.Add(lookupTTL)
						if _, _, err := table.Insert(txn, row); err != nil {
							b.Fatal(err)
						}
					}
				}
				txn.Commit()
			}
		})
	}
}

// BenchmarkDNSCacheUpdates provides a baseline for the same names and IPs using
// the existing DNSCache update path.
func BenchmarkDNSCacheUpdates(b *testing.B) {
	const (
		names      = 512
		ipsPerName = 8
	)
	lookupTime := time.Unix(1_700_000_000, 0)
	nameList := make([]string, names)
	ipList := make([][]netip.Addr, names)
	for nameIndex := range names {
		nameList[nameIndex] = fmt.Sprintf("service-%d.example.com.", nameIndex)
		ips := make([]netip.Addr, 0, ipsPerName)
		for ipIndex := range ipsPerName {
			ips = append(ips, netip.AddrFrom4([4]byte{
				10, byte(nameIndex >> 8), byte(nameIndex), byte(ipIndex + 1),
			}))
		}
		ipList[nameIndex] = ips
	}

	for _, responsesPerOp := range []int{1, 8} {
		b.Run(fmt.Sprintf("responses_per_op=%d", responsesPerOp), func(b *testing.B) {
			cache := NewDNSCache(0)
			for nameIndex := range names {
				cache.Update(lookupTime, nameList[nameIndex], ipList[nameIndex], 60)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.ReportMetric(float64(responsesPerOp*ipsPerName), "rows/op")
			for iteration := range b.N {
				for response := range responsesPerOp {
					nameIndex := (iteration*responsesPerOp + response) % names
					cache.Update(
						lookupTime.Add(time.Duration(iteration+1)*time.Second),
						nameList[nameIndex], ipList[nameIndex], 60,
					)
				}
			}
		})
	}
}

// BenchmarkEndpointFQDNLookup compares the core indexed endpoint/IP lookup
// with the existing per-endpoint DNS cache lookup. It excludes name formatting.
func BenchmarkEndpointFQDNLookup(b *testing.B) {
	const (
		endpoints = 512
		names     = 8
	)
	db := statedb.New()
	table, err := NewEndpointFQDNStateTable(db)
	if err != nil {
		b.Fatal(err)
	}
	ip := netip.MustParseAddr("1.1.1.1")
	expiration := time.Now().Add(time.Hour)
	caches := make([]*DNSCache, endpoints)
	txn := db.WriteTxn(table)
	for endpointID := range endpoints {
		cache := NewDNSCache(0)
		caches[endpointID] = cache
		for nameIndex := range names {
			name := fmt.Sprintf("service-%d-%d.example.com.", endpointID, nameIndex)
			row := EndpointFQDNMapping{
				EndpointID:     uint16(endpointID),
				Name:           name,
				IP:             ip,
				LookupTime:     expiration.Add(-time.Hour),
				TTL:            3600,
				ExpirationTime: expiration,
			}
			if _, _, err := table.Insert(txn, row); err != nil {
				b.Fatal(err)
			}
			cache.Update(row.LookupTime, name, []netip.Addr{ip}, int(row.TTL))
		}
	}
	txn.Commit()

	b.Run("statedb", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := range b.N {
			query := QueryEndpointFQDNByEndpointIP(EndpointFQDNIPKey{
				EndpointID: uint16(iteration % endpoints),
				IP:         ip,
			})
			found := 0
			for range table.List(db.ReadTxn(), query) {
				found++
			}
			if found != names {
				b.Fatalf("got %d names, want %d", found, names)
			}
		}
	})
	b.Run("dns-cache", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := range b.N {
			found := caches[iteration%endpoints].LookupIP(ip)
			if len(found) != names {
				b.Fatalf("got %d names, want %d", len(found), names)
			}
		}
	})
}
