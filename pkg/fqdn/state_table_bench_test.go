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
