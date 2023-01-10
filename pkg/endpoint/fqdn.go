// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"net/netip"
	"time"
)

const logSubsys = "fqdn"

// MarkDNSCTEntry records that dstIP is in use by a connection that is allowed
// by toFQDNs policy. The reverse lookup is attempted in both DNSHistory and
// DNSCTHistory, allowing short DNS TTLs but long-lived connections to
// persist there.DNSCTHistory is used to suppress delete handling of expired DNS
// lookups (in DNSHistory) and it relies on pkg/maps/ctmap/gc to call this
// function.
// Internally, the lookupTime is used to checkpoint this update so that
// dns-garbage-collector-job can correctly clear older connection data.
func (e *Endpoint) MarkDNSCTEntry(dstIP netip.Addr, now time.Time) {
	if !dstIP.IsValid() {
		e.Logger(logSubsys).Error("MarkDNSCTEntry called with invalid IP")
		return
	}

	e.DNSZombies.MarkAlive(now, dstIP)
}

// MarkCTGCTime is the START time of a GC run. It is used by the DNS garbage
// collector to determine whether a DNS zombie can be deleted. This is done by
// comparing the timestamp of the start CT GC run with the alive timestamps of
// specific DNS zombies IPs marked with MarkDNSCTEntry.
// NOTE: While the timestamp is the start of the run, it should be set AFTER
// the run completes. This avoids a race between the DNS garbage collector and
// the CT GC. This would occur when a DNS zombie that has not been visited by
// the CT GC run is seen by a concurrent DNS garbage collector run, and then
// deleted.
// The DNS garbage collector is in daemon/fqdn.go and the CT GC is in
// pkg/maps/ctmap/gc/gc.go
func (e *Endpoint) MarkCTGCTime(now time.Time) {
	e.DNSZombies.SetCTGCTime(now)
}
