// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"net"
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
func (e *Endpoint) MarkDNSCTEntry(dstIP net.IP, now time.Time) {
	if dstIP == nil {
		e.Logger(logSubsys).Error("MarkDNSCTEntry called with nil IP")
		return
	}

	e.DNSZombies.MarkAlive(now, dstIP)
}

// MarkCTGCTime is the START time of a GC run. It is used by the DNS garbage
// collector to determine whether a DNS zombie can be deleted. This is done by
// comparing the timestamp of the start CT GC run with the ailve timestamps of
// specific DNS zombies IPs marked with MarkDNSCTEntry.
// NOTE: While the timestamp is ths start of the run, it should be set AFTER
// the run completes. This avoids a race between the DNS garbage collector and
// the CT GC. This would occur when a DNS zombie that has not been visited by
// the CT GC run is seen by a concurrent DNS garbage collector run, and then
// deleted.
// The DNS garbage collector is in daemon/fqdn.go and the CT GC is in
// pkg/maps/ctmap/gc/gc.go
func (e *Endpoint) MarkCTGCTime(now time.Time) {
	e.DNSZombies.SetCTGCTime(now)
}
