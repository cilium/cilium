// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

// +build !privileged_tests,integration_tests

package cmd

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	. "gopkg.in/check.v1"
)

// makeIPs generates count sequential IPv4 IPs
func makeIPs(count uint32) []net.IP {
	ips := make([]net.IP, 0, count)
	for i := uint32(0); i < count; i++ {
		ips = append(ips, net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i>>0)))
	}
	return ips
}

// BenchmarkFqdnCache tests how slow a full dump of DNSHistory from a number of
// endpoints is. Each endpoints has 1000 DNS lookups, each with 10 IPs. The
// dump iterates over all endpoints, lookups, and IPs.
func (ds *DaemonSuite) BenchmarkFqdnCache(c *C) {
	c.StopTimer()

	endpoints := make([]*endpoint.Endpoint, 0, c.N)
	for i := 0; i < c.N; i++ {
		lookupTime := time.Now()
		ep := &endpoint.Endpoint{} // only works because we only touch .DNSHistory
		ep.DNSHistory = fqdn.NewDNSCache(0)

		for i := 0; i < 1000; i++ {
			ep.DNSHistory.Update(lookupTime, fmt.Sprintf("domain-%d.com.", i), makeIPs(10), 1000)
		}

		endpoints = append(endpoints, ep)
	}
	c.StartTimer()

	extractDNSLookups(endpoints, "0.0.0.0/0", "*")
}
