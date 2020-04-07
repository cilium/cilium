// Copyright 2019 Authors of Hubble
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

// +build !privileged_tests

package fqdncache

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertContainsEntry(t *testing.T, f *FQDNCache, m *models.DNSLookup) {
	e := fromModel(m)
	ep, ok := f.endpoints[uint64(e.EndpointID)]
	require.True(t, ok, "endpoint not found")
	for _, ip := range e.Ips {
		lookups, ok := ep.ipToNames[ip]
		require.True(t, ok, "ip not found")
		assert.Contains(t, lookups, e)
	}
}

func TestFQDNCache_GetNamesOf(t *testing.T) {
	type args struct {
		epID uint64
		ip   net.IP
	}
	tests := []struct {
		name    string
		entries []*models.DNSLookup
		args    args
		want    []string
	}{
		{
			name: "entries by endpoint",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 30),
				newModel(1, time.Unix(0, 0), "ebpf.io.", []net.IP{net.ParseIP("2.2.2.2"), net.ParseIP("1.1.1.1")}, 30),
				newModel(2, time.Unix(0, 0), "wrong.endpoint.local", []net.IP{net.ParseIP("1.1.1.1")}, 30),
			},
			args: args{
				epID: 1,
				ip:   net.ParseIP("1.1.1.1"),
			},
			want: []string{"cilium.io", "ebpf.io"},
		},
		{
			name: "deduplicate domains",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 30),
				newModel(1, time.Unix(0, 0), "cilium.io", []net.IP{net.ParseIP("2.2.2.2"), net.ParseIP("1.1.1.1")}, 30),
			},
			args: args{
				epID: 1,
				ip:   net.ParseIP("1.1.1.1"),
			},
			want: []string{"cilium.io"},
		},
		{
			name: "missing entry",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "cilium.io.", []net.IP{}, 30),
			},
			args: args{
				epID: 1,
				ip:   net.ParseIP("1.1.1.1"),
			},
			want: nil,
		},
		{
			name: "missing endpoint",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "cilium.io.", []net.IP{net.ParseIP("1.1.1.1")}, 30),
			},
			args: args{
				epID: 2,
				ip:   net.ParseIP("1.1.1.1"),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New()
			f.InitializeFrom(tt.entries)
			got := f.GetNamesOf(tt.args.epID, tt.args.ip)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFQDNCache_AddDNSLookup(t *testing.T) {
	type args struct {
		epID       uint64
		lookupTime time.Time
		domainName string
		ips        []net.IP
		ttl        uint32
	}
	tests := []struct {
		name    string
		entries []*models.DNSLookup
		args    args
	}{
		{
			name: "add new endpoint",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "ebpf.io.", []net.IP{net.ParseIP("2.2.2.2")}, 10),
			},
			args: args{
				epID:       2,
				lookupTime: time.Unix(1, 0),
				domainName: "cilium.io.",
				ips:        []net.IP{net.ParseIP("1.1.1.1")},
				ttl:        20,
			},
		},
		{
			name: "add to same endpoint",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "ebpf.io.", []net.IP{net.ParseIP("2.2.2.2")}, 10),
			},
			args: args{
				epID:       1,
				lookupTime: time.Unix(1, 0),
				domainName: "cilium.io.",
				ips:        []net.IP{net.ParseIP("1.1.1.1")},
				ttl:        20,
			},
		},
		{
			name: "add to same ip",
			entries: []*models.DNSLookup{
				newModel(1, time.Unix(0, 0), "ebpf.io.", []net.IP{net.ParseIP("1.1.1.1")}, 10),
			},
			args: args{
				epID:       1,
				lookupTime: time.Unix(1, 0),
				domainName: "cilium.io.",
				ips:        []net.IP{net.ParseIP("1.1.1.1")},
				ttl:        20,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New()
			f.InitializeFrom(tt.entries)
			f.AddDNSLookup(tt.args.epID, tt.args.lookupTime, tt.args.domainName, tt.args.ips, tt.args.ttl)
			// check that the cache contains all previous entries pus the inserted one
			inserted := newModel(tt.args.epID, tt.args.lookupTime, tt.args.domainName, tt.args.ips, tt.args.ttl)
			assertContainsEntry(t, f, inserted)
			for _, e := range tt.entries {
				assertContainsEntry(t, f, e)
			}
		})
	}
}
