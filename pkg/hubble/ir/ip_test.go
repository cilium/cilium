// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestIP_merge(t *testing.T) {
	ip1 := net.ParseIP("1.2.3.4")
	ip2 := net.ParseIP("4.5.6.7")

	uu := map[string]struct {
		ip1, ip2 IP
		e        IP
	}{
		"empty": {},

		"blank": {
			ip2: IP{IPVersion: 4, Source: ip1},
			e:   IP{IPVersion: 4, Source: ip1},
		},

		"noop": {
			ip1: IP{IPVersion: 6, Source: ip1},
			e:   IP{IPVersion: 6, Source: ip1},
		},

		"full": {
			ip1: IP{
				IPVersion:    4,
				Source:       ip1,
				Destination:  ip2,
				SourceXlated: "1.1.1.1",
			},
			ip2: IP{
				IPVersion:    6,
				Source:       ip2,
				Destination:  ip1,
				SourceXlated: "1.2.2.2",
				Encrypted:    true,
			},
			e: IP{
				IPVersion:    6,
				Source:       ip2,
				Destination:  ip1,
				SourceXlated: "1.2.2.2",
				Encrypted:    true,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.ip1.merge(u.ip2))
		})
	}
}

func Test_ipToProto(t *testing.T) {
	ip1 := net.ParseIP("1.2.3.4")
	ip2 := net.ParseIP("4.5.6.7")
	uu := map[string]struct {
		in *flow.IP
		e  IP
	}{
		"empty": {},

		"full": {
			in: &flow.IP{
				Source:       "1.2.3.4",
				Destination:  "4.5.6.7",
				SourceXlated: "1.1.1.1",
				IpVersion:    4,
				Encrypted:    true,
			},
			e: IP{
				Source:       ip1,
				Destination:  ip2,
				SourceXlated: "1.1.1.1",
				IPVersion:    4,
				Encrypted:    true,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, protoToIP(u.in))
		})
	}
}

func TestIP_toProto(t *testing.T) {
	ip1 := net.ParseIP("1.2.3.4")
	ip2 := net.ParseIP("4.5.6.7")
	uu := map[string]struct {
		in IP
		e  *flow.IP
	}{
		"empty": {},

		"partial": {
			in: IP{
				Source:       ip1,
				SourceXlated: "1.1.1.1",
				IPVersion:    4,
				Encrypted:    true,
			},
			e: &flow.IP{
				Source:       "1.2.3.4",
				SourceXlated: "1.1.1.1",
				IpVersion:    4,
				Encrypted:    true,
			},
		},

		"full": {
			in: IP{
				Source:       ip1,
				Destination:  ip2,
				SourceXlated: "1.1.1.1",
				IPVersion:    4,
				Encrypted:    true,
			},
			e: &flow.IP{
				Source:       "1.2.3.4",
				Destination:  "4.5.6.7",
				SourceXlated: "1.1.1.1",
				IpVersion:    4,
				Encrypted:    true,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}
