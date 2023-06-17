// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

type BPFIPCacheGetSuite struct{}

var _ = Suite(&BPFIPCacheGetSuite{})

func (s *BPFIPCacheGetSuite) TestGetPrefix(c *C) {
	tests := []struct {
		ip     net.IP
		prefix []byte
		length int
	}{
		{
			ip:     mustParseIP("213.234.255.89"),
			prefix: []byte{0xD5, 0xEA, 0xFF, 0x59},
			length: 8 * net.IPv4len,
		},
		{
			ip:     mustParseIP("f0ed:0db8:cafe:0000:0000:beef:0042:8329"),
			prefix: []byte{0xf0, 0xed, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0xbe, 0xef, 0x00, 0x42, 0x83, 0x29},
			length: 8 * net.IPv6len,
		},
	}

	for _, tt := range tests {
		prefix := toBits(tt.prefix)
		for maskSize := 0; maskSize <= tt.length; maskSize++ {
			c.Assert(getPrefix(tt.ip, maskSize), checker.DeepEquals, prefix[:maskSize], Commentf("invalid prefix for %v/%v", tt.ip, maskSize))
		}
	}
}

func (s *BPFIPCacheGetSuite) TestGetLPMValue(c *C) {
	entries := map[string][]string{
		"10.0.0.0/8":     {"2"},
		"10.0.0.0/16":    {"9"},
		"10.0.0.0/32":    {"8"},
		"10.128.0.0/9":   {"4", "20"},
		"feed::ed/112":   {"3"},
		"feed::feed/128": {"5", "17"},
	}

	tests := []struct {
		ip          string   // Input ip address.
		hasIdentity bool     // true if a match should be found.
		identity    []string // Expected identity if match should be found.
	}{
		{"10.1.0.0", true, entries["10.0.0.0/8"]},
		{"10.1.0.255", true, entries["10.0.0.0/8"]},
		{"10.0.1.0", true, entries["10.0.0.0/16"]},
		{"10.0.0.0", true, entries["10.0.0.0/32"]},
		{"10.127.255.255", true, entries["10.0.0.0/8"]},
		{"10.128.255.255", true, entries["10.128.0.0/9"]},
		{"10.255.255.255", true, entries["10.128.0.0/9"]},
		{ip: "12.0.0.1", hasIdentity: false},
		{"feed::ffed", true, entries["feed::ed/112"]},
		{"feed::feed", true, entries["feed::feed/128"]},
	}

	for _, tt := range tests {
		v, exists := getLPMValue(mustParseIP(tt.ip), entries)

		c.Assert(exists, Equals, tt.hasIdentity, Commentf("No identity was found for ip '%s': wanted '%s'", tt.ip, tt.identity))

		if exists {
			identity := v.([]string)
			c.Assert(identity, checker.DeepEquals, tt.identity, Commentf("Wrong identity was retrieved for ip %s", tt.ip))
		}
	}
}

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)

	if ip == nil {
		panic(fmt.Errorf("%s is not a valid ip", s))
	}

	if isIPV4(ip) {
		ip = ip.To4()
	}

	return ip
}

func toBits(bytes []byte) []byte {
	var bits []byte

	for _, b := range bytes {
		for j := 0; j < 8; j++ {
			mask := uint8(128) >> uint8(j)

			if mask&b == 0 {
				bits = append(bits, 0x0)
			} else {
				bits = append(bits, 0x1)
			}
		}
	}

	return bits
}
