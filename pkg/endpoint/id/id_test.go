// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package id

import (
	"net/netip"
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IDSuite struct{}

var _ = Suite(&IDSuite{})

func (s *IDSuite) TestSplitID(c *C) {
	type want struct {
		prefixType      PrefixType
		prefixTypeCheck Checker
		id              string
		idCheck         Checker
	}
	tests := []struct {
		name string
		id   string
		want want
	}{
		{
			name: "ID without a prefix",
			id:   "123456",
			want: want{
				prefixType:      CiliumLocalIdPrefix,
				prefixTypeCheck: Equals,
				id:              "123456",
				idCheck:         Equals,
			},
		},
		{
			name: "ID CiliumLocalIdPrefix prefix",
			id:   string(CiliumLocalIdPrefix) + ":123456",
			want: want{
				prefixType:      CiliumLocalIdPrefix,
				prefixTypeCheck: Equals,
				id:              "123456",
				idCheck:         Equals,
			},
		},
		{
			name: "ID with PodNamePrefix prefix",
			id:   string(PodNamePrefix) + ":default:foobar",
			want: want{
				prefixType:      PodNamePrefix,
				prefixTypeCheck: Equals,
				id:              "default:foobar",
				idCheck:         Equals,
			},
		},
		{
			name: "ID with CEPNamePrefix prefix",
			id:   string(CEPNamePrefix) + ":default:baz-net1",
			want: want{
				prefixType:      CEPNamePrefix,
				prefixTypeCheck: Equals,
				id:              "default:baz-net1",
				idCheck:         Equals,
			},
		},
		{
			name: "ID with ':'",
			id:   ":",
			want: want{
				prefixType:      "",
				prefixTypeCheck: Equals,
				id:              "",
				idCheck:         Equals,
			},
		},
		{
			name: "Empty ID",
			id:   "",
			want: want{
				prefixType:      CiliumLocalIdPrefix,
				prefixTypeCheck: Equals,
				id:              "",
				idCheck:         Equals,
			},
		},
	}
	for _, tt := range tests {
		prefixType, id := splitID(tt.id)
		c.Assert(prefixType, tt.want.prefixTypeCheck, tt.want.prefixType, Commentf("Test Name: %s", tt.name))
		c.Assert(id, tt.want.idCheck, tt.want.id, Commentf("Test Name: %s", tt.name))
	}
}

func BenchmarkSplitID(b *testing.B) {
	tests := []struct {
		str        string
		prefixType PrefixType
		id         string
	}{
		{"123456", CiliumLocalIdPrefix, "123456"},
		{string(CiliumLocalIdPrefix + ":123456"), CiliumLocalIdPrefix, "123456"},
		{string(PodNamePrefix + ":default:foobar"), PodNamePrefix, "default:foobar"},
	}
	count := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			pt, str := splitID(test.str)
			if pt == test.prefixType && str == test.id {
				count++
			}
		}
	}
	b.StopTimer()
	if count != len(tests)*b.N {
		b.Errorf("splitID didn't produce correct results")
	}
	b.ReportAllocs()
}

func (s *IDSuite) TestParse(c *C) {
	type test struct {
		input      PrefixType
		wantPrefix PrefixType
		wantID     string
		expectFail bool
	}

	tests := []test{
		{DockerEndpointPrefix + ":foo", DockerEndpointPrefix, "foo", false},
		{DockerEndpointPrefix + ":foo:foo", DockerEndpointPrefix, "foo:foo", false},
		{"unknown:unknown", "", "", true},
		{"unknown", CiliumLocalIdPrefix, "unknown", false},
	}

	for _, t := range tests {
		prefix, id, err := Parse(string(t.input))
		c.Assert(prefix, Equals, t.wantPrefix)
		c.Assert(id, Equals, t.wantID)
		if t.expectFail {
			c.Assert(err, Not(IsNil))
		} else {
			c.Assert(err, IsNil)
		}
	}
}

func (s *IDSuite) TestNewIPPrefix(c *C) {
	c.Assert(strings.HasPrefix(NewIPPrefixID(netip.MustParseAddr("1.1.1.1")), string(IPv4Prefix)), Equals, true)
	c.Assert(strings.HasPrefix(NewIPPrefixID(netip.MustParseAddr("f00d::1")), string(IPv6Prefix)), Equals, true)
}
