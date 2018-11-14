// Copyright 2018 Authors of Cilium
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

package id

import (
	"net"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type IDSuite struct{}

var _ = Suite(&IDSuite{})

func (s *IDSuite) TestSplitID(c *C) {
	type args struct {
		id string
	}
	type want struct {
		prefixType      PrefixType
		prefixTypeCheck Checker
		id              string
		idCheck         Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "ID without a prefix",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"123456",
				}
			},
			setupWant: func() want {
				return want{
					prefixType:      CiliumLocalIdPrefix,
					prefixTypeCheck: Equals,
					id:              "123456",
					idCheck:         Equals,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "ID CiliumLocalIdPrefix prefix",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					string(CiliumLocalIdPrefix) + ":123456",
				}
			},
			setupWant: func() want {
				return want{
					prefixType:      CiliumLocalIdPrefix,
					prefixTypeCheck: Equals,
					id:              "123456",
					idCheck:         Equals,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "ID with PodNamePrefix prefix",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					string(PodNamePrefix) + ":default:foobar",
				}
			},
			setupWant: func() want {
				return want{
					prefixType:      PodNamePrefix,
					prefixTypeCheck: Equals,
					id:              "default:foobar",
					idCheck:         Equals,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "ID with ':'",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					":",
				}
			},
			setupWant: func() want {
				return want{
					prefixType:      "",
					prefixTypeCheck: Equals,
					id:              "",
					idCheck:         Equals,
				}
			},
			postTestRun: func() {
			},
		},
		{
			name: "Empty ID",
			preTestRun: func() {
			},
			setupArgs: func() args {
				return args{
					"",
				}
			},
			setupWant: func() want {
				return want{
					prefixType:      CiliumLocalIdPrefix,
					prefixTypeCheck: Equals,
					id:              "",
					idCheck:         Equals,
				}
			},
			postTestRun: func() {
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		prefixType, id := splitID(args.id)
		c.Assert(prefixType, want.prefixTypeCheck, want.prefixType, Commentf("Test Name: %s", tt.name))
		c.Assert(id, want.idCheck, want.id, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
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
	c.Assert(strings.HasPrefix(NewIPPrefixID(net.ParseIP("1.1.1.1")), string(IPv4Prefix)), Equals, true)
	c.Assert(strings.HasPrefix(NewIPPrefixID(net.ParseIP("f00d::1")), string(IPv6Prefix)), Equals, true)
}
