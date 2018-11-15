// Copyright 2016-2017 Authors of Cilium
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

package api

import (
	"math/rand"
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyAPITestSuite struct{}

var _ = Suite(&PolicyAPITestSuite{})

func (s *PolicyAPITestSuite) TestHTTPEqual(c *C) {
	rule1 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule2 := PortRuleHTTP{Path: "/bar$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule3 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Bar"}}

	c.Assert(rule1.Equal(rule1), Equals, true)
	c.Assert(rule1.Equal(rule2), Equals, false)
	c.Assert(rule1.Equal(rule3), Equals, false)

	rules := L7Rules{
		HTTP: []PortRuleHTTP{rule1, rule2},
	}

	c.Assert(rule1.Exists(rules), Equals, true)
	c.Assert(rule2.Exists(rules), Equals, true)
	c.Assert(rule3.Exists(rules), Equals, false)
}

func (s *PolicyAPITestSuite) TestKafkaEqual(c *C) {
	rule1 := PortRuleKafka{APIVersion: "1", APIKey: "foo", Topic: "topic1"}
	rule2 := PortRuleKafka{APIVersion: "1", APIKey: "bar", Topic: "topic1"}
	rule3 := PortRuleKafka{APIVersion: "1", APIKey: "foo", Topic: "topic2"}

	c.Assert(rule1.Equal(rule1), Equals, true)
	c.Assert(rule1.Equal(rule2), Equals, false)
	c.Assert(rule1.Equal(rule3), Equals, false)

	rules := L7Rules{
		Kafka: []PortRuleKafka{rule1, rule2},
	}

	c.Assert(rule1.Exists(rules), Equals, true)
	c.Assert(rule2.Exists(rules), Equals, true)
	c.Assert(rule3.Exists(rules), Equals, false)
}

func (s *PolicyAPITestSuite) TestL7Equal(c *C) {
	rule1 := PortRuleL7{"Path": "/foo$", "Method": "GET"}
	rule2 := PortRuleL7{"Path": "/bar$", "Method": "GET"}
	rule3 := PortRuleL7{"Path": "/foo$", "Method": "GET", "extra": ""}

	c.Assert(rule1.Equal(rule1), Equals, true)
	c.Assert(rule2.Equal(rule2), Equals, true)
	c.Assert(rule3.Equal(rule3), Equals, true)
	c.Assert(rule1.Equal(rule2), Equals, false)
	c.Assert(rule2.Equal(rule1), Equals, false)
	c.Assert(rule1.Equal(rule3), Equals, false)
	c.Assert(rule3.Equal(rule1), Equals, false)
	c.Assert(rule2.Equal(rule3), Equals, false)
	c.Assert(rule3.Equal(rule2), Equals, false)

	rules := L7Rules{
		L7Proto: "testing",
		L7:      []PortRuleL7{rule1, rule2},
	}

	c.Assert(rule1.Exists(rules), Equals, true)
	c.Assert(rule2.Exists(rules), Equals, true)
	c.Assert(rule3.Exists(rules), Equals, false)
}

func (s *PolicyAPITestSuite) TestValidateL4Proto(c *C) {
	c.Assert(L4Proto("TCP").Validate(), IsNil)
	c.Assert(L4Proto("UDP").Validate(), IsNil)
	c.Assert(L4Proto("ANY").Validate(), IsNil)
	c.Assert(L4Proto("TCP2").Validate(), Not(IsNil))
	c.Assert(L4Proto("t").Validate(), Not(IsNil))
}

func (s *PolicyAPITestSuite) TestParseL4Proto(c *C) {
	p, err := ParseL4Proto("tcp")
	c.Assert(p, Equals, ProtoTCP)
	c.Assert(err, IsNil)

	p, err = ParseL4Proto("Any")
	c.Assert(p, Equals, ProtoAny)
	c.Assert(err, IsNil)

	p, err = ParseL4Proto("")
	c.Assert(p, Equals, ProtoAny)
	c.Assert(err, IsNil)

	_, err = ParseL4Proto("foo2")
	c.Assert(err, Not(IsNil))
}

// TestKeepUniqueIPs tests that KeepUniqueIPs returns a slice with only the unique IPs
func (s *PolicyAPITestSuite) TestKeepUniqueIPs(c *C) {
	// test nil/empty handling
	ips := KeepUniqueIPs(nil)
	c.Assert(len(ips), Equals, 0, Commentf("Non-empty slice returned with empty input"))

	// test all duplicate
	ips = KeepUniqueIPs([]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1")})
	c.Assert(len(ips), Equals, 1, Commentf("Too many IPs returned for only 1 unique"))
	c.Assert(ips[0].String(), Equals, "1.1.1.1", Commentf("Incorrect unique IP returned"))

	// test all unique
	ipSource := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3")}
	ips = KeepUniqueIPs(ipSource)
	c.Assert(len(ips), Equals, 3, Commentf("Too few IPs returned for only 3 uniques"))
	for i := range ipSource {
		c.Assert(ips[i].String(), Equals, ipSource[i].String(), Commentf("Incorrect unique IP returned"))
	}

	// test mixed
	ipSource = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3"), net.ParseIP("2.2.2.2")}
	ips = KeepUniqueIPs(ipSource)
	c.Assert(len(ips), Equals, 3, Commentf("Too few IPs returned for only 3 uniques"))
	for i := range ipSource[:3] {
		c.Assert(ips[i].String(), Equals, ipSource[i].String(), Commentf("Incorrect unique IP returned"))
	}
}

// Note: each "op" works on size things
func (s *PolicyAPITestSuite) BenchmarkKeepUniqueIPs(c *C) {
	size := 1000
	ipsOrig := make([]net.IP, 0, size)
	for i := 0; i < size; i++ {
		ipsOrig = append(ipsOrig, net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i>>0)))
	}
	ips := make([]net.IP, 0, len(ipsOrig))

	copy(ips, ipsOrig)
	for i := 0; i < c.N; i++ {
		c.StopTimer()
		rand.Shuffle(len(ips), func(i, j int) {
			ips[i], ips[j] = ips[j], ips[i]
		})
		c.StartTimer()

		KeepUniqueIPs(ips)
	}
}
