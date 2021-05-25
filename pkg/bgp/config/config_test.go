// Copyright 2021 Authors of Cilium
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

// Package config provides BGP configuration logic.
package config

import (
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type BGPConfigTestSuite struct{}

var _ = Suite(&BGPConfigTestSuite{})

func (s *BGPConfigTestSuite) TestParse(c *C) {
	config, err := Parse(strings.NewReader(yaml))
	c.Assert(err, IsNil)
	c.Assert(config, Not(IsNil))

	config, err = Parse(strings.NewReader(json))
	c.Assert(err, IsNil)
	c.Assert(config, Not(IsNil))

	config, err = Parse(strings.NewReader(`{"json":"random"}`))
	// Usually we use ErrorMatches here, but the error string has newlines
	// which makes the regex matching fail.
	c.Assert(strings.HasPrefix(err.Error(), "failed to parse MetalLB config:"), Equals, true)
	c.Assert(config, IsNil)
}

const (
	yaml = `---
peers:
  - peer-address: 172.19.0.5
    peer-asn: 64512
    my-asn: 64512
address-pools:
  - name: default
    protocol: bgp
    addresses:
      - 192.168.1.150/29
`
	json = `{"peers":[{"peer-address":"172.19.0.5","peer-asn":64512,"my-asn":64512}],"address-pools":[{"name":"default","protocol":"bgp","addresses":["192.168.1.150/29"]}]}`
)
