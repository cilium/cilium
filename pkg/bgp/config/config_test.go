// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package config provides BGP configuration logic.
package config

import (
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
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
