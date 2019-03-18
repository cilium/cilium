// Copyright 2018-2019 Authors of Cilium
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

// +build privileged_tests

package cmd

import (
	"bytes"
	"path"
	"sort"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type CMDHelpersSuite struct{}

var _ = Suite(&CMDHelpersSuite{})

func (s *CMDHelpersSuite) TestExpandNestedJSON(c *C) {
	buf := bytes.NewBufferString("not json at all")
	_, err := expandNestedJSON(*buf)
	c.Assert(err, IsNil)

	buf = bytes.NewBufferString(`{\n\"escapedJson\": \"foo\"}`)
	_, err = expandNestedJSON(*buf)
	c.Assert(err, IsNil)

	buf = bytes.NewBufferString(`nonjson={\n\"escapedJson\": \"foo\"}`)
	_, err = expandNestedJSON(*buf)
	c.Assert(err, IsNil)

	buf = bytes.NewBufferString(`nonjson:morenonjson={\n\"escapedJson\": \"foo\"}`)
	_, err = expandNestedJSON(*buf)
	c.Assert(err, IsNil)

	buf = bytes.NewBufferString(`{"foo": ["{\n  \"port\": 8080,\n  \"protocol\": \"TCP\"\n}"]}`)
	_, err = expandNestedJSON(*buf)
	c.Assert(err, IsNil)

	buf = bytes.NewBufferString(`"foo": [
  "bar:baz/alice={\"bob\":{\"charlie\":4}}\n"
]`)
	_, err = expandNestedJSON(*buf)
	c.Assert(err, IsNil)
}

func (s *CMDHelpersSuite) TestParseTrafficString(c *C) {

	validIngressCases := []string{"ingress", "Ingress", "InGrEss"}
	validEgressCases := []string{"egress", "Egress", "EGrEss"}

	invalidStr := "getItDoneMan"

	for _, validCase := range validIngressCases {
		ingressDir, err := parseTrafficString(validCase)
		c.Assert(ingressDir, Equals, trafficdirection.Ingress)
		c.Assert(err, IsNil)
	}

	for _, validCase := range validEgressCases {
		egressDir, err := parseTrafficString(validCase)
		c.Assert(egressDir, Equals, trafficdirection.Egress)
		c.Assert(err, IsNil)
	}

	invalid, err := parseTrafficString(invalidStr)
	c.Assert(invalid, Equals, trafficdirection.Invalid)
	c.Assert(err, Not(IsNil))

}

func (s *CMDHelpersSuite) TestParsePolicyUpdateArgsHelper(c *C) {
	sortProtos := func(ints []uint8) {
		sort.Slice(ints, func(i, j int) bool {
			return ints[i] < ints[j]
		})
	}

	allProtos := []uint8{}
	for _, proto := range u8proto.ProtoIDs {
		allProtos = append(allProtos, uint8(proto))
	}

	tests := []struct {
		args             []string
		invalid          bool
		mapBaseName      string
		trafficDirection trafficdirection.TrafficDirection
		peerLbl          uint32
		port             uint16
		protos           []uint8
	}{
		{
			args:             []string{labels.IDNameHost, "ingress", "12345"},
			invalid:          false,
			mapBaseName:      "cilium_policy_reserved_1",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             0,
			protos:           []uint8{0},
		},
		{
			args:             []string{"123", "egress", "12345", "1/tcp"},
			invalid:          false,
			mapBaseName:      "cilium_policy_00123",
			trafficDirection: trafficdirection.Egress,
			peerLbl:          12345,
			port:             1,
			protos:           []uint8{uint8(u8proto.TCP)},
		},
		{
			args:             []string{"123", "ingress", "12345", "1"},
			invalid:          false,
			mapBaseName:      "cilium_policy_00123",
			trafficDirection: trafficdirection.Ingress,
			peerLbl:          12345,
			port:             1,
			protos:           allProtos,
		},
		{
			// Invalid traffic direction.
			args:    []string{"123", "invalid", "12345"},
			invalid: true,
		},
		{
			// Invalid protocol.
			args:    []string{"123", "invalid", "1/udt"},
			invalid: true,
		},
	}

	for _, tt := range tests {
		args, err := parsePolicyUpdateArgsHelper(tt.args)

		if tt.invalid {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)

			c.Assert(path.Base(args.path), Equals, tt.mapBaseName)
			c.Assert(args.trafficDirection, Equals, tt.trafficDirection)
			c.Assert(args.label, Equals, tt.peerLbl)
			c.Assert(args.port, Equals, tt.port)

			sortProtos(args.protocols)
			sortProtos(tt.protos)
			c.Assert(args.protocols, checker.DeepEquals, tt.protos)
		}
	}
}
