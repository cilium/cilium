// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package policy

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (ds *PolicyTestSuite) TestGenerateL7RulesByParser(c *C) {
	m := generateL7AllowAllRules(ParserTypeHTTP)
	c.Assert(m, IsNil)

	m = generateL7AllowAllRules(ParserTypeKafka)
	c.Assert(m, IsNil)

	m = generateL7AllowAllRules(ParserTypeDNS)
	c.Assert(m, Not(IsNil))
	c.Assert(len(m), Equals, 1)

	l7Rules := make([]*PerSelectorPolicy, 0, len(m))
	for _, v := range m {
		l7Rules = append(l7Rules, v)
	}

	// Check that we allow all at L7 for DNS for the one rule we should have
	// generated.
	c.Assert(l7Rules[0], checker.DeepEquals, &PerSelectorPolicy{L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{{MatchPattern: "*"}}}})
}

func (ds *PolicyTestSuite) TestVisibilityPolicyCreation(c *C) {

	anno := "<Ingress/80/TCP/HTTP>"
	vp, err := NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 1)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/8080/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 2)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})
	c.Assert(vp.Ingress["8080/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(8080),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.Ingress), Equals, 1)
	c.Assert(vp.Ingress["80/TCP"], DeepEquals, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	})

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/Kafka>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "asdf"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/65536/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/65535/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	anno = "<Ingress/99999/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Ingress/0/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	// Do not allow > 5 digits.
	anno = "<Ingress/123456/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	// Do not allow leading zeroes.
	anno = "<Ingress/02345/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

	anno = "<Egress/53/ANY/DNS>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(err, IsNil)
	c.Assert(vp.Egress, HasLen, 3)
	udp, ok := vp.Egress["53/UDP"]
	c.Assert(ok, Equals, true)
	c.Assert(udp.Proto, Equals, u8proto.UDP)
	tcp, ok := vp.Egress["53/TCP"]
	c.Assert(tcp.Proto, Equals, u8proto.TCP)
	c.Assert(ok, Equals, true)
	sctp, ok := vp.Egress["53/SCTP"]
	c.Assert(sctp.Proto, Equals, u8proto.SCTP)
	c.Assert(ok, Equals, true)

}
