// +build !privileged_tests

package policy

import (
	"github.com/cilium/cilium/pkg/u8proto"
	. "gopkg.in/check.v1"
)

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
}
