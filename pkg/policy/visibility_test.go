// +build !privileged_tests

package policy

import (
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestVisibilityPolicyCreation(c *C) {

	anno := "<Ingress/80/TCP/HTTP>"
	vp, err := NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.ingress), Equals, 1)
	c.Assert(vp.ingress["80/TCP"], Equals, "HTTP")

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/8080/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.ingress), Equals, 2)
	c.Assert(vp.ingress["80/TCP"], Equals, "HTTP")
	c.Assert(vp.ingress["8080/TCP"], Equals, "HTTP")

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, Not(IsNil))
	c.Assert(err, IsNil)

	c.Assert(len(vp.ingress), Equals, 1)
	c.Assert(vp.ingress["80/TCP"], Equals, "HTTP")

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/Kafka>"
	vp, err = NewVisibilityPolicy(anno)
	c.Assert(vp, IsNil)
	c.Assert(err, Not(IsNil))

}
