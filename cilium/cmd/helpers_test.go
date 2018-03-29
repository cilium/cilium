package cmd

import (
	"bytes"
	"testing"

	"github.com/cilium/cilium/pkg/maps/policymap"
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
		c.Assert(ingressDir, Equals, policymap.Ingress)
		c.Assert(err, IsNil)
	}

	for _, validCase := range validEgressCases {
		egressDir, err := parseTrafficString(validCase)
		c.Assert(egressDir, Equals, policymap.Egress)
		c.Assert(err, IsNil)
	}

	invalid, err := parseTrafficString(invalidStr)
	c.Assert(invalid, Equals, policymap.Invalid)
	c.Assert(err, Not(IsNil))

}
