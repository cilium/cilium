package types

import (
	"encoding/json"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

type CommonSuite struct{}

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestLabelSelector(c *C) {
	var label LabelSelector

	longLabel := `{"source": "kubernetes", "key": "io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`

	err := json.Unmarshal([]byte(longLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "kubernetes")
	c.Assert(label.Key, Equals, "io.kubernetes.pod.name")
	c.Assert(label.Value, Equals, "foo")
	c.Assert(label.String(), Equals, "io.kubernetes.pod.name=foo")

	err = json.Unmarshal([]byte(invLabel), &label)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "cilium")
	c.Assert(label.Key, Equals, "web")
	c.Assert(label.Value, Equals, "")
	c.Assert(label.String(), Equals, "web")

	err = json.Unmarshal([]byte(""), &label)
	c.Assert(err, Not(Equals), nil)
}

func (s *CommonSuite) TestAllowRule(c *C) {
	var rule AllowRule

	longLabel := `{"source": "kubernetes", "key": "!io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`
	invertedLabel := `"!web"`

	err := json.Unmarshal([]byte(longLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Inverted, Equals, true)
	c.Assert(rule.Label.Source, Equals, "kubernetes")
	c.Assert(rule.Label.Key, Equals, "io.kubernetes.pod.name")
	c.Assert(rule.Label.Value, Equals, "foo")
	c.Assert(rule.Label.String(), Equals, "io.kubernetes.pod.name=foo")

	err = json.Unmarshal([]byte(invLabel), &rule)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Label.Source, Equals, "cilium")
	c.Assert(rule.Label.Key, Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")
	c.Assert(rule.Label.String(), Equals, "web")

	err = json.Unmarshal([]byte(invertedLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Inverted, Equals, true)
	c.Assert(rule.Label.Source, Equals, "cilium")
	c.Assert(rule.Label.Key, Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")
	c.Assert(rule.Label.String(), Equals, "web")

	err = json.Unmarshal([]byte(""), &rule)
	c.Assert(err, Not(Equals), nil)
}
