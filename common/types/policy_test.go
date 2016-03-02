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
