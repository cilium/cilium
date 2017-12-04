package cmd

import (
	"bytes"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type CMDHelpersSuite struct{}

var _ = Suite(&CMDHelpersSuite{})

func (s *CMDHelpersSuite) TestDumpJSON(c *C) {
	type sampleData struct {
		ID   int
		Name string
	}

	tt := sampleData{
		ID:   1,
		Name: "test",
	}

	err := dumpJSON(tt, "")
	c.Assert(err, IsNil)

	err = dumpJSON(tt, "{.Id}")
	c.Assert(err, IsNil)

	err = dumpJSON(tt, "{{.Id}}")
	if err == nil {
		c.Fatalf("Dumpjson jsonpath no error with invalid path '%s'", err)
	}
}

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
