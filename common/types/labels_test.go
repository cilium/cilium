package types

import (
	"reflect"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LabelsSuite struct{}

var _ = Suite(&LabelsSuite{})

var (
	lbls = Labels{
		"foo":    "bar",
		"foo2":   "=bar2",
		"key":    "",
		"foo==":  "==",
		`foo\\=`: `\=`,
		`//=/`:   "",
		`%`:      `%ed`,
	}
	lblsArray = []string{`%=%ed`, `//=/=`, `foo=bar`, `foo2==bar2`, `foo=====`, `foo\\==\=`, `key=`}
)

func (s *LabelsSuite) TestSHA256Sum(c *C) {
	str, err := lbls.SHA256Sum()
	c.Assert(err, Equals, nil)
	c.Assert(str, Equals, "f4b2082334cdcf08e58c5bb5a04bb291ecc6a4de7555baaf4d5ac110edd7d222")
}

func (s *LabelsSuite) TestSortMap(c *C) {
	sortedMap := lbls.sortMap()
	c.Assert(reflect.DeepEqual(lblsArray, sortedMap), Equals, true, Commentf("\nwant = %+v,\n got = %+v", lblsArray, sortedMap))
}
