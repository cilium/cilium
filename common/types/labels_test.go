package types

import (
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type LabelsSuite struct{}

var _ = Suite(&LabelsSuite{})

var (
	lblsArray = []string{`%=%ed`, `//=/=`, `foo=bar`, `foo2==bar2`, `foo=====`, `foo\\==\=`, `key=`}
)

func createLabels() Labels {
	lbls := []Label{
		NewLabel("foo", "bar", "cilium"),
		NewLabel("foo2", "=bar2", "cilium"),
		NewLabel("key", "", "cilium"),
		NewLabel("foo==", "==", "cilium"),
		NewLabel(`foo\\=`, `\=`, "cilium"),
		NewLabel(`//=/`, "", "cilium"),
		NewLabel(`%`, `%ed`, "cilium"),
	}
	return map[string]*Label{
		"foo":    &lbls[0],
		"foo2":   &lbls[1],
		"key":    &lbls[2],
		"foo==":  &lbls[3],
		`foo\\=`: &lbls[4],
		`//=/`:   &lbls[5],
		`%`:      &lbls[6],
	}
}

func (s *LabelsSuite) TestSHA256Sum(c *C) {
	str, err := createLabels().SHA256Sum()
	c.Assert(err, Equals, nil)
	c.Assert(str, Equals, "f4b2082334cdcf08e58c5bb5a04bb291ecc6a4de7555baaf4d5ac110edd7d222")
}

func (s *LabelsSuite) TestSortMap(c *C) {
	sortedMap := createLabels().sortMap()
	c.Assert(sortedMap, DeepEquals, lblsArray)
}
