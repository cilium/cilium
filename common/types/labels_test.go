package types

import (
	"github.com/noironetworks/cilium-net/common"

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
		NewLabel("foo", "bar", common.CiliumLabelSource),
		NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		NewLabel("key", "", common.CiliumLabelSource),
		NewLabel("foo==", "==", common.CiliumLabelSource),
		NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		NewLabel(`//=/`, "", common.CiliumLabelSource),
		NewLabel(`%`, `%ed`, common.CiliumLabelSource),
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

type lblTest struct {
	label  string
	result Label
}

func (s *LabelsSuite) TestLabelShortForm(c *C) {
	lbls := []lblTest{
		{"1foo", NewLabel("1foo", "", common.CiliumLabelSource)},
		{":2foo", NewLabel("2foo", "", common.CiliumLabelSource)},
		{":3foo=", NewLabel("3foo", "", common.CiliumLabelSource)},
		{"4blah=:foo=", NewLabel("foo", "", "4blah=")},
		{"5blah::foo=", NewLabel(":foo", "", "5blah")},
		{"6foo==", NewLabel("6foo", "=", common.CiliumLabelSource)},
		{"7foo=bar", NewLabel("7foo", "bar", common.CiliumLabelSource)},
		{"k8s:foo=bar:", NewLabel("foo", "bar:", "k8s")},
	}

	for _, v := range lbls {
		res := Label{}
		decodeLabelShortform(v.label, &res)
		c.Assert(res, DeepEquals, v.result)
	}
}
