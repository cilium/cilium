// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package labels

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/cilium/common"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LabelsSuite struct{}

var _ = Suite(&LabelsSuite{})

var (
	lblsArray = []string{`%=%ed`, `//=/=`, `foo=bar`, `foo2==bar2`, `foo=====`, `foo\\==\=`, `key=`}
	lbls      = Labels{
		"foo":    NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2":   NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		"key":    NewLabel("key", "", common.CiliumLabelSource),
		"foo==":  NewLabel("foo==", "==", common.CiliumLabelSource),
		`foo\\=`: NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		`//=/`:   NewLabel(`//=/`, "", common.CiliumLabelSource),
		`%`:      NewLabel(`%`, `%ed`, common.CiliumLabelSource),
	}
)

func (s *LabelsSuite) TestSHA256Sum(c *C) {
	str := lbls.SHA256Sum()
	c.Assert(str, Equals, "253d2565643b2f2f3d2f3d3b666f6f3d6261723b666f6f323d3d626172323b666f6f3d3d3d3d3"+
		"d3b666f6f5c5c3d3d5c3d3b6b65793d3bc672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
}

func (s *LabelsSuite) TestSortMap(c *C) {
	lblsString := strings.Join(lblsArray, ";")
	lblsString += ";"
	sortedMap := lbls.sortedList()
	c.Assert(sortedMap, DeepEquals, []byte(lblsString))
}

type lblTest struct {
	label  string
	result *Label
}

func (s *LabelsSuite) TestMap2Labels(c *C) {
	m := Map2Labels(map[string]string{
		"k8s:foo":  "bar",
		"k8s:foo2": "=bar2",
		"key":      "",
		"foo==":    "==",
		`foo\\=`:   `\=`,
		`//=/`:     "",
		`%`:        `%ed`,
	}, common.CiliumLabelSource)
	fmt.Printf("%+v\n", m)
	fmt.Printf("%+v\n", lbls)
	c.Assert(m, DeepEquals, lbls)
}

func (s *LabelsSuite) TestMergeLabels(c *C) {
	to := Labels{
		"key1": NewLabel("key1", "value1", "source1"),
		"key2": NewLabel("key2", "value3", "source4"),
	}
	from := Labels{
		"key1": NewLabel("key1", "value3", "source4"),
	}
	want := Labels{
		"key1": NewLabel("key1", "value3", "source4"),
		"key2": NewLabel("key2", "value3", "source4"),
	}
	to.MergeLabels(from)
	from["key1"].Value = "changed"
	c.Assert(to, DeepEquals, want)
}

func (s *LabelsSuite) TestParseLabel(c *C) {
	tests := []struct {
		str string
		out *Label
	}{
		{"source1:key1=value1", NewLabel("key1", "value1", "source1")},
		{"key1=value1", NewLabel("key1", "value1", common.CiliumLabelSource)},
		{"value1", NewLabel("value1", "", common.CiliumLabelSource)},
		{"source1:key1", NewLabel("key1", "", "source1")},
		{"source1:key1==value1", NewLabel("key1", "=value1", "source1")},
		{"source::key1=value1", NewLabel("::key1", "value1", "source")},
		{"$key1=value1", NewLabel("key1", "value1", common.ReservedLabelSource)},
		{"1foo", NewLabel("1foo", "", common.CiliumLabelSource)},
		{":2foo", NewLabel("2foo", "", common.CiliumLabelSource)},
		{":3foo=", NewLabel("3foo", "", common.CiliumLabelSource)},
		{"4blah=:foo=", NewLabel("foo", "", "4blah=")},
		{"5blah::foo=", NewLabel("::foo", "", "5blah")},
		{"6foo==", NewLabel("6foo", "=", common.CiliumLabelSource)},
		{"7foo=bar", NewLabel("7foo", "bar", common.CiliumLabelSource)},
		{"k8s:foo=bar:", NewLabel("foo", "bar:", "k8s")},
		{common.ReservedLabelKey + "=host", NewLabel("host", "", common.ReservedLabelSource)},
	}
	for _, test := range tests {
		lbl := ParseLabel(test.str)
		c.Assert(lbl, DeepEquals, test.out)
	}
}

func (s *LabelsSuite) TestLabel(c *C) {
	var label Label

	longLabel := `{"source": "kubernetes", "key": "io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`

	err := json.Unmarshal([]byte(longLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "kubernetes")
	c.Assert(label.AbsoluteKey(), Equals, "root.io.kubernetes.pod.name")
	c.Assert(label.Value, Equals, "foo")

	label = Label{}
	err = json.Unmarshal([]byte(invLabel), &label)
	c.Assert(err, Not(Equals), nil)

	label = Label{}
	err = json.Unmarshal([]byte(shortLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, common.CiliumLabelSource)
	c.Assert(label.AbsoluteKey(), Equals, "root.web")
	c.Assert(label.Value, Equals, "")

	label = Label{}
	err = json.Unmarshal([]byte(""), &label)
	c.Assert(err, Not(Equals), nil)
}

func (s *LabelsSuite) TestLabelCompare(c *C) {
	a1 := NewLabel(".", "", "")
	a2 := NewLabel(".", "", "")
	b1 := NewLabel("bar", "", common.CiliumLabelSource)
	c1 := NewLabel("bar", "", "kubernetes")
	d1 := NewLabel("", "", "")

	c.Assert(a1.Equals(a2), Equals, true)
	c.Assert(a2.Equals(a1), Equals, true)
	c.Assert(a1.Equals(b1), Equals, false)
	c.Assert(a1.Equals(c1), Equals, false)
	c.Assert(a1.Equals(d1), Equals, false)
	c.Assert(b1.Equals(c1), Equals, false)
}

func (s *LabelsSuite) TestLabelSliceSHA256Sum(c *C) {
	a1 := NewLabel(".", "", "")
	a2 := NewLabel(".", "", "")
	b1 := NewLabel("bar", "", common.CiliumLabelSource)
	c1 := NewLabel("bar", "", "kubernetes")
	d1 := NewLabel("", "", "")
	labels := []*Label{
		a1,
		a2,
		b1,
		c1,
		d1,
	}
	sha256sum, err := LabelSliceSHA256Sum(labels)
	c.Assert(err, IsNil)
	c.Assert(sha256sum, DeepEquals, "180d22655dec0e78f62c3e4ac17f5994baedbdfc5c882cbbd668e2628c44f320")
}
