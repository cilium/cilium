// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LabelsSuite struct{}

var _ = Suite(&LabelsSuite{})

var (
	// Elements are sorted by the key
	lblsArray = []string{`unspec:%=%ed`, `unspec://=/=`, `unspec:foo=bar`, `unspec:foo2==bar2`, `unspec:foo=====`, `unspec:foo\\==\=`, `unspec:key=`}
	lbls      = Labels{
		"foo":    NewLabel("foo", "bar", LabelSourceUnspec),
		"foo2":   NewLabel("foo2", "=bar2", LabelSourceUnspec),
		"key":    NewLabel("key", "", LabelSourceUnspec),
		"foo==":  NewLabel("foo==", "==", LabelSourceUnspec),
		`foo\\=`: NewLabel(`foo\\=`, `\=`, LabelSourceUnspec),
		`//=/`:   NewLabel(`//=/`, "", LabelSourceUnspec),
		`%`:      NewLabel(`%`, `%ed`, LabelSourceUnspec),
	}

	DefaultLabelSourceKeyPrefix = LabelSourceAny + "."
)

func TestNewFrom(t *testing.T) {
	for _, tt := range []struct {
		name string
		lbls Labels
		want Labels
	}{
		{
			name: "non-empty labels",
			lbls: lbls,
			want: lbls,
		},
		{
			name: "empty labels",
			lbls: Labels{},
			want: Labels{},
		},
		{
			name: "nil labels",
			lbls: nil,
			want: Labels{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			newLbls := NewFrom(tt.lbls)
			// Verify that underlying maps are different
			assert.NotSame(t, tt.lbls, newLbls)
			// Verify that the map contents are equal
			assert.EqualValues(t, tt.want, newLbls)
		})
	}
}

func (s *LabelsSuite) TestSortMap(c *C) {
	lblsString := strings.Join(lblsArray, ";")
	lblsString += ";"
	sortedMap := lbls.SortedList()
	c.Assert(sortedMap, checker.DeepEquals, []byte(lblsString))
}

func (s *LabelsSuite) TestLabelArraySorted(c *C) {
	lblsString := strings.Join(lblsArray, ";")
	lblsString += ";"
	str := ""
	for _, l := range lbls.LabelArray() {
		str += fmt.Sprintf(`%s:%s=%s;`, l.Source, l.Key, l.Value)
	}
	c.Assert(str, checker.DeepEquals, lblsString)
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
	}, LabelSourceUnspec)
	c.Assert(m, checker.DeepEquals, lbls)
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
	from["key1"] = NewLabel("key1", "changed", "source4")
	c.Assert(to, checker.DeepEquals, want)
}

func (s *LabelsSuite) TestParseLabel(c *C) {
	tests := []struct {
		str string
		out Label
	}{
		{"source1:key1=value1", NewLabel("key1", "value1", "source1")},
		{"key1=value1", NewLabel("key1", "value1", LabelSourceUnspec)},
		{"value1", NewLabel("value1", "", LabelSourceUnspec)},
		{"source1:key1", NewLabel("key1", "", "source1")},
		{"source1:key1==value1", NewLabel("key1", "=value1", "source1")},
		{"source::key1=value1", NewLabel("::key1", "value1", "source")},
		{"$key1=value1", NewLabel("key1", "value1", LabelSourceReserved)},
		{"1foo", NewLabel("1foo", "", LabelSourceUnspec)},
		{":2foo", NewLabel("2foo", "", LabelSourceUnspec)},
		{":3foo=", NewLabel("3foo", "", LabelSourceUnspec)},
		{"reserved:=key", NewLabel("key", "", LabelSourceReserved)},
		{"4blah=:foo=", NewLabel("foo", "", "4blah=")},
		{"5blah::foo=", NewLabel("::foo", "", "5blah")},
		{"6foo==", NewLabel("6foo", "=", LabelSourceUnspec)},
		{"7foo=bar", NewLabel("7foo", "bar", LabelSourceUnspec)},
		{"k8s:foo=bar:", NewLabel("foo", "bar:", LabelSourceK8s)},
		{"reservedz=host", NewLabel("reservedz", "host", LabelSourceUnspec)},
		{":", NewLabel("", "", LabelSourceUnspec)},
		{LabelSourceReservedKeyPrefix + "host", NewLabel("host", "", LabelSourceReserved)},
	}
	for _, test := range tests {
		lbl := ParseLabel(test.str)
		c.Assert(lbl, checker.DeepEquals, test.out)
	}
}

func BenchmarkParseLabel(b *testing.B) {
	tests := []struct {
		str string
		out Label
	}{
		{"source1:key1=value1", NewLabel("key1", "value1", "source1")},
		{"key1=value1", NewLabel("key1", "value1", LabelSourceUnspec)},
		{"value1", NewLabel("value1", "", LabelSourceUnspec)},
		{"source1:key1", NewLabel("key1", "", "source1")},
		{"source1:key1==value1", NewLabel("key1", "=value1", "source1")},
		{"source::key1=value1", NewLabel("::key1", "value1", "source")},
		{"$key1=value1", NewLabel("key1", "value1", LabelSourceReserved)},
		{"1foo", NewLabel("1foo", "", LabelSourceUnspec)},
		{":2foo", NewLabel("2foo", "", LabelSourceUnspec)},
		{":3foo=", NewLabel("3foo", "", LabelSourceUnspec)},
		{"reserved:=key", NewLabel("key", "", LabelSourceReserved)},
		{"4blah=:foo=", NewLabel("foo", "", "4blah=")},
		{"5blah::foo=", NewLabel("::foo", "", "5blah")},
		{"6foo==", NewLabel("6foo", "=", LabelSourceUnspec)},
		{"7foo=bar", NewLabel("7foo", "bar", LabelSourceUnspec)},
		{"k8s:foo=bar:", NewLabel("foo", "bar:", LabelSourceK8s)},
		{"reservedz=host", NewLabel("reservedz", "host", LabelSourceUnspec)},
		{":", NewLabel("", "", LabelSourceUnspec)},
		{LabelSourceReservedKeyPrefix + "host", NewLabel("host", "", LabelSourceReserved)},
	}
	count := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, test := range tests {
			if ParseLabel(test.str).Source == LabelSourceUnspec {
				count++
			}
		}
	}
}

func (s *LabelsSuite) TestParseSelectLabel(c *C) {
	tests := []struct {
		str string
		out Label
	}{
		{"source1:key1=value1", NewLabel("key1", "value1", "source1")},
		{"key1=value1", NewLabel("key1", "value1", LabelSourceAny)},
		{"value1", NewLabel("value1", "", LabelSourceAny)},
		{"source1:key1", NewLabel("key1", "", "source1")},
		{"source1:key1==value1", NewLabel("key1", "=value1", "source1")},
		{"source::key1=value1", NewLabel("::key1", "value1", "source")},
		{"$key1=value1", NewLabel("key1", "value1", LabelSourceReserved)},
		{"1foo", NewLabel("1foo", "", LabelSourceAny)},
		{":2foo", NewLabel("2foo", "", LabelSourceAny)},
		{":3foo=", NewLabel("3foo", "", LabelSourceAny)},
		{"4blah=:foo=", NewLabel("foo", "", "4blah=")},
		{"5blah::foo=", NewLabel("::foo", "", "5blah")},
		{"6foo==", NewLabel("6foo", "=", LabelSourceAny)},
		{"7foo=bar", NewLabel("7foo", "bar", LabelSourceAny)},
		{"k8s:foo=bar:", NewLabel("foo", "bar:", LabelSourceK8s)},
		{LabelSourceReservedKeyPrefix + "host", NewLabel("host", "", LabelSourceReserved)},
	}
	for _, test := range tests {
		lbl := ParseSelectLabel(test.str)
		c.Assert(lbl, checker.DeepEquals, test.out)
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
	c.Assert(label.Value, Equals, "foo")

	label = Label{}
	err = json.Unmarshal([]byte(invLabel), &label)
	c.Assert(err, Not(Equals), nil)

	label = Label{}
	err = json.Unmarshal([]byte(shortLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, LabelSourceUnspec)
	c.Assert(label.Value, Equals, "")

	label = Label{}
	err = json.Unmarshal([]byte(""), &label)
	c.Assert(err, Not(Equals), nil)
}

func (s *LabelsSuite) TestLabelCompare(c *C) {
	a1 := NewLabel(".", "", "")
	a2 := NewLabel(".", "", "")
	b1 := NewLabel("bar", "", LabelSourceUnspec)
	c1 := NewLabel("bar", "", "kubernetes")
	d1 := NewLabel("", "", "")

	c.Assert(a1.Equals(&a2), Equals, true)
	c.Assert(a2.Equals(&a1), Equals, true)
	c.Assert(a1.Equals(&b1), Equals, false)
	c.Assert(a1.Equals(&c1), Equals, false)
	c.Assert(a1.Equals(&d1), Equals, false)
	c.Assert(b1.Equals(&c1), Equals, false)
}

func (s *LabelsSuite) TestLabelParseKey(c *C) {
	tests := []struct {
		str string
		out string
	}{
		{"source0:key0=value1", "source0.key0"},
		{"source3:key1", "source3.key1"},
		{"source4:key1==value1", "source4.key1"},
		{"source::key1=value1", "source.:key1"},
		{"4blah=:foo=", "4blah=.foo"},
		{"5blah::foo=", "5blah.:foo"},
		{"source2.key1=value1", DefaultLabelSourceKeyPrefix + "source2.key1"},
		{"1foo", DefaultLabelSourceKeyPrefix + "1foo"},
		{":2foo", DefaultLabelSourceKeyPrefix + "2foo"},
		{":3foo=", DefaultLabelSourceKeyPrefix + "3foo"},
		{"6foo==", DefaultLabelSourceKeyPrefix + "6foo"},
		{"7foo=bar", DefaultLabelSourceKeyPrefix + "7foo"},
		{"cilium.key1=value1", DefaultLabelSourceKeyPrefix + "cilium.key1"},
		{"key1=value1", DefaultLabelSourceKeyPrefix + "key1"},
		{"value1", DefaultLabelSourceKeyPrefix + "value1"},
		{"$world=value1", LabelSourceReservedKeyPrefix + "world"},
		{"k8s:foo=bar:", LabelSourceK8sKeyPrefix + "foo"},
	}
	for _, test := range tests {
		lbl := GetExtendedKeyFrom(test.str)
		c.Assert(lbl, checker.DeepEquals, test.out)
	}
}

func (s *LabelsSuite) TestLabelsCompare(c *C) {
	la11 := NewLabel("a", "1", "src1")
	la12 := NewLabel("a", "1", "src2")
	la22 := NewLabel("a", "2", "src2")
	lb22 := NewLabel("b", "2", "src2")

	lblsAll := Labels{la11.Key: la11, la12.Key: la12, la22.Key: la22, lb22.Key: lb22}
	lblsFewer := Labels{la11.Key: la11, la12.Key: la12, la22.Key: la22}
	lblsLa11 := Labels{la11.Key: la11}
	lblsLa12 := Labels{la12.Key: la12}
	lblsLa22 := Labels{la22.Key: la22}
	lblsLb22 := Labels{lb22.Key: lb22}

	c.Assert(lblsAll.Equals(lblsAll), Equals, true)
	c.Assert(lblsAll.Equals(lblsFewer), Equals, false)
	c.Assert(lblsFewer.Equals(lblsAll), Equals, false)
	c.Assert(lblsLa11.Equals(lblsLa12), Equals, false)
	c.Assert(lblsLa12.Equals(lblsLa11), Equals, false)
	c.Assert(lblsLa12.Equals(lblsLa22), Equals, false)
	c.Assert(lblsLa22.Equals(lblsLa12), Equals, false)
	c.Assert(lblsLa22.Equals(lblsLb22), Equals, false)
	c.Assert(lblsLb22.Equals(lblsLa22), Equals, false)
}

func (s *LabelsSuite) TestLabelsK8sStringMap(c *C) {
	laKa1 := NewLabel("a", "1", LabelSourceK8s)
	laUa1 := NewLabel("a", "1", LabelSourceUnspec)
	laCa2 := NewLabel("a", "2", LabelSourceContainer)
	laNa3 := NewLabel("a", "3", LabelSourceCNI)
	lbAb2 := NewLabel("b", "2", LabelSourceAny)
	lbRb2 := NewLabel("b", "2", LabelSourceReserved)

	lblsKa1 := Labels{laKa1.Key: laKa1}
	lblsUa1 := Labels{laUa1.Key: laUa1}
	lblsCa2 := Labels{laCa2.Key: laCa2}
	lblsNa3 := Labels{laNa3.Key: laNa3}
	lblsAb2 := Labels{lbAb2.Key: lbAb2}
	lblsRb2 := Labels{lbRb2.Key: lbRb2}
	lblsOverlap := Labels{laKa1.Key: laKa1, laUa1.Key: laUa1}
	lblsAll := Labels{laKa1.Key: laKa1, laUa1.Key: laUa1, laCa2.Key: laCa2, lbAb2.Key: lbAb2, lbRb2.Key: lbRb2}
	lblsFewer := Labels{laKa1.Key: laKa1, laCa2.Key: laCa2, lbAb2.Key: lbAb2, lbRb2.Key: lbRb2}

	c.Assert(lblsKa1.K8sStringMap(), checker.Equals, map[string]string{"a": "1"})
	c.Assert(lblsUa1.K8sStringMap(), checker.Equals, map[string]string{"a": "1"})
	c.Assert(lblsCa2.K8sStringMap(), checker.Equals, map[string]string{"container.a": "2"})
	c.Assert(lblsNa3.K8sStringMap(), checker.Equals, map[string]string{"cni.a": "3"})
	c.Assert(lblsAb2.K8sStringMap(), checker.Equals, map[string]string{"b": "2"})
	c.Assert(lblsRb2.K8sStringMap(), checker.Equals, map[string]string{"reserved.b": "2"})
	c.Assert(lblsOverlap.K8sStringMap(), checker.Equals, map[string]string{"a": "1"})

	c.Assert(lblsFewer.K8sStringMap(), checker.Equals, lblsAll.K8sStringMap())

	// Unfortunately Labels key does not contain the source, which
	// makes the last entry with the same key, but maybe from
	// different source, overwrite the previous value with the
	// same key. This makes the Labels contents dependent on the
	// label insertion order. In this example, "a" from container
	// overwrites "a" from K8s and "a" from Unspec, and "b" from
	// reserved overwrites "b" from any.
	c.Assert(lblsAll.K8sStringMap(), checker.Equals, map[string]string{"container.a": "2", "reserved.b": "2"})
}

func TestLabels_Has(t *testing.T) {
	tests := []struct {
		name string
		l    Labels
		in   Label
		want bool
	}{
		{
			name: "empty labels",
			l:    Labels{},
			in:   NewLabel("foo", "bar", "my-source"),
			want: false,
		},
		{
			name: "has label",
			l: Labels{
				"foo":   NewLabel("foo", "bar", "k8s"),
				"other": NewLabel("other", "bar", ""),
			},
			in:   NewLabel("foo", "bar", "k8s"),
			want: true,
		},
		{
			name: "has label, any source",
			l: Labels{
				"foo":   NewLabel("foo", "bar", "k8s"),
				"other": NewLabel("other", "bar", ""),
			},
			in:   NewLabel("foo", "bar", "any"),
			want: true,
		},
		{
			name: "does not have label",
			l: Labels{
				"foo":   NewLabel("foo", "bar", "any"),
				"other": NewLabel("other", "bar", ""),
			},
			in:   NewLabel("nope", "", ""),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.l.Has(tt.in))
		})
	}
}

func TestLabels_GetFromSource(t *testing.T) {
	type args struct {
		source string
	}
	tests := []struct {
		name string
		l    Labels
		args args
		want Labels
	}{
		{
			name: "should contain label with the given source",
			l: Labels{
				"foo":   NewLabel("foo", "bar", "my-source"),
				"other": NewLabel("other", "bar", ""),
			},
			args: args{
				source: "my-source",
			},
			want: Labels{
				"foo": NewLabel("foo", "bar", "my-source"),
			},
		},
		{
			name: "should return an empty slice as there are not labels for the given source",
			l: Labels{
				"foo":   NewLabel("foo", "bar", "any"),
				"other": NewLabel("other", "bar", ""),
			},
			args: args{
				source: "my-source",
			},
			want: Labels{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.GetFromSource(tt.args.source); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Labels.GetFromSource() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkNewFrom(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewFrom(lbls)
	}
}

func BenchmarkLabels_SortedList(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lbls.SortedList()
	}
}

func BenchmarkLabel_FormatForKVStore(b *testing.B) {
	l := NewLabel("io.kubernetes.pod.namespace", "kube-system", LabelSourceK8s)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.FormatForKVStore()
	}
}

func BenchmarkLabel_String(b *testing.B) {
	l := NewLabel("io.kubernetes.pod.namespace", "kube-system", LabelSourceK8s)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.String()
	}
}

func BenchmarkGenerateLabelString(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		generateLabelString("foo", "key", "value")
	}
}

func TestLabel_String(t *testing.T) {
	// with value
	l := NewLabel("io.kubernetes.pod.namespace", "kube-system", LabelSourceK8s)
	assert.Equal(t, "k8s:io.kubernetes.pod.namespace=kube-system", l.String())
	// without value
	l = NewLabel("io.kubernetes.pod.namespace", "", LabelSourceK8s)
	assert.Equal(t, "k8s:io.kubernetes.pod.namespace", l.String())
}

// test that the .cidr field is correctly populated
func TestNewLabelCIDR(t *testing.T) {
	for _, labelSpec := range []string{
		"cidr:0--0/0",
		"cidr:0--0/1", "cidr:0--0/2", "cidr:2000--0/3", "cidr:2000--0/4",
		"cidr:2000--0/5", "cidr:2000--0/6", "cidr:2000--0/7", "cidr:2000--0/8",
		"cidr:2000--0/9", "cidr:2000--0/10", "cidr:2000--0/11", "cidr:2000--0/12",
		"cidr:2000--0/13", "cidr:2000--0/14", "cidr:2000--0/15", "cidr:2001--0/16",
		"cidr:2001--0/17", "cidr:2001--0/18", "cidr:2001--0/19", "cidr:2001--0/20",
		"cidr:2001-800--0/21", "cidr:2001-c00--0/22", "cidr:2001-c00--0/23", "cidr:2001-d00--0/24",
		"cidr:2001-d80--0/25", "cidr:2001-d80--0/26", "cidr:2001-da0--0/27", "cidr:2001-db0--0/28",
		"cidr:2001-db8--0/29", "cidr:2001-db8--0/30", "cidr:2001-db8--0/31", "cidr:2001-db8--0/32",
		"cidr:2001-db8--0/33", "cidr:2001-db8--0/34", "cidr:2001-db8--0/35", "cidr:2001-db8--0/36",
		"cidr:2001-db8--0/37", "cidr:2001-db8--0/38", "cidr:2001-db8--0/39", "cidr:2001-db8--0/40",
		"cidr:2001-db8--0/41", "cidr:2001-db8--0/42", "cidr:2001-db8--0/43", "cidr:2001-db8--0/44",
		"cidr:2001-db8--0/45", "cidr:2001-db8--0/46", "cidr:2001-db8--0/47", "cidr:2001-db8--0/48",
		"cidr:2001-db8--0/49", "cidr:2001-db8--0/50", "cidr:2001-db8--0/51", "cidr:2001-db8--0/52",
		"cidr:2001-db8--0/53", "cidr:2001-db8--0/54", "cidr:2001-db8--0/55", "cidr:2001-db8--0/56",
		"cidr:2001-db8--0/57", "cidr:2001-db8--0/58", "cidr:2001-db8--0/59", "cidr:2001-db8--0/60",
		"cidr:2001-db8--0/61", "cidr:2001-db8--0/62", "cidr:2001-db8--0/63", "cidr:2001-db8--0/64",
		"cidr:2001-db8--0/65", "cidr:2001-db8--0/66", "cidr:2001-db8--0/67", "cidr:2001-db8--0/68",
		"cidr:2001-db8--0/69", "cidr:2001-db8--0/70", "cidr:2001-db8--0/71", "cidr:2001-db8--0/72",
		"cidr:2001-db8--0/73", "cidr:2001-db8--0/74", "cidr:2001-db8--0/75", "cidr:2001-db8--0/76",
		"cidr:2001-db8--0/77", "cidr:2001-db8--0/78", "cidr:2001-db8--0/79", "cidr:2001-db8--0/80",
		"cidr:2001-db8--0/81", "cidr:2001-db8--0/82", "cidr:2001-db8--0/83", "cidr:2001-db8--0/84",
		"cidr:2001-db8--0/85", "cidr:2001-db8--0/86", "cidr:2001-db8--0/87", "cidr:2001-db8--0/88",
		"cidr:2001-db8--0/89", "cidr:2001-db8--0/90", "cidr:2001-db8--0/91", "cidr:2001-db8--0/92",
		"cidr:2001-db8--0/93", "cidr:2001-db8--0/94", "cidr:2001-db8--0/95", "cidr:2001-db8--0/96",
		"cidr:2001-db8--0/97", "cidr:2001-db8--0/98", "cidr:2001-db8--0/99", "cidr:2001-db8--0/100",
		"cidr:2001-db8--0/101", "cidr:2001-db8--0/102", "cidr:2001-db8--0/103", "cidr:2001-db8--0/104",
		"cidr:2001-db8--0/105", "cidr:2001-db8--0/106", "cidr:2001-db8--0/107", "cidr:2001-db8--0/108",
		"cidr:2001-db8--0/109", "cidr:2001-db8--0/110", "cidr:2001-db8--0/111", "cidr:2001-db8--0/112",
		"cidr:2001-db8--0/113", "cidr:2001-db8--0/114", "cidr:2001-db8--0/115", "cidr:2001-db8--0/116",
		"cidr:2001-db8--0/117", "cidr:2001-db8--0/118", "cidr:2001-db8--0/119", "cidr:2001-db8--0/120",
		"cidr:2001-db8--0/121", "cidr:2001-db8--0/122", "cidr:2001-db8--0/123", "cidr:2001-db8--0/124",
		"cidr:2001-db8--0/125", "cidr:2001-db8--0/126", "cidr:2001-db8--0/127", "cidr:2001-db8--1/128",
		"cidr:1.1.1.1/32",
	} {
		lbl := ParseLabel(labelSpec)
		assert.Equal(t, LabelSourceCIDR, lbl.Source)
		assert.NotNil(t, lbl.cidr)
		ll := strings.SplitN(labelSpec, ":", 2)
		prefixString := strings.Replace(ll[1], "-", ":", -1)
		assert.Equal(t, netip.MustParsePrefix(prefixString).String(), lbl.cidr.String())
	}

	for _, labelSpec := range []string{
		"reserved:world", "k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=foo",
	} {
		lbl := ParseLabel(labelSpec)
		assert.NotEqual(t, LabelSourceCIDR, lbl.Source)
		assert.Nil(t, lbl.cidr)
	}
}
