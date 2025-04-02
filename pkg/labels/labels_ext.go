// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"bytes"
	"iter"
	"net/netip"
	"slices"
	"strings"
	"unique"

	"github.com/cilium/cilium/pkg/option"
)

// This file contains the domain specific getters for 'Labels'. This
// way the core implementation is cleanly separated, while still
// having the convenience of these methods as part of 'Labels'.

func (l Labels) LabelArray() LabelArray {
	return LabelArray(l.ToSlice())
}

func (l Labels) HasLabelWithKey(key string) bool {
	_, ok := l.GetLabel(key)
	return ok
}

//
// Convenience functions to use instead of Has(), which iterates through the labels
//

func (l Labels) HasFixedIdentityLabel() bool {
	return l.HasLabelWithKey(LabelKeyFixedIdentity)
}

func (l Labels) HasInitLabel() bool {
	return l.HasLabelWithKey(IDNameInit)
}

func (l Labels) HasHealthLabel() bool {
	return l.HasLabelWithKey(IDNameHealth)
}

func (l Labels) HasIngressLabel() bool {
	return l.HasLabelWithKey(IDNameIngress)
}

func (l Labels) HasHostLabel() bool {
	return l.HasLabelWithKey(IDNameHost)
}

func (l Labels) HasKubeAPIServerLabel() bool {
	return l.HasLabelWithKey(IDNameKubeAPIServer)
}

func (l Labels) HasRemoteNodeLabel() bool {
	return l.HasLabelWithKey(IDNameRemoteNode)
}

func (l Labels) HasWorldIPv6Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv6)
}

func (l Labels) HasWorldIPv4Label() bool {
	return l.HasLabelWithKey(IDNameWorldIPv4)
}

func (l Labels) HasNonDualstackWorldLabel() bool {
	return l.HasLabelWithKey(IDNameWorld)
}

func (l Labels) HasWorldLabel() bool {
	return l.HasNonDualstackWorldLabel() || l.HasWorldIPv4Label() || l.HasWorldIPv6Label()
}

func (lbls Labels) FromSource(source string) iter.Seq[Label] {
	return func(yield func(Label) bool) {
		for l := range lbls.All() {
			if l.Source() == source {
				if !yield(l) {
					break
				}
			}
		}
	}
}

func (lbls Labels) Contains(other Labels) bool {
	if other.isZero() {
		return true
	} else if lbls.isZero() {
		return false
	}

	rep := lbls.handle.Value()
	repOther := lbls.handle.Value()
	if lbls.overflow == nil && other.overflow == nil && rep.smallLen == repOther.smallLen {
		// Fast path, no overflow and same amount of labels. We can just compare the
		// handles directly.
		return lbls.handle == other.handle
	} else if other.Len() > lbls.Len() {
		return false
	}

	for l := range other.All() {
		_, found := lbls.GetLabel(l.Key())
		if !found {
			return false
		}
	}
	return true
}

func (l Labels) GetPrintableModel() []string {
	return slices.Collect(l.Printable())
}

// Printable returns a (sorted) iterator of strings representing the labels.
func (l Labels) Printable() iter.Seq[string] {
	return func(yield func(string) bool) {
		for lbl := range l.All() {
			var s string
			if lbl.Source() == LabelSourceCIDR {
				s = LabelSourceCIDR + ":" + lbl.CIDR().String()
			} else {
				s = lbl.String()
			}
			if !yield(s) {
				return
			}
		}
	}
}

// String returns the map of labels as human readable string
func (l Labels) String() string {
	var b strings.Builder
	for l := range l.Printable() {
		b.WriteString(l)
		b.WriteByte(',')
	}
	s := b.String()
	if len(s) > 0 {
		// Drop trailing comma
		s = s[:len(s)-1]
	}
	return s
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map,
// unless it is the empty string.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// l == [{Key: "foo", Value: "bar", Source: "cilium")]
//
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "")
// l == [{Key: "foo", Value: "bar", Source: "k8s")]
func Map2Labels(m map[string]string, source string) Labels {
	if len(m) <= smallLabelsSize {
		// Fast path: fits into the small array and we can sort in-place.
		rep := smallRep{}
		for k, v := range m {
			src, k := ParseSource(k, ':')
			if source != "" {
				src = source
			}
			rep.smallArray[rep.smallLen] = MakeLabel(k, v, src)
			rep.smallLen++
		}
		slices.SortFunc(rep.smallArray[:rep.smallLen], func(a, b Label) int {
			return strings.Compare(a.Key(), b.Key())
		})
		lbls := Labels{
			handle: unique.Make(rep),
		}
		return lbls
	}

	// Slow path: does not fit into small array. Build up an temporary,
	// sort it, and construct the labels with it.
	lbls := make([]Label, 0, len(m))
	for k, v := range m {
		src, k := ParseSource(k, ':')
		if source != "" {
			src = source
		}
		lbls = append(lbls, MakeLabel(k, v, src))
	}
	return NewLabels(lbls...)
}

func (lbls Labels) StringMap() (m map[string]string) {
	m = make(map[string]string, lbls.Len())
	for l := range lbls.All() {
		rep := l.rep()
		// Key is "Source:Key", which is what we already have in skv.
		m[rep.skv[:rep.vpos-1]] = rep.value()
	}
	return
}

// Merge labels, preferring right when keys match.
// Example:
// left := Labels{Label{key1, value1, source1}, Label{key2, value3, source4}}
// right := Labels{Label{key1, value3, source4}}
// res := Merge(left, right)
// fmt.Printf("%+v\n", res)
//
//	Labels{Label{key1, value3, source4}, Label{key2, value3, source4}}
func Merge(left, right Labels) Labels {
	out := make([]Label, 0, left.Len()+right.Len())

	nextLeft, stopLeft := iter.Pull(left.All())
	nextRight, stopRight := iter.Pull(right.All())
	defer stopLeft()
	defer stopRight()

	a, ok1 := nextLeft()
	b, ok2 := nextRight()

	// Loop consumes at least one value each iteration.
	for ok1 && ok2 {
		ak, bk := a.Key(), b.Key()
		switch {
		case ak < bk:
			out = append(out, a)
			a, ok1 = nextLeft()
		case ak == bk:
			a, ok1 = nextLeft()
			fallthrough
		default:
			out = append(out, b)
			b, ok2 = nextRight()
		}
	}
	// One or both iterators are exhausted, consume the rest.
	for ok1 {
		out = append(out, a)
		a, ok1 = nextLeft()
	}
	for ok2 {
		out = append(out, b)
		b, ok2 = nextRight()
	}

	return NewLabels(out...)
}

// Merge labels together. Returns new labels.
func (lbls Labels) Merge(other Labels) Labels {
	return Merge(lbls, other)
}

// Add label(s). Returns new [Labels].
func (lbls Labels) Add(labels ...Label) Labels {
	return Merge(lbls, NewLabels(labels...))
}

// Remove returns a new Labels object with the given labels removed.
func (lbls Labels) Remove(labels ...Label) Labels {
	return lbls.Difference(NewLabels(labels...))
}

// Difference returns a new Labels object with the labels from [other]
// removed from it.
func (lbls Labels) Difference(other Labels) Labels {
	out := make([]Label, 0, lbls.Len())
	for lbl := range lbls.All() {
		if _, ok := other.GetLabel(lbl.Key()); !ok {
			out = append(out, lbl)
		}
	}
	return NewLabels(out...)
}

// RemoveKeys returns a new Labels object with the given keys removed.
func (lbls Labels) RemoveKeys(keys ...string) Labels {
	out := make([]Label, 0, lbls.Len())
outer:
	for lbl := range lbls.All() {
		for _, k := range keys {
			if lbl.Key() == k {
				continue outer
			}
		}
		out = append(out, lbl)
	}
	return NewLabels(out...)
}

func (lbls Labels) GetFromSource(source string) Labels {
	out := make([]Label, 0, lbls.Len())
	for lbl := range lbls.All() {
		if lbl.Source() == source {
			out = append(out, lbl)
		}
	}
	return NewLabels(out...)
}

func (lbls Labels) RemoveFromSource(source string) Labels {
	out := make([]Label, 0, lbls.Len())
	for lbl := range lbls.All() {
		if lbl.Source() == source {
			continue
		}
		out = append(out, lbl)
	}
	return NewLabels(out...)
}

func (lbls Labels) K8sStringMap() (m map[string]string) {
	m = make(map[string]string, lbls.Len())
	for lbl := range lbls.All() {
		switch lbl.Source() {
		case LabelSourceK8s, LabelSourceAny, LabelSourceUnspec:
			m[lbl.Key()] = lbl.Value()
		default:
			m[lbl.Source()+"."+lbl.Key()] = lbl.Value()
		}
	}
	return
}

func (lbls Labels) Filter(filter func(Label) bool) Labels {
	newLabels := make([]Label, 0, lbls.Len())
	for lbl := range lbls.All() {
		if filter(lbl) {
			newLabels = append(newLabels, lbl)
		}
	}
	return NewLabels(newLabels...)
}

// GetModel returns model with all the values of the labels.
func (l Labels) GetModel() []string {
	res := make([]string, 0, l.Len())
	for v := range l.All() {
		res = append(res, v.String())
	}
	return res
}

var (
	worldLabelNonDualStack = NewLabel(IDNameWorld, "", LabelSourceReserved)
	worldLabelV4           = NewLabel(IDNameWorldIPv4, "", LabelSourceReserved)
	worldLabelV6           = NewLabel(IDNameWorldIPv6, "", LabelSourceReserved)
)

func (lbls Labels) AddWorldLabel(addr netip.Addr) Labels {
	ls := slices.Collect(lbls.All())
	switch {
	case !option.Config.IsDualStack():
		ls = append(ls, worldLabelNonDualStack)
	case addr.Is4():
		ls = append(ls, worldLabelV4)
	default:
		ls = append(ls, worldLabelV6)
	}

	return NewLabels(ls...)
}

// IsReserved returns true if any of the labels has a reserved source.
func (l Labels) IsReserved() bool {
	return l.HasSource(LabelSourceReserved)
}

// FindReserved locates all labels with reserved source in the labels and
// returns a copy of them.
func (l Labels) FindReserved() Labels {
	return NewLabels(slices.Collect(l.FromSource(LabelSourceReserved))...)
}

// ToSlice returns a slice of label with the values of the given
// Labels' map, sorted by the key.
func (l Labels) ToSlice() []Label {
	return slices.AppendSeq(make([]Label, 0, l.Len()), l.All())
}

// SortedList returns the labels as a sorted list, separated by semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS KEY IN
// THE KEY-VALUE STORE.
func (l Labels) SortedList() []byte {
	// Labels can have arbitrary size. IPv4 CIDR labels in serialized form are
	// max 25 bytes long. Allocate slightly more to avoid having a realloc if
	// there's some other labels which may be longer, since the cost of
	// allocating a few bytes more is dominated by a second allocation,
	// especially since these allocations are short-lived.
	//
	// cidr:123.123.123.123/32=;
	// 0        1         2
	// 1234567890123456789012345
	b := make([]byte, 0, l.Len()*30)
	buf := bytes.NewBuffer(b)
	for l := range l.All() {
		l.FormatForKVStoreInto(buf)
	}

	return buf.Bytes()
}

// Has returns true if l contains the given label.
func (l Labels) HasLabel(label Label) bool {
	lbl, found := l.GetLabel(label.Key())
	return found && label.Equal(lbl)
}

// HasSource returns true if l contains the given label source.
func (l Labels) HasSource(source string) bool {
	for range l.FromSource(source) {
		return true
	}
	return false
}

// CollectSources returns all distinct label sources found in l
func (l Labels) CollectSources() map[string]struct{} {
	sources := make(map[string]struct{})
	for lbl := range l.All() {
		sources[lbl.Source()] = struct{}{}
	}
	return sources
}

func (l Labels) DeepEqual(other *Labels) bool {
	if other == nil {
		return false
	}
	return l.Equal(*other)
}

func (lbls Labels) DeepCopy() Labels {
	return lbls
}

func (lbls Labels) getByKey(key string) (value string, exists bool) {
	// The key is submitted in the form of `source.key=value`
	src, next := ParseSource(key, '.')
	if src == "" || src == LabelSourceUnspec {
		src = LabelSourceAny
	}
	var key2 string
	i := strings.IndexByte(next, '=')
	if i < 0 {
		key2 = next
	} else {
		if i == 0 && src == LabelSourceReserved {
			key2 = next[i+1:]
		} else {
			key2 = next[:i]
		}
	}
	if src == LabelSourceCIDR {
		c, err := LabelToPrefix(key2)
		if err != nil {
			return "", false
		}
		for l := range lbls.All() {
			if l.HasCIDR(c) {
				return l.Value(), true
			}
		}
	}

	match, ok := lbls.GetLabel(key2)
	if !ok {
		return "", false
	}
	if src != LabelSourceAny && match.Source() != src {
		return "", false
	}
	return match.Value(), true

}

func (lbls Labels) Get(key string) (value string) {
	value, _ = lbls.getByKey(key)
	return
}

func (lbls Labels) Has(key string) (exists bool) {
	_, exists = lbls.getByKey(key)
	return
}

func FromSlice(lbls []Label) Labels {
	return NewLabels(lbls...)
}

// ParseLabels parses the labels from strings.
func ParseLabels(s ...string) Labels {
	lbls := make([]Label, 0, len(s))
	for _, v := range s {
		if lbl := ParseLabel(v); lbl.Key() != "" {
			lbls = append(lbls, lbl)
		}
	}
	return NewLabels(lbls...)
}

// NewLabelsFromSortedList returns labels based on the output of SortedList()
// Trailing ';' will result in an empty key that must be filtered out.
func NewLabelsFromSortedList(list string) Labels {
	base := strings.Split(list, ";")
	array := make([]Label, 0, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key() != "" {
			array = append(array, lbl)
		}
	}
	return NewLabels(array...)
}

// Intersects returns true if ls contains at least one label in needed.
//
// This has the same matching semantics as Has, namely,
// ["k8s:foo=bar"].Intersects(["any:foo=bar"]) == true
// ["any:foo=bar"].Intersects(["k8s:foo=bar"]) == false
func (lbls Labels) Intersects(needed Labels) bool {
	for l := range lbls.All() {
		for n := range needed.All() {
			if l.Has(n) {
				return true
			}
		}
	}
	return false
}

// generateLabelString generates the string representation of a label with
// the provided source, key, and value in the format "source:key=value".
func generateLabelString(source, key, value string) string {
	return source + ":" + key + "=" + value
}

// GenerateK8sLabelString generates the string representation of a label with
// the provided source, key, and value in the format "LabelSourceK8s:key=value".
func GenerateK8sLabelString(k, v string) string {
	return generateLabelString(LabelSourceK8s, k, v)
}

// GetExtendedKeyFrom returns the extended key of a label string.
// For example:
// `k8s:foo=bar` returns `k8s.foo`
// `container:foo=bar` returns `container.foo`
// `foo=bar` returns `any.foo=bar`
func GetExtendedKeyFrom(str string) string {
	src, next := ParseSource(str, ':')
	if src == "" {
		src = LabelSourceAny
	}
	// Remove an eventually value
	i := strings.IndexByte(next, '=')
	if i >= 0 {
		return src + PathDelimiter + next[:i]
	}
	return src + PathDelimiter + next
}

// NewLabelsFromModel creates labels from string array.
func NewLabelsFromModel(base []string) Labels {
	lbls := make([]Label, 0, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key() != "" {
			lbls = append(lbls, lbl)
		}
	}
	return NewLabels(lbls...)
}

// GetCiliumKeyFrom returns the label's source and key from the an extended key
// in the format SOURCE:KEY.
func GetCiliumKeyFrom(extKey string) string {
	i := strings.IndexByte(extKey, PathDelimiter[0])
	if i >= 0 {
		return extKey[:i] + ":" + extKey[i+1:]
	}
	return LabelSourceAny + ":" + extKey
}
