// Copyright 2016-2018 Authors of Cilium
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
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
)

const (
	// IDNameAll is a special label which matches all labels.
	IDNameAll = "all"

	// IDNameHost is the label used for the hostname ID.
	IDNameHost = "host"

	// IDNameWorld is the label used for the world ID.
	IDNameWorld = "world"

	// IDNameCluster is the label used to identify an unspecified endpoint
	// inside the cluster
	IDNameCluster = "cluster"

	// IDNameHealth is the label used for the local cilium-health endpoint
	IDNameHealth = "health"

	// IDNameInit is the label used to identify any endpoint that has not
	// received any labels yet.
	IDNameInit = "init"
)

// OpLabels represents the the possible types.
// +k8s:openapi-gen=false
type OpLabels struct {
	// Active labels that are enabled and disabled but not deleted
	Custom Labels
	// Labels derived from orchestration system
	OrchestrationIdentity Labels

	//OrchestrationIdentity
	// OrchestrationIdentity labels which have been disabled
	Disabled Labels

	//OrchestrationInfo - labels from orchestration which are not used in determining a security identity
	OrchestrationInfo Labels
}

// IdentityLabels returns map of labels that are used when determining a
// security identity.
func (o *OpLabels) IdentityLabels() Labels {
	enabled := make(Labels, len(o.Custom)+len(o.OrchestrationIdentity))

	for k, v := range o.Custom {
		enabled[k] = v
	}

	for k, v := range o.OrchestrationIdentity {
		enabled[k] = v
	}

	return enabled
}

// AllLabels returns all Labels within the provided OpLabels.
func (o *OpLabels) AllLabels() Labels {
	all := make(Labels, len(o.Custom)+len(o.OrchestrationInfo)+len(o.OrchestrationIdentity)+len(o.Disabled))

	for k, v := range o.Custom {
		all[k] = v
	}

	for k, v := range o.Disabled {
		all[k] = v
	}

	for k, v := range o.OrchestrationIdentity {
		all[k] = v
	}

	for k, v := range o.OrchestrationInfo {
		all[k] = v
	}
	return all
}

// NewOplabelsFromModel creates new label from the model.
func NewOplabelsFromModel(base *models.LabelConfigurationStatus) *OpLabels {
	if base == nil {
		return nil
	}

	return &OpLabels{
		Custom:                NewLabelsFromModel(base.Realized.User),
		Disabled:              NewLabelsFromModel(base.Disabled),
		OrchestrationIdentity: NewLabelsFromModel(base.SecurityRelevant),
		OrchestrationInfo:     NewLabelsFromModel(base.Derived),
	}
}

const (
	// LabelSourceUnspec is a label with unspecified source
	LabelSourceUnspec = "unspec"

	// LabelSourceAny is a label that matches any source
	LabelSourceAny = "any"

	// LabelSourceK8s is a label imported from Kubernetes
	LabelSourceK8s = "k8s"

	// LabelSourceMesos is a label imported from Mesos
	LabelSourceMesos = "mesos"

	// LabelSourceK8sKeyPrefix is prefix of a Kubernetes label
	LabelSourceK8sKeyPrefix = LabelSourceK8s + "."

	// LabelSourceContainer is a label imported from the container runtime
	LabelSourceContainer = "container"

	// LabelSourceReserved is the label source for reserved types.
	LabelSourceReserved = "reserved"

	// LabelSourceCIDR is the label source for generated CIDRs.
	LabelSourceCIDR = "cidr"

	// LabelSourceReservedKeyPrefix is the prefix of a reserved label
	LabelSourceReservedKeyPrefix = LabelSourceReserved + "."
)

// Label is the cilium's representation of a container label.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	// Source can be one of the values present in const.go (e.g.: LabelSourceContainer)
	Source string `json:"source"`
	// Mark element to be used to find unused labels in lists
	deletionMark bool
}

// Labels is a map of labels where the map's key is the same as the label's key.
type Labels map[string]*Label

// GetPrintableModel turns the Labels into a sorted list of strings
// representing the labels, with CIDRs deduplicated (ie, only provide the most
// specific CIDR).
func (l Labels) GetPrintableModel() (res []string) {
	cidr := ""
	prefixLength := 0
	for _, v := range l {
		if v.Source == LabelSourceCIDR {
			vStr := strings.Replace(v.String(), "-", ":", -1)
			prefix := strings.Replace(v.Key, "-", ":", -1)
			_, ipnet, _ := net.ParseCIDR(prefix)
			ones, _ := ipnet.Mask.Size()
			if ones > prefixLength {
				cidr = vStr
				prefixLength = ones
			}
			continue
		}
		res = append(res, v.String())
	}
	if cidr != "" {
		res = append(res, cidr)
	}

	sort.Strings(res)
	return res
}

// String returns the map of labels as human readable string
func (l Labels) String() string {
	return strings.Join(l.GetPrintableModel(), ",")
}

// MarkAllForDeletion marks all the labels with the deletionMark.
func (l Labels) MarkAllForDeletion() {
	for k := range l {
		l[k].deletionMark = true
	}
}

func (l *Label) ClearDeletionMark() {
	l.deletionMark = false
}

// UpsertLabel updates or inserts 'label' in 'l', but only if exactly the same label
// was not already in 'l'. If a label with the same key is found, the label's deletionMark
// is cleared. Returns 'true' if a label was added, or an old label was updated, 'false'
// otherwise.
func (l Labels) UpsertLabel(label *Label) bool {
	oldLabel := l[label.Key]
	if oldLabel != nil {
		l[label.Key].ClearDeletionMark()
		// Key is the same, check if Value and Source are also the same
		if label.Value == oldLabel.Value && label.Source == oldLabel.Source {
			return false // No change
		}
	}
	// Insert or replace old label
	l[label.Key] = label.DeepCopy()
	return true
}

// DeleteMarked deletes the labels which have the deletionMark set and returns
// true if any of them were deleted.
func (l Labels) DeleteMarked() bool {
	deleted := false
	for k := range l {
		if l[k].deletionMark {
			delete(l, k)
			deleted = true
		}
	}

	return deleted
}

// AppendPrefixInKey appends the given prefix to all the Key's of the map and the
// respective Labels' Key.
func (l Labels) AppendPrefixInKey(prefix string) Labels {
	newLabels := Labels{}
	for k, v := range l {
		newLabels[prefix+k] = &Label{
			Key:    prefix + v.Key,
			Value:  v.Value,
			Source: v.Source,
		}
	}
	return newLabels
}

// Equals returns true if the two Labels contain the same set of labels.
func (l Labels) Equals(other Labels) bool {
	if len(l) != len(other) {
		return false
	}

	for k, lbl1 := range l {
		if lbl2, ok := other[k]; ok {
			if lbl1.Source == lbl2.Source && lbl1.Key == lbl2.Key && lbl1.Value == lbl2.Value {
				continue
			}
		}
		return false
	}
	return true
}

// NewLabel returns a new label from the given key, value and source. If source is empty,
// the default value will be LabelSourceUnspec. If key starts with '$', the source
// will be overwritten with LabelSourceReserved. If key contains ':', the value
// before ':' will be used as source if given source is empty, otherwise the value before
// ':' will be deleted and unused.
func NewLabel(key string, value string, source string) *Label {
	var src string
	src, key = parseSource(key)
	if source == "" {
		if src == "" {
			source = LabelSourceUnspec
		} else {
			source = src
		}
	}
	if src == LabelSourceReserved && key == "" {
		key = value
		value = ""
	}

	return &Label{
		Key:    key,
		Value:  value,
		Source: source,
	}
}

// Equals returns true if source, AbsoluteKey() and Value are equal and false otherwise.
func (l *Label) Equals(b *Label) bool {
	if !l.IsAnySource() {
		if l.Source != b.Source {
			return false
		}
	}
	return l.Key == b.Key && l.Value == b.Value
}

// IsAllLabel returns true if the label is reserved and matches with IDNameAll.
func (l *Label) IsAllLabel() bool {
	return l.Source == LabelSourceReserved && l.Key == "all"
}

// IsAnySource return if the label was set with source "any".
func (l *Label) IsAnySource() bool {
	return l.Source == LabelSourceAny
}

// Matches returns true if l matches the target
func (l *Label) Matches(target *Label) bool {
	return l.IsAllLabel() || l.Equals(target)
}

// String returns the string representation of Label in the for of Source:Key=Value or
// Source:Key if Value is empty.
func (l *Label) String() string {
	if len(l.Value) != 0 {
		return fmt.Sprintf("%s:%s=%s", l.Source, l.Key, l.Value)
	}
	return fmt.Sprintf("%s:%s", l.Source, l.Key)
}

// IsValid returns true if Key != "".
func (l *Label) IsValid() bool {
	return l.Key != ""
}

// UnmarshalJSON TODO create better explanation about unmarshall with examples
func (l *Label) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	if l == nil {
		return fmt.Errorf("cannot unmarhshal to nil pointer")
	}

	if len(data) == 0 {
		return fmt.Errorf("invalid Label: empty data")
	}

	var aux struct {
		Source string `json:"source"`
		Key    string `json:"key"`
		Value  string `json:"value,omitempty"`
	}

	err := decoder.Decode(&aux)
	if err != nil {
		// If parsing of the full representation failed then try the short
		// form in the format:
		//
		// [SOURCE:]KEY[=VALUE]
		var aux string

		decoder = json.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("decode of Label as string failed: %+v", err)
		}

		if aux == "" {
			return fmt.Errorf("invalid Label: Failed to parse %s as a string", data)
		}

		*l = *ParseLabel(aux)
	} else {
		if aux.Key == "" {
			return fmt.Errorf("invalid Label: '%s' does not contain label key", data)
		}

		l.Source = aux.Source
		l.Key = aux.Key
		l.Value = aux.Value
	}

	return nil
}

// GetExtendedKey returns the key of a label with the source encoded.
func (l *Label) GetExtendedKey() string {
	return l.Source + common.PathDelimiter + l.Key
}

// GetCiliumKeyFrom returns the label's source and key from the an extended key
// in the format SOURCE:KEY.
func GetCiliumKeyFrom(extKey string) string {
	sourceSplit := strings.SplitN(extKey, common.PathDelimiter, 2)
	if len(sourceSplit) == 2 {
		return sourceSplit[0] + ":" + sourceSplit[1]
	}
	return LabelSourceAny + ":" + sourceSplit[0]
}

// GetExtendedKeyFrom returns the extended key of a label string.
// For example:
// `k8s:foo=bar` returns `k8s.foo`
// `container:foo=bar` returns `container.foo`
// `foo=bar` returns `any.foo=bar`
func GetExtendedKeyFrom(str string) string {
	src, next := parseSource(str)
	if src == "" {
		src = LabelSourceAny
	}
	// Remove an eventually value
	nextSplit := strings.SplitN(next, "=", 2)
	next = nextSplit[0]
	return src + common.PathDelimiter + next
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels. The
// source argument will overwrite the source written in the key of the given map.
// Example:
// l := Map2Labels(map[string]string{"k8s:foo": "bar"}, "cilium")
// fmt.Printf("%+v\n", l)
//   map[string]Label{"foo":Label{Key:"foo", Value:"bar", Source:"cilium"}}
func Map2Labels(m map[string]string, source string) Labels {
	o := Labels{}
	for k, v := range m {
		l := NewLabel(k, v, source)
		o[l.Key] = l
	}
	return o
}

// DeepCopy returns a deep copy of the labels.
func (l Labels) DeepCopy() Labels {
	if l == nil {
		return nil
	}

	o := make(Labels, len(l))
	for k, v := range l {
		o[k] = v.DeepCopy()
	}
	return o
}

// NewLabelsFromModel creates labels from string array.
func NewLabelsFromModel(base []string) Labels {
	lbls := make(Labels, len(base))
	for _, v := range base {
		if lbl := ParseLabel(v); lbl.Key != "" {
			lbls[lbl.Key] = lbl
		}
	}

	return lbls
}

// NewLabelsFromSortedList returns labels based on the output of SortedList()
func NewLabelsFromSortedList(list string) Labels {
	return NewLabelsFromModel(strings.Split(list, ";"))
}

// NewSelectLabelArrayFromModel parses a slice of strings and converts them
// into an array of selecting labels.
func NewSelectLabelArrayFromModel(base []string) LabelArray {
	lbls := make(LabelArray, 0, len(base))
	for _, v := range base {
		lbls = append(lbls, ParseSelectLabel(v))
	}

	return lbls
}

// GetModel returns model with all the values of the labels.
func (l Labels) GetModel() []string {
	res := make([]string, 0, len(l))
	for _, v := range l {
		res = append(res, v.String())
	}
	return res
}

// MergeLabels merges labels from into to. It overwrites all labels with the same Key as
// from written into to.
// Example:
// to := Labels{Label{key1, value1, source1}, Label{key2, value3, source4}}
// from := Labels{Label{key1, value3, source4}}
// to.MergeLabels(from)
// fmt.Printf("%+v\n", to)
//   Labels{Label{key1, value3, source4}, Label{key2, value3, source4}}
func (l Labels) MergeLabels(from Labels) {
	fromCpy := from.DeepCopy()
	for k, v := range fromCpy {
		l[k] = v
	}
}

// SHA256Sum calculates l' internal SHA256Sum. For a particular set of labels is
// guarantee that it will always have the same SHA256Sum.
func (l Labels) SHA256Sum() string {
	return fmt.Sprintf("%x", sha512.Sum512_256(l.SortedList()))
}

// SortedList returns the labels as a sorted list, separated by semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS KEY IN
// THE KEY-VALUE STORE.
func (l Labels) SortedList() []byte {
	var keys []string
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := ""
	for _, k := range keys {
		// We don't care if the values already have a '=' since this method is
		// only used to calculate a SHA256Sum
		result += fmt.Sprintf(`%s:%s=%s;`, l[k].Source, k, l[k].Value)
	}

	return []byte(result)
}

// ToSlice returns a slice of label with the values of the given Labels' map.
func (l Labels) ToSlice() []*Label {
	labels := []*Label{}
	for _, v := range l {
		labels = append(labels, v.DeepCopy())
	}
	return labels
}

// LabelArray returns the labels as label array
func (l Labels) LabelArray() LabelArray {
	return l.ToSlice()
}

// FindReserved locates all labels with reserved source in the labels and
// returns a copy of them. If there are no reserved labels, returns nil.
func (l Labels) FindReserved() Labels {
	lbls := Labels{}

	for k, lbl := range l {
		if lbl.Source == LabelSourceReserved {
			lbls[k] = lbl.DeepCopy()
		}
	}

	if len(lbls) > 0 {
		return lbls
	}
	return nil
}

// parseSource returns the parsed source of the given str. It also returns the next piece
// of text that is after the source.
// Example:
//  src, next := parseSource("foo:bar==value")
// Println(src) // foo
// Println(next) // bar==value
func parseSource(str string) (src, next string) {
	if str == "" {
		return "", ""
	}
	if str[0] == '$' {
		str = strings.Replace(str, "$", LabelSourceReserved+":", 1)
	}
	sourceSplit := strings.SplitN(str, ":", 2)
	if len(sourceSplit) != 2 {
		next = sourceSplit[0]
		if strings.HasPrefix(next, LabelSourceReserved) {
			src = LabelSourceReserved
			next = strings.TrimPrefix(next, LabelSourceReservedKeyPrefix)
		}
	} else {
		if sourceSplit[0] != "" {
			src = sourceSplit[0]
		}
		next = sourceSplit[1]
	}
	return
}

// ParseLabel returns the label representation of the given string. The str should be
// in the form of Source:Key=Value or Source:Key if Value is empty. It also parses short
// forms, for example: $host will be Label{Key: "host", Source: "reserved", Value: ""}.
func ParseLabel(str string) *Label {
	lbl := Label{}
	src, next := parseSource(str)
	if src != "" {
		lbl.Source = src
	} else {
		lbl.Source = LabelSourceUnspec
	}

	keySplit := strings.SplitN(next, "=", 2)
	lbl.Key = keySplit[0]
	if len(keySplit) > 1 {
		if src == LabelSourceReserved && keySplit[0] == "" {
			lbl.Key = keySplit[1]
		} else {
			lbl.Value = keySplit[1]
		}
	}
	return &lbl
}

// ParseSelectLabel returns a selecting label representation of the given
// string. Unlike ParseLabel, if source is unspecified, the source defaults to
// LabelSourceAny
func ParseSelectLabel(str string) *Label {
	lbl := ParseLabel(str)

	if lbl.Source == LabelSourceUnspec {
		lbl.Source = LabelSourceAny
	}

	return lbl
}

// generateLabelString generates the string representation of a label with
// the provided source, key, and value in the format "source:key=value".
func generateLabelString(source, key, value string) string {
	return fmt.Sprintf("%s:%s=%s", source, key, value)
}

// GenerateK8sLabelString generates the string representation of a label with
// the provided source, key, and value in the format "LabelSourceK8s:key=value".
func GenerateK8sLabelString(k, v string) string {
	return generateLabelString(LabelSourceK8s, k, v)
}
