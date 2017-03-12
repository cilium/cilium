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
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-labels")
)

const (
	ID_NAME_ALL   = "all"
	ID_NAME_HOST  = "host"
	ID_NAME_WORLD = "world"
)

type LabelOpType string

const (
	secLabelTimeout             = time.Duration(120 * time.Second)
	AddLabelsOp     LabelOpType = "AddLabelsOp"
	DelLabelsOp     LabelOpType = "DelLabelsOp"
	EnableLabelsOp  LabelOpType = "EnableLabelsOp"
	DisableLabelsOp LabelOpType = "DisableLabelsOp"
)

type LabelOp map[LabelOpType]Labels

type OpLabels struct {
	// Active labels that are enabled and disabled but not deleted
	Custom Labels
	// Labels derived from orchestration system
	Orchestration Labels
	// Orchestration labels which have been disabled
	Disabled Labels
}

func (o *OpLabels) DeepCopy() *OpLabels {
	return &OpLabels{
		Custom:        o.Custom.DeepCopy(),
		Disabled:      o.Disabled.DeepCopy(),
		Orchestration: o.Orchestration.DeepCopy(),
	}
}

func (o *OpLabels) Enabled() Labels {
	enabled := make(Labels, len(o.Custom)+len(o.Orchestration))

	for k, v := range o.Custom {
		enabled[k] = v
	}

	for k, v := range o.Orchestration {
		enabled[k] = v
	}

	return enabled
}

func NewOplabelsFromModel(base *models.LabelConfiguration) *OpLabels {
	if base == nil {
		return nil
	}

	return &OpLabels{
		Custom:        NewLabelsFromModel(base.Custom),
		Disabled:      NewLabelsFromModel(base.Disabled),
		Orchestration: NewLabelsFromModel(base.OrchestrationSystem),
	}
}

type LabelOwner interface {
	ResolveName(name string) string
}

// Label is the cilium's representation of a container label.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	// Source can be on of the values present in const.go (e.g.: CiliumLabelSource)
	Source string `json:"source"`
	absKey string
	// Mark element to be used to find unused labels in lists
	DeletionMark bool `json:"-"`
	owner        LabelOwner
}

// Labels is a map of labels where the map's key is the same as the label's key.
type Labels map[string]*Label

// Marks all labels with the DeletionMark
func (l Labels) MarkAllForDeletion() {
	for k := range l {
		l[k].DeletionMark = true
	}
}

// Deletes the labels which have the DeletionMark set and returns true if any
func (l Labels) DeleteMarked() bool {
	deleted := false
	for k := range l {
		if l[k].DeletionMark {
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
			absKey: v.absKey,
		}
	}
	return newLabels
}

// NewLabel returns a new label from the given key, value and source. If source is empty,
// the default value will be common.CiliumLabelSource. If key starts with '$', the source
// will be overwritten with common.ReservedLabelSource. If key contains ':', the value
// before ':' will be used as source if given source is empty, otherwise the value before
// ':' will be deleted and unused.
func NewLabel(key string, value string, source string) *Label {
	var src string
	src, key = parseSource(key)
	if source == "" {
		if src == "" {
			source = common.CiliumLabelSource
		} else {
			source = src
		}
	}
	if src == common.ReservedLabelSource && key == "" {
		key = value
		value = ""
	}

	return &Label{
		Key:    key,
		Value:  value,
		Source: source,
	}
}

// NewOwnedLabel returns a new label like NewLabel but also assigns an owner
func NewOwnedLabel(key string, value string, source string, owner LabelOwner) *Label {
	l := NewLabel(key, value, source)
	l.SetOwner(owner)
	return l
}

// SetOwner modifies the owner of a label
func (l *Label) SetOwner(owner LabelOwner) {
	l.owner = owner
}

// Equals returns true if source, AbsoluteKey() and Value are equal and false otherwise.
func (l *Label) Equals(b *Label) bool {
	return l.Source == b.Source &&
		l.AbsoluteKey() == b.AbsoluteKey() &&
		l.Value == b.Value
}

func (l *Label) IsAllLabel() bool {
	// ID_NAME_ALL is a special label which matches all labels
	return l.Source == common.ReservedLabelSource && l.Key == ID_NAME_ALL
}

func (l *Label) Matches(target *Label) bool {
	return l.IsAllLabel() || l.Equals(target)
}

// Resolve resolves the absolute key path for this Label from policyNode.
func (l *Label) Resolve(owner LabelOwner) {
	l.SetOwner(owner)

	// Force generation of absolute key
	l.AbsoluteKey()

	log.Debugf("Resolved label %s to path %s\n", l.String(), l.absKey)
}

// AbsoluteKey if set returns the absolute key path, otherwise returns the label's Key.
func (l *Label) AbsoluteKey() string {
	if l.absKey == "" {
		// Never translate using an owner if a reserved label
		if l.owner != nil && l.Source != common.ReservedLabelSource &&
			!strings.HasPrefix(l.Key, common.K8sPodNamespaceLabel) {
			l.absKey = l.owner.ResolveName(l.Key)
		} else {
			if !strings.HasPrefix(l.Key, "root.") {
				l.absKey = "root." + l.Key
			} else {
				l.absKey = l.Key
			}
		}
	}

	return l.absKey
}

// String returns the string representation of Label in the for of Source:Key=Value or
// Source:Key if Value is empty.
func (l Label) String() string {
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

func (lbls Labels) DeepCopy() Labels {
	o := Labels{}
	for k, v := range lbls {
		o[k] = &Label{
			Key:    v.Key,
			Value:  v.Value,
			Source: v.Source,
			absKey: v.absKey,
		}
	}
	return o
}

func NewLabelsFromModel(base []string) Labels {
	lbls := Labels{}
	for _, v := range base {
		lbl := ParseLabel(v)
		lbls[lbl.Key] = lbl
	}

	return lbls
}

func (lbls Labels) GetModel() []string {
	res := []string{}
	for _, v := range lbls {
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
func (lbls Labels) MergeLabels(from Labels) {
	fromCpy := from.DeepCopy()
	for k, v := range fromCpy {
		lbls[k] = v
	}
}

// SHA256Sum calculates lbls' internal SHA256Sum. For a particular set of labels is
// guarantee that it will always have the same SHA256Sum.
func (lbls Labels) SHA256Sum() string {
	return fmt.Sprintf("%x", sha512.New512_256().Sum(lbls.sortedList()))
}

func (lbls Labels) sortedList() []byte {
	var keys []string
	for k := range lbls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := ""
	for _, k := range keys {
		// We don't care if the values already have a '=' since this method is
		// only used to calculate a SHA256Sum
		result += fmt.Sprintf(`%s=%s;`, k, lbls[k].Value)
	}

	return []byte(result)
}

/// ToSlice returns a slice of label with the values of the given Labels' map.
func (lbls Labels) ToSlice() []Label {
	labels := []Label{}
	for _, v := range lbls {
		labels = append(labels, *v)
	}
	return labels
}

/// LabelSlice2LabelsMap returns a Labels' map with all labels from the given slice of
// label.
func LabelSlice2LabelsMap(lbls []Label) Labels {
	labels := Labels{}
	for _, v := range lbls {
		labels[v.Key] = NewLabel(v.Key, v.Value, v.Source)
	}
	return labels
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
		str = strings.Replace(str, "$", common.ReservedLabelSource+":", 1)
	}
	sourceSplit := strings.SplitN(str, ":", 2)
	if len(sourceSplit) != 2 {
		next = sourceSplit[0]
		if strings.HasPrefix(next, common.ReservedLabelKey) {
			src = common.ReservedLabelSource
			next = strings.TrimPrefix(next, common.ReservedLabelKey)
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
		lbl.Source = common.CiliumLabelSource
	}

	keySplit := strings.SplitN(next, "=", 2)
	lbl.Key = keySplit[0]
	if len(keySplit) > 1 {
		if src == common.ReservedLabelSource && keySplit[0] == "" {
			lbl.Key = keySplit[1]
		} else {
			lbl.Value = keySplit[1]
		}
	}
	return &lbl
}

func ParseStringLabels(strLbls []string) Labels {
	lbls := Labels{}
	for _, l := range strLbls {
		lbl := ParseLabel(l)
		lbls[lbl.Key] = lbl
	}

	return lbls
}

func LabelSliceSHA256Sum(labels []Label) (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(labels); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func ParseStringLabelsInOrder(strLbls []string) []Label {
	lbls := []Label{}
	for _, l := range strLbls {
		lbl := ParseLabel(l)
		lbls = append(lbls, *lbl)
	}

	return lbls
}
