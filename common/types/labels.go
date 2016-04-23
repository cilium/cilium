package types

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/noironetworks/cilium-net/common"
)

// Label is the cilium's representation of a container label.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	// Source can be on of the values present in const.go (e.g.: CiliumLabelSource)
	Source string `json:"source"`
	absKey string
}

// Labels is a map of labels where the map's key is the same as the label's key.
type Labels map[string]*Label

// SecCtxLabel is the representation of the security context for a particular set of
// labels.
type SecCtxLabel struct {
	ID       int    `json:"id"`        // SecCtxLabel's ID.
	RefCount int    `json:"ref-count"` // Number of containers that have this SecCtxLabel.
	Labels   Labels `json:"labels"`    // Set of labels that belong to this SecCtxLabel.
}

// NewLabel returns a new label from the given key, value and source.
func NewLabel(key string, value string, source string) *Label {
	return &Label{
		Key:    key,
		Value:  value,
		Source: source,
	}
}

// Equals returns true if source, AbsoluteKey() and Value are equal and false otherwise.
func (l *Label) Equals(b *Label) bool {
	return l.Source == b.Source &&
		l.AbsoluteKey() == b.AbsoluteKey() &&
		l.Value == b.Value
}

// Resolve resolves the absolute key path for this Label from policyNode.
func (l *Label) Resolve(policyNode *PolicyNode) {
	if l.Source == common.CiliumLabelSource &&
		!strings.HasPrefix(l.Key, common.GlobalLabelPrefix) {
		l.absKey = policyNode.Path() + "." + l.Key
	} else {
		l.absKey = l.Key
	}
}

// AbsoluteKey if set returns the absolute key path, otherwise returns the label's Key.
func (l *Label) AbsoluteKey() string {
	if l.absKey != "" {
		return l.absKey
	}

	return l.Key
}

// String returns the string representation of Label in the for of Source#Key=Value or
// Source#Key if Value is empty.
func (l Label) String() string {
	if len(l.Value) != 0 {
		return fmt.Sprintf("%s#%s=%s", l.Source, l.Key, l.Value)
	}
	return fmt.Sprintf("%s#%s", l.Source, l.Key)
}

func decodeReservedLabel(source string, label *Label) {
	label.Source = common.ReservedLabelSource
	label.Key = source[1:]
	label.Value = ""
}

func decodeLabelShortForm(source string, label *Label) {
	if source[0] == '$' {
		decodeReservedLabel(source, label)
		return
	}

	sep := strings.SplitN(source, ":", 2)
	if len(sep) != 2 {
		label.Source = common.CiliumLabelSource
	} else {
		if sep[0] == "" {
			label.Source = common.CiliumLabelSource
		} else {
			label.Source = sep[0]
		}
		source = sep[1]
	}

	sep = strings.SplitN(source, "=", 2)
	if len(sep) == 1 {
		label.Key = source
		label.Value = ""
	} else {
		label.Key = sep[0]
		label.Value = sep[1]
	}
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

	if bytes.Contains(data, []byte(`"source":`)) {
		var aux struct {
			Source string `json:"source"`
			Key    string `json:"key"`
			Value  string `json:"value,omitempty"`
		}

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("decode of Label failed: %+v", err)
		}

		if aux.Key == "" {
			return fmt.Errorf("invalid Label: '%s' does not contain label key", data)
		}

		l.Source = aux.Source
		l.Key = aux.Key
		l.Value = aux.Value
	} else {
		// This is a short form in which only a string to be interpreted
		// as a cilium label key is provided
		var aux string

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("decode of Label as string failed: %+v", err)
		}

		if aux == "" {
			return fmt.Errorf("invalid Label: Failed to parse %s as a string", data)
		}

		decodeLabelShortForm(aux, l)
	}

	return nil
}

// Map2Labels transforms in the form: map[key(string)]value(string) into Labels.
// Example:
// l := Map2Labels(map[string]string{"foo": "bar"}, "cilium")
// fmt.Printf("%+v\n", l)
//   map[string]Label{"foo":Label{Key:"foo", Value:"bar", Source:"cilium"}}
func Map2Labels(m map[string]string, source string) Labels {
	o := Labels{}
	for k, v := range m {
		o[k] = &Label{
			Key:    k,
			Value:  v,
			Source: source,
		}
	}
	return o
}

// MergeLabels merges labels from into to. It overwrites all labels with the same Key as
// from writen into to.
// Example:
// to := Labels{Label{key1, value1, source1}, Label{key2, value3, source4}}
// from := Labels{Label{key1, value3, source4}}
// to.MergeLabels(from)
// fmt.Printf("%+v\n", to)
//   Labels{Label{key1, value3, source4}, Label{key2, value3, source4}}
func (lbls Labels) MergeLabels(from Labels) {
	for k, v := range from {
		lbls[k] = v
	}
}

// SHA256Sum calculates lbls' internal SHA256Sum. For a particular set of labels is
// guarantee that it will always have the same SHA256Sum.
func (lbls Labels) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	sortedMap := lbls.sortMap()
	if err := json.NewEncoder(sha).Encode(sortedMap); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (lbls Labels) sortMap() []string {
	var keys []string
	for k := range lbls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sortedMap []string
	for _, k := range keys {
		// We don't care if the values already have a '=' since this method is
		// only used to calculate a SHA256Sum
		str := fmt.Sprintf(`%s=%s`, k, lbls[k].Value)
		sortedMap = append(sortedMap, str)
	}
	return sortedMap
}

/// ToSlice returns a slice of label with the values of the given Labels' map.
func (lbls Labels) ToSlice() []Label {
	labels := []Label{}
	for _, v := range lbls {
		labels = append(labels, *v)
	}
	return labels
}
