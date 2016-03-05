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

type Label struct {
	Key    string `json:"Key"`
	Value  string `json:"Value,omitempty"`
	absKey string
	Source string `json:"Source"`
}

func NewLabel(key string, value string, source string) Label {
	lbl := Label{
		Key:    key,
		Value:  value,
		Source: source,
	}

	return lbl
}

func (l *Label) Compare(b *Label) bool {
	return l.Source == b.Source && l.AbsoluteKey() == b.AbsoluteKey() && l.Value == b.Value
}

func (l *Label) Resolve(node *PolicyNode) {
	if l.Source == "cilium" && !strings.HasPrefix(l.Key, common.GlobalLabelPrefix) {
		l.absKey = node.Path() + "." + l.Key
	} else {
		l.absKey = l.Key
	}
}

func (l *Label) AbsoluteKey() string {
	if l.absKey != "" {
		return l.absKey
	}

	return l.Key
}

func (l *Label) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	if l == nil {
		return fmt.Errorf("Cannot unmarhshal to nil pointer")
	}

	if len(data) == 0 {
		return fmt.Errorf("Invalid Label: empty data")
	}

	if bytes.Contains(data, []byte(`"source":`)) {
		var aux struct {
			Source string `json:"Source"`
			Key    string `json:"Key"`
			Value  string `json:"value"`
		}

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("Decode of Label failed: %+v", err)
		}

		if aux.Key == "" {
			return fmt.Errorf("Invalid Label: must provide a label key")
		}

		l.Source = aux.Source
		l.Key = aux.Key
		l.Value = aux.Value
	} else {
		// FIXME: [source:]key[=value]

		// This is a short form in which only a string to be interpreted
		// as a cilium label key is provided
		var aux string

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("Decode of Label as string failed: %+v", err)
		}

		if aux == "" {
			return fmt.Errorf("Invalid Label: must provide a label key")
		}

		l.Source = "cilium"
		l.Key = aux
		l.Value = ""
	}

	return nil
}

type Labels map[string]string

type LabelsResponse struct {
	ID int `json:"id"`
}

func (lbls Labels) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	enc := json.NewEncoder(sha)
	sortedMap := lbls.sortMap()
	if err := enc.Encode(sortedMap); err != nil {
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
		str := fmt.Sprintf(`%s=%s`, k, lbls[k])
		sortedMap = append(sortedMap, str)
	}
	return sortedMap
}
