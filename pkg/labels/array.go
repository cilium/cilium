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

// LabelArray is an array of labels forming a set
type LabelArray []*Label

// ParseLabelArray parses a list of labels and returns a LabelArray
func ParseLabelArray(labels ...string) LabelArray {
	array := make([]*Label, len(labels))
	for i := range labels {
		array[i] = ParseLabel(labels[i])
	}
	return array
}

// ParseSelectLabelArray parses a list of select labels and returns a LabelArray
func ParseSelectLabelArray(labels ...string) LabelArray {
	array := make([]*Label, len(labels))
	for i := range labels {
		array[i] = ParseSelectLabel(labels[i])
	}
	return array
}

// ParseLabelArrayFromArray converts an array of strings as labels and returns a LabelArray
func ParseLabelArrayFromArray(base []string) LabelArray {
	array := make([]*Label, len(base))
	for i := range base {
		array[i] = ParseLabel(base[i])
	}
	return array
}

// ParseSelectLabelArrayFromArray converts an array of strings as select labels and returns a LabelArray
func ParseSelectLabelArrayFromArray(base []string) LabelArray {
	array := make([]*Label, len(base))
	for i := range base {
		array[i] = ParseSelectLabel(base[i])
	}
	return array
}

// Contains returns true if all ls contains all the labels in needed. If
// needed contains no labels, Contains() will always return true
func (ls LabelArray) Contains(needed LabelArray) bool {
nextLabel:
	for _, neededLabel := range needed {
		for _, l := range ls {
			if neededLabel.Matches(l) {
				continue nextLabel
			}
		}

		return false
	}

	return true
}

// Lacks is identical to Contains but returns all missing labels
func (ls LabelArray) Lacks(needed LabelArray) LabelArray {
	missing := LabelArray{}
nextLabel:
	for _, neededLabel := range needed {
		for _, l := range ls {
			if neededLabel.Matches(l) {
				continue nextLabel
			}
		}

		missing = append(missing, neededLabel)
	}

	return missing
}

// Has returns whether the provided key exists.
// Implementation of the k8s.io/apimachinery/pkg/labels.Labels interface.
func (ls LabelArray) Has(key string) bool {
	// The key is submitted in the form of `source.key=value`
	keyLabel := parseSelectLabel(key, '.')
	if keyLabel.IsAnySource() {
		for _, lsl := range ls {
			if lsl.Key == keyLabel.Key {
				return true
			}
		}
	} else {
		for _, lsl := range ls {
			// Note that if '=value' is part of 'key' it is ignored here
			if lsl.Source == keyLabel.Source && lsl.Key == keyLabel.Key {
				return true
			}
		}
	}
	return false
}

// Get returns the value for the provided key.
// Implementation of the k8s.io/apimachinery/pkg/labels.Labels interface.
func (ls LabelArray) Get(key string) string {
	keyLabel := parseSelectLabel(key, '.')
	if keyLabel.IsAnySource() {
		for _, lsl := range ls {
			if lsl.Key == keyLabel.Key {
				return lsl.Value
			}
		}
	} else {
		for _, lsl := range ls {
			if lsl.Source == keyLabel.Source && lsl.Key == keyLabel.Key {
				return lsl.Value
			}
		}
	}
	return ""
}

// DeepCopy returns a deep copy of the labels.
func (ls LabelArray) DeepCopy() LabelArray {
	if ls == nil {
		return nil
	}

	o := make(LabelArray, 0, len(ls))
	for _, v := range ls {
		o = append(o, v.DeepCopy())
	}
	return o
}

// GetModel returns the LabelArray as a string array with fully-qualified labels.
// The output is parseable by ParseLabelArrayFromArray
func (ls LabelArray) GetModel() []string {
	res := []string{}
	for _, v := range ls {
		if v == nil {
			res = append(res, "")
		} else {
			res = append(res, v.String())
		}
	}
	return res
}
