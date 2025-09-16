// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"unique"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/labels"
)

const separator = "\x1f" // ascii information separator 1
type stringList string

// RuleMeta is the set of meta-information from the owning rules.
// To save memory, it is an interned type. Thus all the struct members
// are strings (but are really delimited lists)
type RuleMeta struct {
	labels labels.LabelArrayListString // from LabelArrayList.String()
	log    stringList
}

func (rm RuleMeta) LabelArray() labels.LabelArrayList {
	return labels.LabelArrayListFromString(rm.labels)
}

func (rm RuleMeta) LabelArrayListString() labels.LabelArrayListString {
	return rm.labels
}

func newStringList(items ...string) stringList {
	slices.Sort(items)
	return stringList(strings.Join(items, separator))
}

func (sl stringList) List() []string {
	return strings.Split(string(sl), separator)
}

func mergeStringList(a, b stringList) stringList {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}

	logLines := set.NewSet[string]()
	for _, line := range a.List() {
		logLines.Insert(line)
	}
	for _, line := range b.List() {
		logLines.Insert(line)
	}
	return newStringList(logLines.AsSlice()...)
}

// ruleOrigin is an interned labels.LabelArrayList.String(), a list of rule labels tracking which
// policy rules are the origin for this policy. This information is used when distilling a policy to
// an EndpointPolicy, to track which policy rules were involved for a specific verdict.
type ruleOrigin unique.Handle[RuleMeta]

func (ro ruleOrigin) Value() RuleMeta {
	return (unique.Handle[RuleMeta])(ro).Value()
}

func (ro ruleOrigin) LabelsString() labels.LabelArrayListString {
	return ro.Value().labels
}

func (ro ruleOrigin) LogString() string {
	out, _ := json.Marshal(ro.Value().log.List())
	return string(out)
}

func (ro ruleOrigin) GetLabelArrayList() labels.LabelArrayList {
	return labels.LabelArrayListFromString(ro.LabelsString())
}

func (ro ruleOrigin) stringLabels() stringLabels {
	return newStringLabels(ro.LabelsString())
}

func (rm RuleMeta) Log() []string {
	return rm.log.List()
}

func newRuleOrigin(rm RuleMeta) ruleOrigin {
	return ruleOrigin(unique.Make(rm))
}

func makeRuleOrigin(lbls labels.LabelArrayList, logs []string) ruleOrigin {
	return newRuleOrigin(RuleMeta{
		labels: lbls.ArrayListString(),
		log:    newStringList(logs...),
	})
}

func makeSingleRuleOrigin(lbls labels.LabelArray, log string) ruleOrigin {
	return makeRuleOrigin(labels.LabelArrayList{lbls}, []string{log})
}

// Merge combines two rule origins.
// Returns the merged value
func (ro ruleOrigin) Merge(other ruleOrigin) ruleOrigin {
	if ro == other {
		return ro
	}

	// do not merge zero values
	if ro.Value() == (RuleMeta{}) {
		return other
	}
	if other.Value() == (RuleMeta{}) {
		return ro
	}

	new := RuleMeta{
		labels: labels.MergeSortedLabelArrayListStrings(ro.LabelsString(), other.LabelsString()),
		log:    mergeStringList(ro.Value().log, other.Value().log),
	}

	return ruleOrigin(unique.Make(new))

}

var NilRuleOrigin = newRuleOrigin(RuleMeta{labels: "[]"})

// stringLabels is an interned labels.LabelArray.String()
type stringLabels unique.Handle[labels.LabelArrayListString]

var EmptyStringLabels = makeStringLabels(nil)

func (sl stringLabels) Value() labels.LabelArrayListString {
	return unique.Handle[labels.LabelArrayListString](sl).Value()
}

func makeStringLabels(lbls labels.LabelArray) stringLabels {
	return newStringLabels(labels.LabelArrayList{lbls.Sort()}.ArrayListString())
}

func newStringLabels(lbls labels.LabelArrayListString) stringLabels {
	return stringLabels(unique.Make(lbls))
}
