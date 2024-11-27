// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"fmt"
	"iter"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// OpLabels represents the possible types.
type OpLabels struct {
	// Active labels that are enabled and disabled but not deleted
	Custom Labels

	// Labels derived from orchestration system
	OrchestrationIdentity Labels

	// orchestrationIdentity labels which have been disabled
	Disabled Labels

	// orchestrationInfo - labels from orchestration which are not used in determining a security identity
	OrchestrationInfo Labels
}

// NewOpLabels creates new initialized OpLabels
func NewOpLabels() OpLabels {
	return OpLabels{
		Custom:                Empty,
		Disabled:              Empty,
		OrchestrationIdentity: Empty,
		OrchestrationInfo:     Empty,
	}
}

func (o *OpLabels) DeepEqual(other *OpLabels) bool {
	return o.Custom.Equal(other.Custom) &&
		o.Disabled.Equal(other.Disabled) &&
		o.OrchestrationIdentity.Equal(other.OrchestrationIdentity) &&
		o.OrchestrationInfo.Equal(other.OrchestrationInfo)
}

// SplitUserLabelChanges returns labels to 'add' and 'del'ete to make
// the custom labels match 'lbls'
func (o *OpLabels) SplitUserLabelChanges(lbls Labels) (add, del Labels) {
	var addSlice, delSlice []Label
	for lbl := range lbls.All() {
		if _, found := o.Custom.GetLabel(lbl.Key()); !found {
			addSlice = append(addSlice, lbl)
		}
	}
	for lbl := range o.Custom.All() {
		if _, found := lbls.GetLabel(lbl.Key()); !found {
			delSlice = append(delSlice, lbl)
		}
	}
	return NewLabels(addSlice...), NewLabels(delSlice...)
}

// IdentityLabels returns map of labels that are used when determining a
// security identity.
func (o *OpLabels) IdentityLabels() Labels {
	return Merge(o.Custom, o.OrchestrationIdentity)
}

// GetIdentityLabel returns the value of the given Key from all IdentityLabels.
func (o *OpLabels) GetIdentityLabel(key string) (l Label, found bool) {
	l, found = o.OrchestrationIdentity.GetLabel(key)
	if !found {
		l, found = o.Custom.GetLabel(key)
	}
	return l, found
}

// AllLabels returns an iterator for all labels
func (o *OpLabels) AllLabels() iter.Seq[Label] {
	return func(yield func(Label) bool) {
		for l := range o.Custom.All() {
			if !yield(l) {
				return
			}
		}
		for l := range o.Disabled.All() {
			if !yield(l) {
				return
			}
		}
		for l := range o.OrchestrationIdentity.All() {
			if !yield(l) {
				return
			}
		}
		for l := range o.OrchestrationInfo.All() {
			if !yield(l) {
				return
			}
		}
	}
}

func (o *OpLabels) ReplaceInformationLabels(sourceFilter string, l Labels, logger *logrus.Entry) bool {
	changed := false
	labelSlice := make([]Label, 0, o.OrchestrationInfo.Len())
	for new := range l.All() {
		replace := true
		old, exists := o.OrchestrationInfo.GetLabel(new.Key())
		if exists {
			switch {
			case sourceFilter != LabelSourceAny && old.Source() != sourceFilter:
				replace = false
			case old == new:
				replace = false
			}
		}
		if replace {
			changed = true
			logger.WithField(logfields.Object, logfields.Repr(new)).Debug("Assigning information label")
			labelSlice = append(labelSlice, new)
		} else {
			labelSlice = append(labelSlice, old)
		}
	}
	o.OrchestrationInfo = NewLabels(labelSlice...)

	return changed
}

func (o *OpLabels) ReplaceIdentityLabels(sourceFilter string, l Labels, logger *logrus.Entry) bool {
	changed := false

	idLabels := make([]Label, 0, max(l.Len(), o.OrchestrationIdentity.Len()))
	disabledLabels := make([]Label, 0, o.Disabled.Len())

	for new := range l.All() {
		// A disabled identity label stays disabled without value updates
		if lbl, found := o.Disabled.GetLabel(new.Key()); found {
			disabledLabels = append(disabledLabels, lbl)
			continue
		}
		replace := true
		old, exists := o.OrchestrationIdentity.GetLabel(new.Key())
		if exists {
			switch {
			case sourceFilter != LabelSourceAny && old.Source() != sourceFilter:
				replace = false
			case old == new:
				replace = false
			}
		}
		if replace {
			changed = true
			logger.WithField(logfields.Object, logfields.Repr(new)).Debug("Assigning security relevant label")
			idLabels = append(idLabels, new)
		} else {
			idLabels = append(idLabels, old)
		}
	}

	o.OrchestrationIdentity = NewLabels(idLabels...)
	changed = changed || len(disabledLabels) != o.Disabled.Len()
	o.Disabled = NewLabels(disabledLabels...)

	return changed
}

func (o *OpLabels) ModifyIdentityLabels(addLabels, delLabels Labels) (changed bool, err error) {
	for lbl := range delLabels.All() {
		k := lbl.Key()
		// The change request is accepted if the label is on
		// any of the lists. If the label is already disabled,
		// we will simply ignore that change.
		if _, found := o.Custom.GetLabel(k); !found {
			if _, found := o.OrchestrationIdentity.GetLabel(k); !found {
				if _, found := o.Disabled.GetLabel(k); !found {
					return false, fmt.Errorf("label %s not found", k)
				}
			}
		}
	}

	// Will not fail after this point
	for lbl := range delLabels.All() {
		k := lbl.Key()
		if v, found := o.OrchestrationIdentity.GetLabel(k); found {
			o.OrchestrationIdentity = o.OrchestrationIdentity.RemoveKeys(k)
			o.Disabled = o.Disabled.Add(v)
			changed = true
		}

		if _, found := o.Custom.GetLabel(k); found {
			o.Custom = o.Custom.RemoveKeys(k)
			changed = true
		}
	}

	for lbl := range addLabels.All() {
		k := lbl.Key()
		if _, found := o.Disabled.GetLabel(k); found { // Restore label.
			o.Disabled = o.Disabled.RemoveKeys(k)
			o.OrchestrationIdentity = o.OrchestrationIdentity.Add(lbl)
			changed = true
		} else if _, found := o.OrchestrationIdentity.GetLabel(k); found { // Replace label's source and value.
			o.OrchestrationIdentity = o.OrchestrationIdentity.Add(lbl)
			changed = true
		} else {
			o.Custom = o.Custom.Add(lbl)
			changed = true
		}
	}
	return changed, nil
}

/*
// upsertLabel updates or inserts 'label' in 'l', but only if exactly the same label
// was not already in 'l'. Returns 'true' if a label was added, or an old label was
// updated, 'false' otherwise.
// The label is only updated if its source matches the provided 'sourceFilter'
// or in case the provided sourceFilter is 'LabelSourceAny'. The new label must
// also match the old label 'source' in order for it to be replaced.
func (l Labels) upsertLabel(sourceFilter string, label Label) bool {
	oldLabel, found := l[label.Key()]
	if found {
		if sourceFilter != LabelSourceAny && sourceFilter != oldLabel.Source() {
			return false
		}

		// Key is the same, check if Value and Source are also the same
		if label.Value() == oldLabel.Value() && label.Source() == oldLabel.Source() {
			return false // No change
		}

		// If the label is not from the same source, then don't replace it.
		if oldLabel.Source() != label.Source() {
			return false
		}
	}

	// Insert or replace old label
	l[label.Key()] = label
	return true
}

// deleteUnMarked deletes the labels which have not been marked for keeping.
// The labels are only deleted if their source matches the provided sourceFilter
// or in case the provided sourceFilter is 'LabelSourceAny'.
// Returns true if any of them were deleted.
func (l Labels) deleteUnMarked(sourceFilter string, marks keepMarks) bool {
	deleted := false
	for k, v := range l {
		if _, keep := marks[k]; !keep && (sourceFilter == LabelSourceAny || sourceFilter == v.Source()) {
			delete(l, k)
			deleted = true
		}
	}

	return deleted
}
*/
