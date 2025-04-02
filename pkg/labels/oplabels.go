// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type keepMarks map[string]struct{}

// set marks the label with 'key' to not be deleted.
func (k keepMarks) set(key string) {
	k[key] = struct{}{} // marked for keeping
}

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

func (o *OpLabels) DeepEqual(other *OpLabels) bool {
	return o.Custom.Equal(other.Custom) &&
		o.OrchestrationIdentity.Equal(other.OrchestrationIdentity) &&
		o.Disabled.Equal(other.Disabled) &&
		o.OrchestrationInfo.Equal(other.OrchestrationInfo)
}

// NewOpLabels creates new initialized OpLabels
func NewOpLabels() OpLabels {
	return OpLabels{
		Custom:                Labels{},
		Disabled:              Labels{},
		OrchestrationIdentity: Labels{},
		OrchestrationInfo:     Labels{},
	}
}

// SplitUserLabelChanges returns labels to 'add' and 'del'ete to make
// the custom labels match 'lbls'
func (o *OpLabels) SplitUserLabelChanges(lbls Labels) (add, del Labels) {
	for lbl := range lbls.All() {
		if !o.Custom.Has(lbl.Key()) {
			add = add.Add(lbl)
		}
	}

	for lbl := range o.Custom.All() {
		if !lbls.Has(lbl.Key()) {
			del = del.Add(lbl)
		}
	}

	return add, del
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

// AllLabels returns all Labels within the provided OpLabels.
func (o *OpLabels) AllLabels() Labels {
	all := make([]Label, 0, o.Custom.Len()+o.OrchestrationInfo.Len()+o.OrchestrationIdentity.Len()+o.Disabled.Len())
	all = slices.AppendSeq(all, o.Custom.All())
	all = slices.AppendSeq(all, o.Disabled.All())
	all = slices.AppendSeq(all, o.OrchestrationIdentity.All())
	all = slices.AppendSeq(all, o.OrchestrationInfo.All())
	return NewLabels(all...)
}

func (o *OpLabels) ReplaceInformationLabels(sourceFilter string, l Labels, logger *logrus.Entry) bool {
	changed := false
	keepers := make(keepMarks)
	for v := range l.All() {
		keepers.set(v.Key())
		if upsertLabel(&o.OrchestrationInfo, sourceFilter, v) {
			changed = true
			logger.WithField(logfields.Object, logfields.Repr(v)).Debug("Assigning information label")
		}
	}
	deleteUnMarked(&o.OrchestrationInfo, sourceFilter, keepers)

	return changed
}

func (o *OpLabels) ReplaceIdentityLabels(sourceFilter string, l Labels, logger *logrus.Entry) bool {
	changed := false

	keepers := make(keepMarks)
	disabledKeepers := make(keepMarks)

	for lbl := range l.All() {
		// A disabled identity label stays disabled without value updates
		if o.Disabled.Has(lbl.Key()) {
			disabledKeepers.set(lbl.Key())
		} else if keepers.set(lbl.Key()); upsertLabel(&o.OrchestrationIdentity, sourceFilter, lbl) {
			logger.WithField(logfields.Object, logfields.Repr(lbl)).Debug("Assigning security relevant label")
			changed = true
		}
	}

	if deleteUnMarked(&o.OrchestrationIdentity, sourceFilter, keepers) || deleteUnMarked(&o.Disabled, sourceFilter, disabledKeepers) {
		changed = true
	}

	return changed
}

func (o *OpLabels) ModifyIdentityLabels(addLabels, delLabels Labels) (changed bool, err error) {
	for lbl := range delLabels.All() {
		// The change request is accepted if the label is on
		// any of the lists. If the label is already disabled,
		// we will simply ignore that change.
		if !o.Custom.Has(lbl.Key()) {
			if !o.OrchestrationIdentity.Has(lbl.Key()) {
				if !o.Disabled.Has(lbl.Key()) {
					return false, fmt.Errorf("label %s not found", lbl.Key())
				}
			}
		}
	}

	// Will not fail after this point
	for lbl := range delLabels.All() {
		if v, found := o.OrchestrationIdentity.GetLabel(lbl.Key()); found {
			o.OrchestrationIdentity = o.OrchestrationIdentity.RemoveKeys(lbl.Key())
			o.Disabled = o.Disabled.Add(v)
			changed = true
		}

		if !o.Custom.Has(lbl.Key()) {
			o.Custom = o.Custom.RemoveKeys(lbl.Key())
			changed = true
		}
	}

	for lbl := range addLabels.All() {
		if o.Disabled.Has(lbl.Key()) {
			o.Disabled = o.Disabled.RemoveKeys(lbl.Key())
			o.OrchestrationIdentity = o.OrchestrationIdentity.Add(lbl)
			changed = true
		} else if o.OrchestrationIdentity.Has(lbl.Key()) { // Replace label's source and value.
			o.OrchestrationIdentity = o.OrchestrationIdentity.Add(lbl)
			changed = true
		} else {
			o.Custom = o.Custom.Add(lbl)
			changed = true
		}
	}
	return changed, nil
}

// upsertLabel updates or inserts 'label' in 'l', but only if exactly the same label
// was not already in 'l'. Returns 'true' if a label was added, or an old label was
// updated, 'false' otherwise.
// The label is only updated if its source matches the provided 'sourceFilter'
// or in case the provided sourceFilter is 'LabelSourceAny'. The new label must
// also match the old label 'source' in order for it to be replaced.
func upsertLabel(l *Labels, sourceFilter string, label Label) bool {
	oldLabel, found := l.GetLabel(label.Key())
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
	*l = l.Add(label)
	return true
}

// deleteUnMarked deletes the labels which have not been marked for keeping.
// The labels are only deleted if their source matches the provided sourceFilter
// or in case the provided sourceFilter is 'LabelSourceAny'.
// Returns true if any of them were deleted.
func deleteUnMarked(l *Labels, sourceFilter string, marks keepMarks) bool {
	deleted := false
	for v := range l.All() {
		if _, keep := marks[v.Key()]; !keep && (sourceFilter == LabelSourceAny || sourceFilter == v.Source()) {
			*l = l.Remove(v)
			deleted = true
		}
	}

	return deleted
}
