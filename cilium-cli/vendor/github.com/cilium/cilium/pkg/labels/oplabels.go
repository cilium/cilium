// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type keepMarks map[string]struct{}

// set marks the label with 'key' to not be deleted.
func (k keepMarks) set(key string) {
	k[key] = struct{}{} // marked for keeping
}

// OpLabels represents the the possible types.
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
		Custom:                Labels{},
		Disabled:              Labels{},
		OrchestrationIdentity: Labels{},
		OrchestrationInfo:     Labels{},
	}
}

// SplitUserLabelChanges returns labels to 'add' and 'del'ete to make
// the custom labels match 'lbls'
// FIXME: Somewhere in the code we crash if the returned maps are non-nil
// but length 0. We retain this behaviour here because it's easier.
func (o *OpLabels) SplitUserLabelChanges(lbls Labels) (add, del Labels) {
	for key, lbl := range lbls {
		if _, found := o.Custom[key]; !found {
			if add == nil {
				add = Labels{}
			}
			add[key] = lbl
		}
	}

	for key, lbl := range o.Custom {
		if _, found := lbls[key]; !found {
			if del == nil {
				del = Labels{}
			}
			del[key] = lbl
		}
	}

	return add, del
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

// GetIdentityLabel returns the value of the given Key from all IdentityLabels.
func (o *OpLabels) GetIdentityLabel(key string) (l Label, found bool) {
	l, found = o.OrchestrationIdentity[key]
	if !found {
		l, found = o.Custom[key]
	}
	return l, found
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

func (o *OpLabels) ReplaceInformationLabels(l Labels, logger *logrus.Entry) bool {
	changed := false
	keepers := make(keepMarks)
	for _, v := range l {
		keepers.set(v.Key)
		if o.OrchestrationInfo.upsertLabel(v) {
			changed = true
			logger.WithField(logfields.Object, logfields.Repr(v)).Debug("Assigning information label")
		}
	}
	o.OrchestrationInfo.deleteUnMarked(keepers)

	return changed
}

func (o *OpLabels) ReplaceIdentityLabels(l Labels, logger *logrus.Entry) bool {
	changed := false

	keepers := make(keepMarks)
	disabledKeepers := make(keepMarks)

	for k, v := range l {
		// A disabled identity label stays disabled without value updates
		if _, found := o.Disabled[k]; found {
			disabledKeepers.set(k)
		} else if keepers.set(v.Key); o.OrchestrationIdentity.upsertLabel(v) {
			logger.WithField(logfields.Object, logfields.Repr(v)).Debug("Assigning security relevant label")
			changed = true
		}
	}

	if o.OrchestrationIdentity.deleteUnMarked(keepers) || o.Disabled.deleteUnMarked(disabledKeepers) {
		changed = true
	}

	return changed
}

func (o *OpLabels) ModifyIdentityLabels(addLabels, delLabels Labels) (changed bool, err error) {
	for k := range delLabels {
		// The change request is accepted if the label is on
		// any of the lists. If the label is already disabled,
		// we will simply ignore that change.
		if _, found := o.Custom[k]; !found {
			if _, found := o.OrchestrationIdentity[k]; !found {
				if _, found := o.Disabled[k]; !found {
					return false, fmt.Errorf("label %s not found", k)
				}
			}
		}
	}

	// Will not fail after this point
	for k := range delLabels {
		if v, found := o.OrchestrationIdentity[k]; found {
			delete(o.OrchestrationIdentity, k)
			o.Disabled[k] = v
			changed = true
		}

		if _, found := o.Custom[k]; found {
			delete(o.Custom, k)
			changed = true
		}
	}

	for k, v := range addLabels {
		if _, found := o.Disabled[k]; found { // Restore label.
			delete(o.Disabled, k)
			o.OrchestrationIdentity[k] = v
			changed = true
		} else if _, found := o.OrchestrationIdentity[k]; found { // Replace label's source and value.
			o.OrchestrationIdentity[k] = v
			changed = true
		} else {
			o.Custom[k] = v
			changed = true
		}
	}
	return changed, nil
}

// upsertLabel updates or inserts 'label' in 'l', but only if exactly the same label
// was not already in 'l'. Returns 'true' if a label was added, or an old label was
// updated, 'false' otherwise.
func (l Labels) upsertLabel(label Label) bool {
	oldLabel, found := l[label.Key]
	if found {
		// Key is the same, check if Value and Source are also the same
		if label.Value == oldLabel.Value && label.Source == oldLabel.Source {
			return false // No change
		}
	}
	// Insert or replace old label
	l[label.Key] = label
	return true
}

// deleteUnMarked deletes the labels which have not been marked for keeping.
// Returns true if any of them were deleted.
func (l Labels) deleteUnMarked(marks keepMarks) bool {
	deleted := false
	for k := range l {
		if _, keep := marks[k]; !keep {
			delete(l, k)
			deleted = true
		}
	}

	return deleted
}
