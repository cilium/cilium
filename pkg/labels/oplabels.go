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
	"fmt"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

// OpLabels represents the the possible types.
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type OpLabels struct {
	// Active labels that are enabled and disabled but not deleted
	custom Labels
	// Labels derived from orchestration system
	orchestrationIdentity markedLabels

	//orchestrationIdentity
	// orchestrationIdentity labels which have been disabled
	disabled markedLabels

	//orchestrationInfo - labels from orchestration which are not used in determining a security identity
	orchestrationInfo markedLabels
}

// NewOpLabels creates new initialized OpLabels
func NewOpLabels() OpLabels {
	return OpLabels{
		custom:                Labels{},
		disabled:              markedLabels{labels: Labels{}},
		orchestrationIdentity: markedLabels{labels: Labels{}},
		orchestrationInfo:     markedLabels{labels: Labels{}},
	}
}

// NewOplabelsFromModel creates new label from the model.
func NewOpLabelsFromModel(custom, disabled, identity, info []string) OpLabels {
	return OpLabels{
		custom:                NewLabelsFromModel(custom),
		disabled:              newMarkedLabelsFromModel(disabled),
		orchestrationIdentity: newMarkedLabelsFromModel(identity),
		orchestrationInfo:     newMarkedLabelsFromModel(info),
	}
}

func (o *OpLabels) GetUserModel() []string {
	return o.custom.GetModel()
}

func (o *OpLabels) GetIdentityModel() []string {
	return o.orchestrationIdentity.getModel()
}

func (o *OpLabels) GetInfoModel() []string {
	return o.orchestrationInfo.getModel()
}

func (o *OpLabels) GetDisabledModel() []string {
	return o.disabled.getModel()
}

func (o *OpLabels) OrchestrationIdentitySortedList() []byte {
	return o.orchestrationIdentity.labels.SortedList()
}

func (o *OpLabels) OrchestrationInfoSortedList() []byte {
	return o.orchestrationInfo.labels.SortedList()
}

func (o *OpLabels) DisabledLabels() Labels {
	return o.disabled.labels
}

func (o *OpLabels) IsReserved() bool {
	return o.orchestrationIdentity.findReserved() != nil
}

// SplitUserLabelChanges returns labels to 'add' and 'del'ete to make
// the custom labels match 'lbls'
// FIXME: Somewhere in the code we crash if the returned maps are non-nil
// but length 0. We retain this behaviour here because it's easier.
func (o *OpLabels) SplitUserLabelChanges(lbls Labels) (add, del Labels) {
	for key, lbl := range lbls {
		if o.custom[key] == nil {
			if add == nil {
				add = Labels{}
			}
			add[key] = lbl
		}
	}

	for key, lbl := range o.custom {
		if lbls[key] == nil {
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
	enabled := make(Labels, len(o.custom)+len(o.orchestrationIdentity.labels))

	for k, v := range o.custom {
		enabled[k] = v
	}

	for k, v := range o.orchestrationIdentity.labels {
		enabled[k] = v
	}

	return enabled
}

// GetIdentityLabel returns the value of the given Key from all IdentityLabels.
func (o *OpLabels) GetIdentityLabel(key string) *Label {
	l := o.orchestrationIdentity.labels[key]
	if l != nil {
		return l
	}
	return o.custom[key]
}

// AllLabels returns all Labels within the provided OpLabels.
func (o *OpLabels) AllLabels() Labels {
	all := make(Labels, len(o.custom)+len(o.orchestrationInfo.labels)+len(o.orchestrationIdentity.labels)+len(o.disabled.labels))

	for k, v := range o.custom {
		all[k] = v
	}

	for k, v := range o.disabled.labels {
		all[k] = v
	}

	for k, v := range o.orchestrationIdentity.labels {
		all[k] = v
	}

	for k, v := range o.orchestrationInfo.labels {
		all[k] = v
	}
	return all
}

func (o *OpLabels) ReplaceInformationLabels(l Labels, logger *logrus.Entry) bool {
	changed := false
	o.orchestrationInfo.markAllForDeletion()
	for _, v := range l {
		if o.orchestrationInfo.upsertLabel(v) {
			changed = true
			if logger != nil {
				logger.WithField(logfields.Labels, logfields.Repr(v)).Debug("Assigning information label")
			}
		}
	}
	o.orchestrationInfo.deleteUnMarked()

	return changed
}

func (o *OpLabels) ReplaceIdentityLabels(l Labels, logger *logrus.Entry) bool {
	changed := false

	o.orchestrationIdentity.markAllForDeletion()
	o.disabled.markAllForDeletion()

	for k, v := range l {
		// A disabled identity label stays disabled without value updates
		if o.disabled.labels[k] != nil {
			o.disabled.setKeeperMark(k)
		} else if o.orchestrationIdentity.upsertLabel(v) {
			if logger != nil {
				logger.WithField(logfields.Labels, logfields.Repr(v)).Debug("Assigning security relevant label")
			}
			changed = true
		}
	}

	if o.orchestrationIdentity.deleteUnMarked() || o.disabled.deleteUnMarked() {
		changed = true
	}

	return changed
}

func (o *OpLabels) ModifyIdentityLabels(addLabels, delLabels Labels) (changed bool, err error) {
	for k := range delLabels {
		// The change request is accepted if the label is on
		// any of the lists. If the label is already disabled,
		// we will simply ignore that change.
		if o.custom[k] == nil && o.orchestrationIdentity.labels[k] == nil && o.disabled.labels[k] == nil {
			return false, fmt.Errorf("label %s not found", k)
		}
	}

	// Will not fail after this point
	for k := range delLabels {
		if v := o.orchestrationIdentity.labels[k]; v != nil {
			delete(o.orchestrationIdentity.labels, k)
			o.disabled.labels[k] = v
			changed = true
		}

		if o.custom[k] != nil {
			delete(o.custom, k)
			changed = true
		}
	}

	for k, v := range addLabels {
		if o.disabled.labels[k] != nil { // Restore label.
			delete(o.disabled.labels, k)
			o.orchestrationIdentity.labels[k] = v
			changed = true
		} else if o.orchestrationIdentity.labels[k] != nil { // Replace label's source and value.
			o.orchestrationIdentity.labels[k] = v
			changed = true
		} else {
			o.custom[k] = v
			changed = true
		}
	}
	return changed, nil
}

// markedLabels is a map of labels that can be marked for deletion
// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false
type markedLabels struct {
	labels  Labels
	keepers map[string]struct{} // empty for everyting marked for deletion
}

func newMarkedLabelsFromModel(base []string) markedLabels {
	return markedLabels{labels: NewLabelsFromModel(base)}
}

// markAllForDeletion marks all the labels with the deletionMark.
func (l *markedLabels) markAllForDeletion() {
	l.keepers = nil
}

// setKeeperMark marks the label with 'key' to not be deleted.
func (l *markedLabels) setKeeperMark(key string) {
	if l.keepers == nil {
		l.keepers = make(map[string]struct{})
	}
	l.keepers[key] = struct{}{} // marked for keeping
}

// upsertLabel updates or inserts 'label' in 'l', but only if exactly the same label
// was not already in 'l'. If a label with the same key is found, the label's deletionMark
// is cleared. Returns 'true' if a label was added, or an old label was updated, 'false'
// otherwise.
func (l *markedLabels) upsertLabel(label *Label) bool {
	l.setKeeperMark(label.Key)
	oldLabel, found := l.labels[label.Key]
	if found {
		// Key is the same, check if Value and Source are also the same
		if label.Value == oldLabel.Value && label.Source == oldLabel.Source {
			return false // No change
		}
	}
	// Insert or replace old label
	l.labels[label.Key] = label
	return true
}

// deleteUnMarked deletes the labels which have not been marked for keeping.
// Returns true if any of them were deleted.
func (l *markedLabels) deleteUnMarked() bool {
	deleted := false
	for k := range l.labels {
		if _, keep := l.keepers[k]; !keep {
			delete(l.labels, k)
			deleted = true
		}
	}

	return deleted
}

// GetModel returns model with all the values of the labels.
func (l *markedLabels) getModel() []string {
	return l.labels.GetModel()
}

func (l *markedLabels) findReserved() Labels {
	return l.labels.FindReserved()
}
