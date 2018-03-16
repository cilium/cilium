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

package v3

import (
	"encoding/json"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/mitchellh/hashstructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLbls "k8s.io/apimachinery/pkg/labels"
)

var log = logging.DefaultLogger

// IdentitySelector is a wrapper for k8s LabelSelector.
type IdentitySelector struct {
	*metav1.LabelSelector
}

// LabelSelectorString returns a user-friendly string representation of
// IdentitySelector.
func (n *IdentitySelector) LabelSelectorString() string {
	return metav1.FormatLabelSelector(n.LabelSelector)
}

// String returns a string representation of IdentitySelector.
func (n IdentitySelector) String() string {
	j, _ := n.MarshalJSON()
	return string(j)
}

// Hash return hash of the internal json structure that represents the identity selector
func (n *IdentitySelector) Hash() (uint64, error) {
	return hashstructure.Hash(n.LabelSelector, nil)
}

// UnmarshalJSON unmarshals the identity selector from the byte array.
func (n *IdentitySelector) UnmarshalJSON(b []byte) error {
	n.LabelSelector = &metav1.LabelSelector{}
	err := json.Unmarshal(b, n.LabelSelector)
	if err != nil {
		return err
	}
	if n.MatchLabels != nil {
		ml := map[string]string{}
		for k, v := range n.MatchLabels {
			ml[labels.GetExtendedKeyFrom(k)] = v
		}
		n.MatchLabels = ml
	}
	if n.MatchExpressions != nil {
		newMatchExpr := make([]metav1.LabelSelectorRequirement, len(n.MatchExpressions))
		for i, v := range n.MatchExpressions {
			v.Key = labels.GetExtendedKeyFrom(v.Key)
			newMatchExpr[i] = v
		}
		n.MatchExpressions = newMatchExpr
	}
	return nil
}

// MarshalJSON returns a JSON representation of the byte array.
func (n IdentitySelector) MarshalJSON() ([]byte, error) {
	ls := metav1.LabelSelector{}

	if n.LabelSelector == nil {
		return json.Marshal(ls)
	}

	if n.MatchLabels != nil {
		newLabels := map[string]string{}
		for k, v := range n.MatchLabels {
			newLabels[labels.GetCiliumKeyFrom(k)] = v
		}
		ls.MatchLabels = newLabels
	}
	if n.MatchExpressions != nil {
		newMatchExpr := make([]metav1.LabelSelectorRequirement, len(n.MatchExpressions))
		for i, v := range n.MatchExpressions {
			v.Key = labels.GetCiliumKeyFrom(v.Key)
			newMatchExpr[i] = v
		}
		ls.MatchExpressions = newMatchExpr
	}
	return json.Marshal(ls)
}

// HasKeyPrefix checks if the identity selector contains the given key prefix in
// its MatchLabels map and MatchExpressions slice.
func (n IdentitySelector) HasKeyPrefix(prefix string) bool {
	for k := range n.MatchLabels {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for _, v := range n.MatchExpressions {
		if strings.HasPrefix(v.Key, prefix) {
			return true
		}
	}
	return false
}

// HasKey checks if the identity selector contains the given key in
// its MatchLabels map or in its MatchExpressions slice.
func (n IdentitySelector) HasKey(key string) bool {
	if _, ok := n.MatchLabels[key]; ok {
		return true
	}
	for _, v := range n.MatchExpressions {
		if v.Key == key {
			return true
		}
	}
	return false
}

// NewWildcardIdentitySelector returns a selector that matches on all identities
func NewWildcardIdentitySelector() IdentitySelector {
	return IdentitySelector{&metav1.LabelSelector{MatchLabels: map[string]string{}}}
}

// NewESFromLabels creates a new identity selector from the given labels.
func NewESFromLabels(lbls ...*labels.Label) IdentitySelector {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}
	return IdentitySelector{
		&metav1.LabelSelector{
			MatchLabels: ml,
		},
	}
}

// NewESFromK8sLabelSelector returns a new identity selector from the label
// where it the given srcPrefix will be encoded in the label's keys.
func NewESFromK8sLabelSelector(srcPrefix string, ls *metav1.LabelSelector) IdentitySelector {
	newLs := &metav1.LabelSelector{}
	if ls.MatchLabels != nil {
		newLabels := map[string]string{}
		for k, v := range ls.MatchLabels {
			newLabels[srcPrefix+k] = v
		}
		newLs.MatchLabels = newLabels
	}
	if ls.MatchExpressions != nil {
		newMatchExpr := make([]metav1.LabelSelectorRequirement, len(ls.MatchExpressions))
		for i, v := range ls.MatchExpressions {
			v.Key = srcPrefix + v.Key
			newMatchExpr[i] = v
		}
		newLs.MatchExpressions = newMatchExpr
	}
	return IdentitySelector{newLs}
}

// Matches returns true if the identity selector Matches the `lblsToMatch`.
// Returns always true if the identity selector contains the reserved label for
// "all".
func (n *IdentitySelector) Matches(lblsToMatch k8sLbls.Labels) bool {
	lbSelector, err := metav1.LabelSelectorAsSelector(n.LabelSelector)
	if err != nil {
		// FIXME: Omit this error or throw it to the caller?
		// We are doing the verification in the ParseIdentitySelector but
		// don't make sure the user can modify the current labels.
		log.WithError(err).WithField(logfields.IdentityLabelSelector,
			logfields.Repr(n)).Error("unable to match label selector in selector")
		return false
	}

	for k := range n.MatchLabels {
		if k == labels.LabelSourceReservedKeyPrefix+labels.IDNameAll {
			return true
		}
	}

	return lbSelector.Matches(lblsToMatch)
}

// IsWildcard returns true if the identity selector selects all identities.
func (n *IdentitySelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0
}

// IdentitySelectorSlice is a slice of IdentitySelectors that can be sorted.
type IdentitySelectorSlice []IdentitySelector

func (s IdentitySelectorSlice) Len() int      { return len(s) }
func (s IdentitySelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s IdentitySelectorSlice) Less(i, j int) bool {
	strI := s[i].LabelSelectorString()
	strJ := s[j].LabelSelectorString()

	return strings.Compare(strI, strJ) < 0
}
