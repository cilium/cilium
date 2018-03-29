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

package v2

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

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*metav1.LabelSelector
}

// LabelSelectorString returns a user-friendly string representation of
// EndpointSelector.
func (n *EndpointSelector) LabelSelectorString() string {
	return metav1.FormatLabelSelector(n.LabelSelector)
}

// String returns a string representation of EndpointSelector.
func (n EndpointSelector) String() string {
	j, _ := n.MarshalJSON()
	return string(j)
}

// Hash return hash of the internal json structure that represents the endpoint selector
func (n *EndpointSelector) Hash() (uint64, error) {
	return hashstructure.Hash(n.LabelSelector, nil)
}

// UnmarshalJSON unmarshals the endpoint selector from the byte array.
func (n *EndpointSelector) UnmarshalJSON(b []byte) error {
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
func (n EndpointSelector) MarshalJSON() ([]byte, error) {
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

// HasKeyPrefix checks if the endpoint selector contains the given key prefix in
// its MatchLabels map and MatchExpressions slice.
func (n EndpointSelector) HasKeyPrefix(prefix string) bool {
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

// HasKey checks if the endpoint selector contains the given key in
// its MatchLabels map or in its MatchExpressions slice.
func (n EndpointSelector) HasKey(key string) bool {
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

// NewWildcardEndpointSelector returns a selector that matches on all endpoints
func NewWildcardEndpointSelector() EndpointSelector {
	return EndpointSelector{&metav1.LabelSelector{MatchLabels: map[string]string{}}}
}

// NewESFromLabels creates a new endpoint selector from the given labels.
func NewESFromLabels(lbls ...*labels.Label) EndpointSelector {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}
	return EndpointSelector{
		&metav1.LabelSelector{
			MatchLabels: ml,
		},
	}
}

// NewESFromK8sLabelSelector returns a new endpoint selector from the label
// where it the given srcPrefix will be encoded in the label's keys.
func NewESFromK8sLabelSelector(srcPrefix string, ls *metav1.LabelSelector) EndpointSelector {
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
	return EndpointSelector{newLs}
}

// Matches returns true if the endpoint selector Matches the `lblsToMatch`.
// Returns always true if the endpoint selector contains the reserved label for
// "all".
func (n *EndpointSelector) Matches(lblsToMatch k8sLbls.Labels) bool {
	lbSelector, err := metav1.LabelSelectorAsSelector(n.LabelSelector)
	if err != nil {
		// FIXME: Omit this error or throw it to the caller?
		// We are doing the verification in the ParseEndpointSelector but
		// don't make sure the user can modify the current labels.
		log.WithError(err).WithField(logfields.EndpointLabelSelector,
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

// IsWildcard returns true if the endpoint selector selects all endpoints.
func (n *EndpointSelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0
}

// EndpointSelectorSlice is a slice of EndpointSelectors that can be sorted.
type EndpointSelectorSlice []EndpointSelector

func (s EndpointSelectorSlice) Len() int      { return len(s) }
func (s EndpointSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s EndpointSelectorSlice) Less(i, j int) bool {
	strI := s[i].LabelSelectorString()
	strJ := s[j].LabelSelectorString()

	return strings.Compare(strI, strJ) < 0
}
