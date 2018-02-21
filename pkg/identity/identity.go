// Copyright 2018 Authors of Cilium
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

package identity

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`
	// SHA256 of labels.
	LabelsSHA256 string `json:"labelsSHA256"`
}

func NewIdentityFromModel(base *models.Identity) *Identity {
	if base == nil {
		return nil
	}

	id := &Identity{
		ID:     NumericIdentity(base.ID),
		Labels: make(labels.Labels),
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels[lbl.Key] = lbl
	}

	return id
}

// GetLabelsSHA256 returns the SHA256 of the labels associated with the
// identity. The SHA is calculated if not already cached.
func (id *Identity) GetLabelsSHA256() string {
	if id.LabelsSHA256 == "" {
		id.LabelsSHA256 = id.Labels.SHA256Sum()
	}

	return id.LabelsSHA256
}

// StringID returns the identity identifier as string
func (id *Identity) StringID() string {
	return id.ID.StringID()
}

func (id *Identity) GetModel() *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:           int64(id.ID),
		Labels:       []string{},
		LabelsSHA256: "",
	}

	for _, v := range id.Labels {
		ret.Labels = append(ret.Labels, v.String())
	}
	ret.LabelsSHA256 = id.GetLabelsSHA256()
	return ret
}

// NewIdentity creates a new identity
func NewIdentity(id NumericIdentity, lbls labels.Labels) *Identity {
	return &Identity{ID: id, Labels: lbls}
}
