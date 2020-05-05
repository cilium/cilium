// Copyright 2018-2019 Authors of Cilium
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

package model

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

func NewIdentityFromModel(base *models.Identity) *identity.Identity {
	if base == nil {
		return nil
	}

	id := &identity.Identity{
		ID:     identity.NumericIdentity(base.ID),
		Labels: make(labels.Labels),
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels[lbl.Key] = lbl
	}
	id.Sanitize()

	return id
}

func CreateModel(id *identity.Identity) *models.Identity {
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
