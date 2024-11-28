// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	return &identity.Identity{
		ID:     identity.NumericIdentity(base.ID),
		Labels: labels.ParseLabels(base.Labels...),
	}
}

func CreateModel(id *identity.Identity) *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:     int64(id.ID),
		Labels: make([]string, 0, id.Labels.Len()),
	}

	for v := range id.Labels.All() {
		ret.Labels = append(ret.Labels, v.String())
	}
	return ret
}
