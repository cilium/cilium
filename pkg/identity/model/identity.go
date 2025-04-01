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

	id := &identity.Identity{
		ID:     identity.NumericIdentity(base.ID),
		Labels: labels.Empty,
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels = id.Labels.Add(lbl)
	}
	id.Sanitize()

	return id
}

func CreateModel(id *identity.Identity) *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:     int64(id.ID),
		Labels: make([]string, 0, id.Labels.Len()),
	}

	for _, v := range id.LabelArray {
		ret.Labels = append(ret.Labels, v.String())
	}
	return ret
}
