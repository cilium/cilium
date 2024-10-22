// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// NewOplabelsFromModel creates new label from the model.
func NewOplabelsFromModel(base *models.LabelConfigurationStatus) *labels.OpLabels {
	if base == nil {
		return nil
	}

	return &labels.OpLabels{
		Custom:                labels.NewLabelsFromModel(base.Realized.User),
		Disabled:              labels.NewLabelsFromModel(base.Disabled),
		OrchestrationIdentity: labels.NewLabelsFromModel(base.SecurityRelevant),
		OrchestrationInfo:     labels.NewLabelsFromModel(base.Derived),
	}
}

func NewModel(o *labels.OpLabels) *models.LabelConfigurationStatus {
	return &models.LabelConfigurationStatus{
		Realized: &models.LabelConfigurationSpec{
			User: o.Custom.GetModel(),
		},
		SecurityRelevant: o.OrchestrationIdentity.GetModel(),
		Derived:          o.OrchestrationInfo.GetModel(),
		Disabled:         o.Disabled.GetModel(),
	}
}
