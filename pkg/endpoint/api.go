// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"github.com/cilium/cilium/api/v1/models"
)

// GetLabelsModel returns the labels of the endpoint in their representation
// for the Cilium API. Returns an error if the Endpoint is being deleted.
func (e *Endpoint) GetLabelsModel() (*models.LabelConfiguration, error) {
	if err := e.RLockAlive(); err != nil {
		return nil, err
	}
	spec := &models.LabelConfigurationSpec{
		User: e.OpLabels.Custom.GetModel(),
	}

	cfg := models.LabelConfiguration{
		Spec: spec,
		Status: &models.LabelConfigurationStatus{
			Realized:         spec,
			SecurityRelevant: e.OpLabels.OrchestrationIdentity.GetModel(),
			Derived:          e.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:         e.OpLabels.Disabled.GetModel(),
		},
	}
	e.RUnlock()
	return &cfg, nil
}
