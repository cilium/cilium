// Copyright 2017 Authors of Cilium
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

package client

import (
	"github.com/cilium/cilium/api/v1/client/prefilter"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// GetPrefilter returns a list of all CIDR prefixes
func (c *Client) GetPrefilter() (*models.Prefilter, error) {
	resp, err := c.Prefilter.GetPrefilter(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// PatchPrefilter sets a list of CIDR prefixes
func (c *Client) PatchPrefilter(spec *models.PrefilterSpec) (*models.Prefilter, error) {
	params := prefilter.NewPatchPrefilterParams().WithPrefilterSpec(spec).WithTimeout(api.ClientTimeout)
	resp, err := c.Prefilter.PatchPrefilter(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// DeletePrefilter deletes a list of CIDR prefixes
func (c *Client) DeletePrefilter(spec *models.PrefilterSpec) error {
	current, err := c.GetPrefilter()
	if err != nil {
		return Hint(err)
	}

	deleteSet := map[string]bool{}
	keepList := []string{}
	for _, delCIDR := range spec.Deny {
		deleteSet[delCIDR] = true
	}

	if current.Status != nil && current.Status.Realized != nil {
		for _, keepCIDR := range current.Status.Realized.Deny {
			if !deleteSet[keepCIDR] {
				keepList = append(keepList, keepCIDR)
			}
		}
	}

	update := current.Status.Realized
	update.Deny = keepList
	_, err = c.PatchPrefilter(update)
	return Hint(err)
}
