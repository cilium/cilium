// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
func (c *Client) DeletePrefilter(spec *models.PrefilterSpec) (*models.Prefilter, error) {
	params := prefilter.NewDeletePrefilterParams().WithPrefilterSpec(spec).WithTimeout(api.ClientTimeout)
	resp, err := c.Prefilter.DeletePrefilter(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
