// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/service"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// GetLRPs returns a list of all local redirect policies.
func (c *Client) GetLRPs() ([]*models.LRPSpec, error) {
	resp, err := c.Service.GetLrp(service.NewGetLrpParams().WithTimeout(api.ClientTimeout))
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
