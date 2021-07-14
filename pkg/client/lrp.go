// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/models"
)

// GetLRPs returns a list of all local redirect policies.
func (c *Client) GetLRPs() ([]*models.LRPSpec, error) {
	resp, err := c.Service.GetLrp(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
