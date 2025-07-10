// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/models"
)

// GetServices returns a list of all services.
func (c *Client) GetServices() ([]*models.Service, error) {
	resp, err := c.Service.GetService(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
