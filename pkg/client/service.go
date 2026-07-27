// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/service"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// GetServices returns a list of all services.
func (c *Client) GetServices() ([]*models.Service, error) {
	resp, err := c.Service.GetService(service.NewGetServiceParams().WithTimeout(api.ClientTimeout))
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
