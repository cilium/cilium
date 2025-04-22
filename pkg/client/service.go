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
	resp, err := c.Service.GetService(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// GetServiceID returns a service by ID.
func (c *Client) GetServiceID(id int64) (*models.Service, error) {
	params := service.NewGetServiceIDParams().WithID(id).WithTimeout(api.ClientTimeout)
	resp, err := c.Service.GetServiceID(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
