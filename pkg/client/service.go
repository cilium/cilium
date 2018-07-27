// Copyright 2016-2017 Authors of Cilium
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

// PutServiceID creates or updates a service. Returns true if service was created.
func (c *Client) PutServiceID(id int64, svc *models.ServiceSpec) (bool, error) {
	svc.ID = id
	params := service.NewPutServiceIDParams().WithID(id).WithConfig(svc).WithTimeout(api.ClientTimeout)
	_, created, err := c.Service.PutServiceID(params)
	return created != nil, Hint(err)
}

// DeleteServiceID deletes a service by ID.
func (c *Client) DeleteServiceID(id int64) error {
	params := service.NewDeleteServiceIDParams().WithID(id).WithTimeout(api.ClientTimeout)
	_, err := c.Service.DeleteServiceID(params)
	return Hint(err)
}
