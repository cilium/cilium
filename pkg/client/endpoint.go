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
	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	pkgEndpoint "github.com/cilium/cilium/pkg/endpoint"
)

// EndpointList returns list of endpoints
func (c *Client) EndpointList() ([]*models.Endpoint, error) {
	resp, err := c.Endpoint.GetEndpoint(nil)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// EndpointGet returns endpoint by ID
func (c *Client) EndpointGet(id string) (*models.Endpoint, error) {
	params := endpoint.NewGetEndpointIDParams().WithID(id)
	resp, err := c.Endpoint.GetEndpointID(params)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// EndpointCreate creates a new endpoint
func (c *Client) EndpointCreate(ep *models.EndpointChangeRequest) error {
	id := pkgEndpoint.NewCiliumID(ep.ID)
	params := endpoint.NewPutEndpointIDParams().WithID(id).WithEndpoint(ep)
	_, err := c.Endpoint.PutEndpointID(params)
	return err
}

// EndpointPatch modifies the endpoint
func (c *Client) EndpointPatch(id string, ep *models.EndpointChangeRequest) error {
	params := endpoint.NewPatchEndpointIDParams().WithID(id).WithEndpoint(ep)
	_, err := c.Endpoint.PatchEndpointID(params)
	return err
}

// EndpointDelete deletes endpoint
func (c *Client) EndpointDelete(id string) error {
	params := endpoint.NewDeleteEndpointIDParams().WithID(id)
	_, _, err := c.Endpoint.DeleteEndpointID(params)
	return err
}

// EndpointConfigGet returns endpoint configuration
func (c *Client) EndpointConfigGet(id string) (*models.Configuration, error) {
	params := endpoint.NewGetEndpointIDConfigParams().WithID(id)
	resp, err := c.Endpoint.GetEndpointIDConfig(params)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// EndpointConfigPatch modifies endpoint configuration
func (c *Client) EndpointConfigPatch(id string, cfg models.ConfigurationMap) error {
	params := endpoint.NewPatchEndpointIDConfigParams().WithID(id)
	if cfg != nil {
		params.SetConfiguration(cfg)
	}

	_, err := c.Endpoint.PatchEndpointIDConfig(params)
	return err
}

// EndpointLabelsGet returns endpoint label configuration
func (c *Client) EndpointLabelsGet(id string) (*models.LabelConfiguration, error) {
	params := endpoint.NewGetEndpointIDLabelsParams().WithID(id)
	resp, err := c.Endpoint.GetEndpointIDLabels(params)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// EndpointLabelsPut modifies endpoint label configuration
func (c *Client) EndpointLabelsPut(id string, cfg *models.LabelConfigurationModifier) error {
	params := endpoint.NewPutEndpointIDLabelsParams().WithID(id)
	_, err := c.Endpoint.PutEndpointIDLabels(params.WithConfiguration(cfg))
	return err
}
