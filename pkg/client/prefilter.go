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
)

// GetPrefilter returns a list of all CIDR prefixes
func (c *Client) GetPrefilter() (*models.CIDRList, error) {
	resp, err := c.Prefilter.GetPrefilter(nil)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// PutPrefilter adds a list of CIDR prefixes
func (c *Client) PutPrefilter(cl *models.CIDRList) error {
	params := prefilter.NewPutPrefilterParams().WithCidrList(cl)
	_, err := c.Prefilter.PutPrefilter(params)
	return Hint(err)
}

// DeletePrefilter deletes a list of CIDR prefixes
func (c *Client) DeletePrefilter(cl *models.CIDRList) error {
	params := prefilter.NewDeletePrefilterParams().WithCidrList(cl)
	_, err := c.Prefilter.DeletePrefilter(params)
	return Hint(err)
}
