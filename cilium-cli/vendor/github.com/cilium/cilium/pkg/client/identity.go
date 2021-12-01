// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// IdentityGet returns a security identity.
func (c *Client) IdentityGet(id string) (*models.Identity, error) {
	params := policy.NewGetIdentityIDParams().WithID(id).WithTimeout(api.ClientTimeout)

	resp, err := c.Policy.GetIdentityID(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
