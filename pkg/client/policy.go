// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// PolicyGet returns policy rules
// Deprecated, to be removed in v1.19
func (c *Client) PolicyGet() (*models.Policy, error) {
	params := policy.NewGetPolicyParams().WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.GetPolicy(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// PolicyCacheGet returns the contents of a SelectorCache.
func (c *Client) PolicyCacheGet() (models.SelectorCache, error) {
	params := policy.NewGetPolicySelectorsParams().WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.GetPolicySelectors(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// SubjectPolicySelectorsGet returns the contents of the subject SelectorCache.
func (c *Client) SubjectPolicySelectorsGet() (models.SelectorCache, error) {
	params := policy.NewGetPolicySubjectSelectorsParams().WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.GetPolicySubjectSelectors(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
