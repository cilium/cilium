// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

package client

import (
	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// PolicyPut inserts the `policyJSON`
func (c *Client) PolicyPut(policyJSON string) (*models.Policy, error) {
	params := policy.NewPutPolicyParams().WithPolicy(policyJSON).WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.PutPolicy(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}

// PolicyGet returns policy rules
func (c *Client) PolicyGet(labels []string) (*models.Policy, error) {
	params := policy.NewGetPolicyParams().WithLabels(labels).WithTimeout(api.ClientTimeout)
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

// PolicyDelete deletes policy rules
func (c *Client) PolicyDelete(labels []string) (*models.Policy, error) {
	params := policy.NewDeletePolicyParams().WithLabels(labels).WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.DeletePolicy(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, Hint(err)
}

// PolicyResolveGet resolves policy for a Trace Selector with source and destination identity.
func (c *Client) PolicyResolveGet(traceSelector *models.TraceSelector) (*models.PolicyTraceResult, error) {
	params := policy.NewGetPolicyResolveParams().WithTraceSelector(traceSelector).WithTimeout(api.ClientTimeout)
	resp, err := c.Policy.GetPolicyResolve(params)
	if err != nil {
		return nil, Hint(err)
	}
	return resp.Payload, nil
}
