// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
)

func TestCountEndpointsBelowPolicyRevision(t *testing.T) {
	identity := &models.Identity{ID: 12345}

	realized := func(rev int64) *models.EndpointStatus {
		return &models.EndpointStatus{
			Identity: identity,
			Policy: &models.EndpointPolicyStatus{
				Realized: &models.EndpointPolicy{PolicyRevision: rev},
			},
		}
	}

	tests := []struct {
		name string
		eps  []*models.Endpoint
		rev  int
		want int
	}{
		{
			name: "no endpoints",
			eps:  nil,
			rev:  10,
			want: 0,
		},
		{
			name: "identity-less endpoint is skipped",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{Identity: nil}},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "nil status is skipped",
			eps: []*models.Endpoint{
				{Status: nil},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "identity endpoint with stale realized revision is counted",
			eps: []*models.Endpoint{
				{Status: realized(9)},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint with nil policy is counted",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{Identity: identity, Policy: nil}},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint with nil realized is counted",
			eps: []*models.Endpoint{
				{Status: &models.EndpointStatus{
					Identity: identity,
					Policy:   &models.EndpointPolicyStatus{Realized: nil},
				}},
			},
			rev:  10,
			want: 1,
		},
		{
			name: "identity endpoint at target revision is not counted",
			eps: []*models.Endpoint{
				{Status: realized(10)},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "identity endpoint ahead of target revision is not counted",
			eps: []*models.Endpoint{
				{Status: realized(11)},
			},
			rev:  10,
			want: 0,
		},
		{
			name: "mix: only identity-bearing lagging endpoints are counted",
			eps: []*models.Endpoint{
				{Status: realized(11)},                               // ahead, not counted
				{Status: realized(9)},                                // stale, counted
				{Status: &models.EndpointStatus{Identity: nil}},      // no identity, skipped
				{Status: nil},                                        // no status, skipped
				{Status: &models.EndpointStatus{Identity: identity}}, // identity, nil policy, counted
			},
			rev:  10,
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, countEndpointsBelowPolicyRevision(tt.eps, tt.rev))
		})
	}
}
