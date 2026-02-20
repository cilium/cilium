// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestFromPolicy(t *testing.T) {
	uu := map[string]struct {
		in *flow.Policy
		e  Policy
	}{
		"nil": {
			e: Policy{},
		},

		"full": {
			in: &flow.Policy{
				Kind:      "Kubernetes",
				Namespace: "default",
				Name:      "test-policy",
				Labels:    []string{"app=frontend", "env=prod"},
				Revision:  42,
			},
			e: Policy{
				Kind:      "Kubernetes",
				Namespace: "default",
				Name:      "test-policy",
				Labels:    []string{"app=frontend", "env=prod"},
				Revision:  42,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToPolicy(u.in))
		})
	}
}
