// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium-cli/connectivity/check"
)

func TestNewConnectivityTests(t *testing.T) {
	testCases := []struct {
		params                 check.Parameters
		expectedCount          int
		expectedTestNamespaces []string
	}{
		{
			params: check.Parameters{
				FlowValidation: check.FlowValidationModeDisabled,
				TestNamespace:  "cilium-test",
			},
			expectedCount:          1,
			expectedTestNamespaces: []string{"cilium-test"},
		},
		{
			params: check.Parameters{
				FlowValidation:  check.FlowValidationModeDisabled,
				TestNamespace:   "cilium-test",
				TestConcurrency: -1,
			},
			expectedCount:          1,
			expectedTestNamespaces: []string{"cilium-test"},
		},
		{
			params: check.Parameters{
				FlowValidation:  check.FlowValidationModeDisabled,
				TestNamespace:   "cilium-test",
				TestConcurrency: 3,
			},
			expectedCount:          3,
			expectedTestNamespaces: []string{"cilium-test-1", "cilium-test-2", "cilium-test-3"},
		},
	}
	for _, tt := range testCases {
		// function to test
		actual, err := newConnectivityTests(tt.params)

		require.NoError(t, err)
		require.Equal(t, tt.expectedCount, len(actual))
		for i, n := range tt.expectedTestNamespaces {
			require.Equal(t, n, actual[i].Params().TestNamespace)
		}
	}
}
