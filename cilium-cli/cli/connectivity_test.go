// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

func TestNewConnectivityTests(t *testing.T) {
	testCases := []struct {
		params                            check.Parameters
		expectedCount                     int
		expectedTestNamespaces            []string
		expectedExternalTargetCANamespace []string
	}{
		{
			params: check.Parameters{
				FlowValidation:            check.FlowValidationModeDisabled,
				TestNamespace:             "cilium-test",
				ExternalTargetCANamespace: "",
			},
			expectedCount:                     1,
			expectedTestNamespaces:            []string{"cilium-test-1"},
			expectedExternalTargetCANamespace: []string{"cilium-test-1"},
		},
		{
			params: check.Parameters{
				FlowValidation:            check.FlowValidationModeDisabled,
				TestNamespace:             "cilium-test",
				ExternalTargetCANamespace: "cilium-test",
			},
			expectedCount:                     1,
			expectedTestNamespaces:            []string{"cilium-test-1"},
			expectedExternalTargetCANamespace: []string{"cilium-test"},
		},
		{
			params: check.Parameters{
				FlowValidation:            check.FlowValidationModeDisabled,
				TestNamespace:             "cilium-test",
				ExternalTargetCANamespace: "cilium-test",
				TestConcurrency:           -1,
			},
			expectedCount:                     1,
			expectedTestNamespaces:            []string{"cilium-test-1"},
			expectedExternalTargetCANamespace: []string{"cilium-test"},
		},
		{
			params: check.Parameters{
				FlowValidation:            check.FlowValidationModeDisabled,
				TestNamespace:             "cilium-test",
				ExternalTargetCANamespace: "",
				TestConcurrency:           3,
			},
			expectedCount:                     3,
			expectedTestNamespaces:            []string{"cilium-test-1", "cilium-test-2", "cilium-test-3"},
			expectedExternalTargetCANamespace: []string{"cilium-test-1", "cilium-test-2", "cilium-test-3"},
		},
		{
			params: check.Parameters{
				FlowValidation:            check.FlowValidationModeDisabled,
				TestNamespace:             "cilium-test",
				ExternalTargetCANamespace: "cilium-test",
				TestConcurrency:           3,
			},
			expectedCount:                     3,
			expectedTestNamespaces:            []string{"cilium-test-1", "cilium-test-2", "cilium-test-3"},
			expectedExternalTargetCANamespace: []string{"cilium-test"},
		},
	}
	for _, tt := range testCases {
		// function to test
		actual, err := newConnectivityTests(tt.params, check.NewConcurrentLogger(&bytes.Buffer{}, 1))

		require.NoError(t, err)
		require.Equal(t, tt.expectedCount, len(actual))
		for i, n := range tt.expectedTestNamespaces {
			require.Equal(t, n, actual[i].Params().TestNamespace)
		}
		for i, n := range tt.expectedExternalTargetCANamespace {
			require.Equal(t, n, actual[i].Params().ExternalTargetCANamespace)
		}
	}
}

func TestConnectivityTestFlags(t *testing.T) {
	ct := newCmdConnectivityTest(&api.NopHooks{})
	require.Empty(t, params.JunitProperties)
	ct.Flags().Set("junit-property", "a=b")
	require.NoError(t, ct.Flags().Set("junit-property", "a=b"))
	require.Equal(t, map[string]string{"a": "b"}, params.JunitProperties)
	require.NoError(t, ct.Flags().Set("junit-property", "c=d"))
	require.Equal(t, map[string]string{"a": "b", "c": "d"}, params.JunitProperties)

	require.Empty(t, params.NodeSelector)
	require.NoError(t, ct.Flags().Set("node-selector", "a=b"))
	require.Equal(t, map[string]string{"a": "b"}, params.NodeSelector)
	require.NoError(t, ct.Flags().Set("node-selector", "c=d"))
	require.Equal(t, map[string]string{"a": "b", "c": "d"}, params.NodeSelector)
}
