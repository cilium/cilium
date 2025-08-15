// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPolicyLabelSourceFix tests the fix for issue #40912
// where CiliumNetworkPolicy labels without explicit source field
// were getting empty source instead of defaulting to "unspec".
func TestPolicyLabelSourceFix(t *testing.T) {
	// This simulates the label structure from a CiliumNetworkPolicy
	// that would be parsed from YAML like:
	// labels:
	// - key: policy-comment
	//   value: allow all traffic inside namespace
	policyLabelJSON := `{
		"key": "policy-comment",
		"value": "allow all traffic inside namespace"
	}`

	var label Label
	err := json.Unmarshal([]byte(policyLabelJSON), &label)
	require.NoError(t, err)

	// Before the fix, this would be an empty string ""
	// After the fix, it should be "unspec"
	require.Equal(t, LabelSourceUnspec, label.Source)
	require.Equal(t, "policy-comment", label.Key)
	require.Equal(t, "allow all traffic inside namespace", label.Value)

	// Verify the string representation includes the source
	expectedString := "unspec:policy-comment=allow all traffic inside namespace"
	require.Equal(t, expectedString, label.String())
}

// TestPolicyLabelArraySourceFix tests that LabelArray parsing also works correctly
func TestPolicyLabelArraySourceFix(t *testing.T) {
	// This simulates parsing a LabelArray from JSON where some labels
	// don't have explicit source fields
	labelsJSON := `[
		{
			"key": "policy-comment",
			"value": "allow all traffic inside namespace"
		},
		{
			"source": "k8s",
			"key": "io.cilium.k8s.policy.name",
			"value": "test-policy"
		}
	]`

	var labelArray LabelArray
	err := json.Unmarshal([]byte(labelsJSON), &labelArray)
	require.NoError(t, err)

	require.Len(t, labelArray, 2)

	// First label should have defaulted source
	require.Equal(t, LabelSourceUnspec, labelArray[0].Source)
	require.Equal(t, "policy-comment", labelArray[0].Key)
	require.Equal(t, "allow all traffic inside namespace", labelArray[0].Value)

	// Second label should keep its explicit source
	require.Equal(t, "k8s", labelArray[1].Source)
	require.Equal(t, "io.cilium.k8s.policy.name", labelArray[1].Key)
	require.Equal(t, "test-policy", labelArray[1].Value)
}
