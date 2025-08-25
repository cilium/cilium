// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/labels"
)

// TestParseToCiliumLabelsSourceK8s tests that CiliumNetworkPolicy labels
// without explicit source field are set to "k8s" source.
func TestParseToCiliumLabelsSourceK8s(t *testing.T) {
	// Create a label array that simulates user-defined labels from a CiliumNetworkPolicy
	// with different source scenarios
	userLabels := labels.LabelArray{
		{Key: "policy-comment", Value: "allow all traffic inside namespace", Source: ""}, // Empty source
		{Key: "team", Value: "platform", Source: labels.LabelSourceUnspec},               // Unspec source (from UnmarshalJSON)
		{Key: "explicit-source", Value: "test", Source: "custom"},                        // This should be preserved
	}

	// Process through ParseToCiliumLabels as would happen in real policy parsing
	processedLabels := ParseToCiliumLabels("default", "test-policy", types.UID("test-uid"), userLabels)

	// Find the user-defined labels in the processed result
	var policyCommentLabel, teamLabel, explicitSourceLabel *labels.Label
	for _, lbl := range processedLabels {
		switch lbl.Key {
		case "policy-comment":
			policyCommentLabel = &lbl
		case "team":
			teamLabel = &lbl
		case "explicit-source":
			explicitSourceLabel = &lbl
		}
	}

	// Verify that labels without explicit source now have "k8s" source
	require.NotNil(t, policyCommentLabel)
	require.Equal(t, labels.LabelSourceK8s, policyCommentLabel.Source)
	require.Equal(t, "policy-comment", policyCommentLabel.Key)
	require.Equal(t, "allow all traffic inside namespace", policyCommentLabel.Value)

	require.NotNil(t, teamLabel)
	require.Equal(t, labels.LabelSourceK8s, teamLabel.Source)
	require.Equal(t, "team", teamLabel.Key)
	require.Equal(t, "platform", teamLabel.Value)

	// Verify that labels with explicit source are preserved
	require.NotNil(t, explicitSourceLabel)
	require.Equal(t, "custom", explicitSourceLabel.Source)
	require.Equal(t, "explicit-source", explicitSourceLabel.Key)
	require.Equal(t, "test", explicitSourceLabel.Value)

	// Verify string representation shows correct source
	expectedString := "k8s:policy-comment=allow all traffic inside namespace"
	require.Equal(t, expectedString, policyCommentLabel.String())
}
