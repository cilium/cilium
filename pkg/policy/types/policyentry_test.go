// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/policy/api"
)

func TestEntityNamespaceMarker(t *testing.T) {
	// Test that EntityNamespaceMarker implements PeerSelector
	var _ PeerSelector = EntityNamespaceMarker{}

	marker := EntityNamespaceMarker{}
	marker.IsPeerSelector() // Should compile and not panic
}

func TestPeerSelectorSliceHasEntityNamespaceMarker(t *testing.T) {
	tests := []struct {
		name     string
		slice    PeerSelectorSlice
		expected bool
	}{
		{
			name:     "empty slice",
			slice:    PeerSelectorSlice{},
			expected: false,
		},
		{
			name:     "nil slice",
			slice:    nil,
			expected: false,
		},
		{
			name: "only EndpointSelectors",
			slice: PeerSelectorSlice{
				api.NewESFromLabels(),
				api.NewESFromLabels(),
			},
			expected: false,
		},
		{
			name: "only EntityNamespaceMarker",
			slice: PeerSelectorSlice{
				EntityNamespaceMarker{},
			},
			expected: true,
		},
		{
			name: "mixed with EntityNamespaceMarker",
			slice: PeerSelectorSlice{
				api.NewESFromLabels(),
				EntityNamespaceMarker{},
				api.NewESFromLabels(),
			},
			expected: true,
		},
		{
			name: "CIDR and FQDN without marker",
			slice: PeerSelectorSlice{
				api.CIDR("10.0.0.0/8"),
				api.FQDNSelector{MatchName: "example.com"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.slice.HasEntityNamespaceMarker()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPeerSelectorSliceGetAsEndpointSelectors(t *testing.T) {
	// Test that GetAsEndpointSelectors ignores EntityNamespaceMarker
	slice := PeerSelectorSlice{
		api.NewESFromLabels(),
		EntityNamespaceMarker{},
		api.NewESFromLabels(),
	}

	selectors := slice.GetAsEndpointSelectors()
	// Should only return the two EndpointSelectors, not the marker
	require.Len(t, selectors, 2)
}

func TestPeerSelectorSliceGetAsEndpointSelectorsWithNamespace(t *testing.T) {
	// Use the proper label format: "k8s.io.kubernetes.pod.namespace"
	// The label source prefix is added differently in the matching code
	namespaceLabel := "io.kubernetes.pod.namespace"

	tests := []struct {
		name          string
		slice         PeerSelectorSlice
		namespace     string
		expectedCount int
	}{
		{
			name: "expand marker with namespace",
			slice: PeerSelectorSlice{
				EntityNamespaceMarker{},
			},
			namespace:     "my-namespace",
			expectedCount: 1,
		},
		{
			name: "marker with empty namespace returns nothing",
			slice: PeerSelectorSlice{
				EntityNamespaceMarker{},
			},
			namespace:     "",
			expectedCount: 0,
		},
		{
			name: "mixed selectors with marker",
			slice: PeerSelectorSlice{
				api.NewESFromLabels(),
				EntityNamespaceMarker{},
				api.NewESFromLabels(),
			},
			namespace:     "test-ns",
			expectedCount: 3, // 2 original + 1 expanded from marker
		},
		{
			name: "no marker just returns regular selectors",
			slice: PeerSelectorSlice{
				api.NewESFromLabels(),
				api.NewESFromLabels(),
			},
			namespace:     "any-ns",
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selectors := tt.slice.GetAsEndpointSelectorsWithNamespace(tt.namespace, namespaceLabel)
			require.Len(t, selectors, tt.expectedCount)
		})
	}
}

func TestPeerSelectorSliceDeepEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        PeerSelectorSlice
		b        PeerSelectorSlice
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "empty and nil are equal (both have len 0)",
			a:        PeerSelectorSlice{},
			b:        nil,
			expected: true, // DeepEqual treats empty and nil as equal since len() == 0
		},
		{
			name:     "both empty",
			a:        PeerSelectorSlice{},
			b:        PeerSelectorSlice{},
			expected: true,
		},
		{
			name:     "both have EntityNamespaceMarker",
			a:        PeerSelectorSlice{EntityNamespaceMarker{}},
			b:        PeerSelectorSlice{EntityNamespaceMarker{}},
			expected: true,
		},
		{
			name:     "one has marker, other doesn't",
			a:        PeerSelectorSlice{EntityNamespaceMarker{}},
			b:        PeerSelectorSlice{api.NewESFromLabels()},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        PeerSelectorSlice{EntityNamespaceMarker{}, EntityNamespaceMarker{}},
			b:        PeerSelectorSlice{EntityNamespaceMarker{}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.a.DeepEqual(&tt.b)
			require.Equal(t, tt.expected, result)
		})
	}
}
