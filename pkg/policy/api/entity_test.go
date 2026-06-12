// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func resetEntitySelectorMapping() {
	EntitySelectorMapping[EntityCluster] = EndpointSelectorSlice{}
	EntitySelectorMapping[EntityKubeAPIServer] = EndpointSelectorSlice{endpointSelectorKubeAPIServer}
}

func TestParseAdditionalEntitySelectors(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name: "empty config",
			raw:  "",
		},
		{
			name: "kube-apiserver selector",
			raw:  `{"kube-apiserver":{"matchLabels":{"k8s-app":"konnectivity-agent"}}}`,
		},
		{
			name:    "invalid json",
			raw:     `{`,
			wantErr: "unable to parse policy-entity-selectors",
		},
		{
			name:    "unsupported entity",
			raw:     `{"cluster":{"matchLabels":{"foo":"bar"}}}`,
			wantErr: `entity "cluster" cannot be customized`,
		},
		{
			name:    "empty selector",
			raw:     `{"kube-apiserver":{}}`,
			wantErr: `entity "kube-apiserver" requires a non-empty label selector`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selectors, err := ParseAdditionalEntitySelectors(tt.raw)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			if tt.raw == "" {
				require.Nil(t, selectors)
				return
			}

			require.Contains(t, selectors, EntityKubeAPIServer)
			require.Len(t, selectors[EntityKubeAPIServer], 1)
		})
	}
}

func TestInitEntitiesAdditionalKubeAPIServerSelector(t *testing.T) {
	t.Cleanup(func() {
		InitEntities("cluster1", nil)
	})

	resetEntitySelectorMapping()

	additional, err := ParseAdditionalEntitySelectors(`{"kube-apiserver":{"matchLabels":{"k8s-app":"konnectivity-agent"}}}`)
	require.NoError(t, err)

	InitEntities("cluster1", additional)

	require.Len(t, EntitySelectorMapping[EntityKubeAPIServer], 2)
	// cluster entity includes the default selectors plus the additional
	// kube-apiserver selector.
	require.Len(t, EntitySelectorMapping[EntityCluster], 9)

	additionalSelector := EntitySelectorMapping[EntityKubeAPIServer][1]
	require.True(t, additionalSelector.HasKey("k8s:k8s-app"))
	values, ok := additionalSelector.GetMatch("k8s:k8s-app")
	require.True(t, ok)
	require.Equal(t, []string{"konnectivity-agent"}, values)
}
