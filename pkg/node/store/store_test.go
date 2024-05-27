// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/node/types"
)

func TestValidatingNode(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		node      types.Node
		validator nodeValidator
		errstr    string
	}{
		{
			name:      "valid cluster name",
			node:      types.Node{Cluster: "foo", Name: "qux"},
			validator: ClusterNameValidator("foo"),
		},
		{
			name:      "invalid cluster name",
			node:      types.Node{Cluster: "foo", Name: "qux"},
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name:      "valid name name",
			key:       "qux",
			node:      types.Node{Cluster: "foo", Name: "qux"},
			validator: NameValidator(),
		},
		{
			name:      "invalid namespaced name",
			key:       "fred",
			node:      types.Node{Cluster: "foo", Name: "qux"},
			validator: NameValidator(),
			errstr:    "name does not match key: got qux, expected fred",
		},
		{
			name:      "valid cluster ID",
			node:      types.Node{Cluster: "foo", Name: "qux", ClusterID: 10},
			validator: ClusterIDValidator(ptr.To[uint32](10)),
		},
		{
			name:      "invalid cluster ID",
			node:      types.Node{Cluster: "foo", Name: "qux", ClusterID: 10},
			validator: ClusterIDValidator(ptr.To[uint32](15)),
			errstr:    "unexpected cluster ID: got 10, expected 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.node.Marshal()
			require.NoError(t, err)

			got := ValidatingKeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			require.EqualExportedValues(t, tt.node, got.(*ValidatingNode).Node)
		})
	}
}
