// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func TestNamespaceOutputs(t *testing.T) {
	var testCases = []struct {
		name                    string
		namespaces              []*observerpb.Namespace
		expectedJSONOutput      string
		expectedTableOutput     string
		expectedWideTableOutput string
	}{
		{
			name: "multiple namespaces no cluster",
			namespaces: []*observerpb.Namespace{
				{Namespace: "foo"},
				{Namespace: "bar"},
				{Namespace: "baz"},
				{Namespace: "faz"},
			},
			expectedJSONOutput: `[
  {
    "namespace": "foo"
  },
  {
    "namespace": "bar"
  },
  {
    "namespace": "baz"
  },
  {
    "namespace": "faz"
  }
]
`,
			expectedTableOutput: `NAMESPACE
foo
bar
baz
faz
`,
			expectedWideTableOutput: `NAMESPACE   CLUSTER
foo
bar
baz
faz
`,
		},
		{
			name: "multiple namespaces with cluster",
			namespaces: []*observerpb.Namespace{
				{Namespace: "foo", Cluster: "cluster-1"},
				{Namespace: "bar", Cluster: "cluster-1"},
				{Namespace: "baz", Cluster: "cluster-2"},
				{Namespace: "faz", Cluster: "cluster-2"},
			},
			expectedJSONOutput: `[
  {
    "cluster": "cluster-1",
    "namespace": "foo"
  },
  {
    "cluster": "cluster-1",
    "namespace": "bar"
  },
  {
    "cluster": "cluster-2",
    "namespace": "baz"
  },
  {
    "cluster": "cluster-2",
    "namespace": "faz"
  }
]
`,
			expectedTableOutput: `NAMESPACE
foo
bar
baz
faz
`,
			expectedWideTableOutput: `NAMESPACE   CLUSTER
foo         cluster-1
bar         cluster-1
baz         cluster-2
faz         cluster-2
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				listOpts.output = ""
			}()
			buf := bytes.Buffer{}

			// json
			require.NoError(t, jsonOutput(&buf, tc.namespaces), tc.name)
			assert.Equal(t, tc.expectedJSONOutput, buf.String(), "json %s", tc.name)

			// regular table
			buf.Reset()
			require.NoError(t, namespaceTableOutput(&buf, tc.namespaces), tc.name)
			assert.Equal(t, tc.expectedTableOutput, buf.String(), "regular table %s", tc.name)

			// wide table
			listOpts.output = "wide"
			buf.Reset()
			require.NoError(t, namespaceTableOutput(&buf, tc.namespaces), tc.name)
			assert.Equal(t, tc.expectedWideTableOutput, buf.String(), "wide table %s", tc.name)
		})
	}
}
