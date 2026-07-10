// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package list

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
)

func TestNodeOutputs(t *testing.T) {
	var testCases = []struct {
		name                    string
		nodes                   []*observerpb.Node
		expectedJSONOutput      string
		expectedTableOutput     string
		expectedWideTableOutput string
	}{
		{
			name: "four nodes, connected, unavailable, and error",
			nodes: []*observerpb.Node{
				{
					Name:     "foo",
					Version:  "1",
					State:    relaypb.NodeState_NODE_CONNECTED,
					UptimeNs: 1e12,
					NumFlows: 500,
					MaxFlows: 1000,
					Address:  "1.2.3.4",
					Tls: &observerpb.TLS{
						Enabled:    true,
						ServerName: "foo.bar.tls",
					},
				},
				{
					Name:    "bar",
					Version: "2",
					State:   relaypb.NodeState_NODE_UNAVAILABLE,
					Address: "5.6.7.8",
				},
				{
					Name:    "baz",
					Version: "3",
					State:   relaypb.NodeState_NODE_GONE,
				},
				{
					Name:    "faz",
					Version: "4",
					State:   relaypb.NodeState_NODE_ERROR,
				},
			},
			expectedJSONOutput: `[
  {
    "name": "foo",
    "version": "1",
    "address": "1.2.3.4",
    "state": "NODE_CONNECTED",
    "tls": {
      "enabled": true,
      "server_name": "foo.bar.tls"
    },
    "uptime_ns": "1000000000000",
    "num_flows": "500",
    "max_flows": "1000"
  },
  {
    "name": "bar",
    "version": "2",
    "address": "5.6.7.8",
    "state": "NODE_UNAVAILABLE"
  },
  {
    "name": "baz",
    "version": "3",
    "state": "NODE_GONE"
  },
  {
    "name": "faz",
    "version": "4",
    "state": "NODE_ERROR"
  }
]
`,
			expectedTableOutput: `NAME   STATUS        AGE      FLOWS/S   CURRENT/MAX-FLOWS
foo    Connected     16m40s   0.00      500/1000 ( 50.00%)
bar    Unavailable   N/A      N/A       N/A
baz    Gone          N/A      N/A       N/A
faz    Error         N/A      N/A       N/A
`,
			expectedWideTableOutput: `NAME   STATUS        AGE      FLOWS/S   CURRENT/MAX-FLOWS    VERSION   ADDRESS   TLS
foo    Connected     16m40s   0.00      500/1000 ( 50.00%)   1         1.2.3.4   Enabled
bar    Unavailable   N/A      N/A       N/A                  2         5.6.7.8   N/A
baz    Gone          N/A      N/A       N/A                  3                   N/A
faz    Error         N/A      N/A       N/A                  4                   N/A
`,
		},
		{
			name: "one node, connected",
			nodes: []*observerpb.Node{
				{
					Name:     "foo",
					Version:  "1",
					State:    relaypb.NodeState_NODE_CONNECTED,
					UptimeNs: 1e12,
					NumFlows: 500,
					MaxFlows: 1000,
					Address:  "1.2.3.4",
					Tls: &observerpb.TLS{
						Enabled:    true,
						ServerName: "foo.bar.tls",
					},
				},
			},
			expectedJSONOutput: `[
  {
    "name": "foo",
    "version": "1",
    "address": "1.2.3.4",
    "state": "NODE_CONNECTED",
    "tls": {
      "enabled": true,
      "server_name": "foo.bar.tls"
    },
    "uptime_ns": "1000000000000",
    "num_flows": "500",
    "max_flows": "1000"
  }
]
`,
			expectedTableOutput: `NAME   STATUS      AGE      FLOWS/S   CURRENT/MAX-FLOWS
foo    Connected   16m40s   0.00      500/1000 ( 50.00%)
`,
			expectedWideTableOutput: `NAME   STATUS      AGE      FLOWS/S   CURRENT/MAX-FLOWS    VERSION   ADDRESS   TLS
foo    Connected   16m40s   0.00      500/1000 ( 50.00%)   1         1.2.3.4   Enabled
`,
		},
		{
			name: "happy path empty nodes",
			nodes: []*observerpb.Node{
				{},
			},
			expectedJSONOutput: `[
  {}
]
`,
			expectedTableOutput: `NAME   STATUS    AGE   FLOWS/S   CURRENT/MAX-FLOWS
       Unknown   N/A   N/A       N/A
`,
			expectedWideTableOutput: `NAME   STATUS    AGE   FLOWS/S   CURRENT/MAX-FLOWS   VERSION   ADDRESS   TLS
       Unknown   N/A   N/A       N/A                 N/A                 N/A
`,
		},
		{
			name: "sad path with nil nodes",
			nodes: []*observerpb.Node{
				nil,
			},
			expectedJSONOutput: `[
  null
]
`,
			expectedTableOutput: `NAME   STATUS    AGE   FLOWS/S   CURRENT/MAX-FLOWS
       Unknown   N/A   N/A       N/A
`,
			expectedWideTableOutput: `NAME   STATUS    AGE   FLOWS/S   CURRENT/MAX-FLOWS   VERSION   ADDRESS   TLS
       Unknown   N/A   N/A       N/A                 N/A                 N/A
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
			require.NoError(t, jsonOutput(&buf, tc.nodes), tc.name)
			assert.Equal(t, tc.expectedJSONOutput, buf.String(), "json %s", tc.name)

			// regular table
			buf.Reset()
			require.NoError(t, nodeTableOutput(&buf, tc.nodes), tc.name)
			assert.Equal(t, tc.expectedTableOutput, buf.String(), "regular table %s", tc.name)

			// wide table
			listOpts.output = "wide"
			buf.Reset()
			require.NoError(t, nodeTableOutput(&buf, tc.nodes), tc.name)
			assert.Equal(t, tc.expectedWideTableOutput, buf.String(), "wide table %s", tc.name)
		})
	}
}
