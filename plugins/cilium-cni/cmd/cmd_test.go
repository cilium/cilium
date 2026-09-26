// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/connector"
)

func TestNetkitPeerRXQueues(t *testing.T) {
	for _, mode := range []connector.Mode{connector.ModeNetkit, connector.ModeNetkitL2} {
		require.Zero(t, netkitPeerRXQueues(nil, mode))
		require.Zero(t, netkitPeerRXQueues(map[string]any{
			"EnableNetworkDriver": false,
		}, mode))
		require.Zero(t, netkitPeerRXQueues(map[string]any{
			"EnableNetworkDriver": "true",
		}, mode))
		require.Equal(t, netkitPeerRXQueueCount, netkitPeerRXQueues(map[string]any{
			"EnableNetworkDriver": true,
		}, mode))
	}

	require.Zero(t, netkitPeerRXQueues(map[string]any{
		"EnableNetworkDriver": true,
	}, connector.ModeVeth))
}
