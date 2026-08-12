// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

func TestIsCloudIPAMMode(t *testing.T) {
	require.True(t, isCloudIPAMMode(ipamOption.IPAMENI))
	require.True(t, isCloudIPAMMode(ipamOption.IPAMAzure))
	require.True(t, isCloudIPAMMode(ipamOption.IPAMAlibabaCloud))
	require.False(t, isCloudIPAMMode(ipamOption.IPAMClusterPool))
}

func TestAlibabaCloudIPv6DisablesEndpointRulesReconciler(t *testing.T) {
	var logs bytes.Buffer
	err := registerEndpointRulesReconciler(params{
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		DaemonConfig: &option.DaemonConfig{
			IPAM:       ipamOption.IPAMAlibabaCloud,
			EnableIPv6: true,
		},
	})
	require.NoError(t, err)
	require.Contains(t, logs.String(), "Endpoint routing rule reconciliation is disabled")
	require.Contains(t, logs.String(), "routing metadata for IPv6 is not supported by AlibabaCloud IPAM")
}
