// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvoyNodeToIP(t *testing.T) {
	var ip string
	var err error

	ip, err = EnvoyNodeIdToIP("host~127.0.0.1~no-id~localdomain")
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", ip)

	_, err = EnvoyNodeIdToIP("host~127.0.0.1~localdomain")
	require.Error(t, err)

	_, err = EnvoyNodeIdToIP("host~not-an-ip~v0.default~default.svc.cluster.local")
	require.Error(t, err)
}
