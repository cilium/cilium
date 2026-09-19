// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
)

func TestLRPCRDSyncResourceNames(t *testing.T) {
	lrpAgentConfigDisabled := lrpAgentConfig{enableLocalRedirectPolicy: false}
	lrpAgentConfigEnabled := lrpAgentConfig{enableLocalRedirectPolicy: true}

	t.Run("disabled", func(t *testing.T) {
		require.Empty(t, lrpCRDSyncResourceNames(lrpAgentConfigDisabled).Names)
	})

	t.Run("enabled", func(t *testing.T) {
		out := lrpCRDSyncResourceNames(lrpAgentConfigEnabled)
		require.Equal(t,
			[]k8sSynced.CRDSyncResourceName{
				k8sSynced.CRDSyncResourceName(k8sSynced.CRDResourceName(ciliumv2.CLRPName)),
			},
			out.Names,
		)
	})
}
