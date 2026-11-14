// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qos

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/qos/config"
)

func TestQoSCRDSyncResourceNames(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		require.Empty(t, qosCRDSyncResourceNames(config.Config{EnableQoS: false}).Names)
	})

	t.Run("enabled", func(t *testing.T) {
		out := qosCRDSyncResourceNames(config.Config{EnableQoS: true})
		require.Equal(t,
			[]k8sSynced.CRDSyncResourceName{
				k8sSynced.CRDSyncResourceName(k8sSynced.CRDResourceName(v2alpha1.CQMName)),
				k8sSynced.CRDSyncResourceName(k8sSynced.CRDResourceName(v2alpha1.CQCName)),
				k8sSynced.CRDSyncResourceName(k8sSynced.CRDResourceName(v2alpha1.CQPName)),
			},
			out.Names,
		)
	})
}
