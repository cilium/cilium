// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnDemandEnvoyStopBeforeStart(t *testing.T) {
	starter := &onDemandXdsStarter{}
	require.NoError(t, starter.stopStandaloneEnvoy())
	require.ErrorIs(t, starter.startStandaloneEnvoy(t.Context(), nil), errEnvoyStopped)
}

func TestOnDemandEnvoyStopAfterStart(t *testing.T) {
	proxy := &StandaloneEnvoy{
		stopCh: make(chan struct{}),
		errCh:  make(chan error),
	}
	starter := &onDemandXdsStarter{envoy: proxy}
	stopped := make(chan struct{})
	go func() {
		<-proxy.stopCh
		close(proxy.errCh)
		close(stopped)
	}()

	require.NoError(t, starter.stopStandaloneEnvoy())
	<-stopped
}
