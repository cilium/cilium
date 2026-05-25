// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

func TestADSGRPCServerStopsOnContextCancel(t *testing.T) {
	logger := hivetest.Logger(t)
	server := newADSServer(logger, nil, nil, xdsServerConfig{
		envoySocketDir:       t.TempDir(),
		proxyGID:             os.Getgid(),
		policyRestoreTimeout: time.Second,
	}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.run(ctx)
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(server.socketPath)
		return err == nil
	}, time.Second, 10*time.Millisecond)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ADS gRPC server did not stop after context cancellation")
	}

	_, err := os.Stat(server.socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}
