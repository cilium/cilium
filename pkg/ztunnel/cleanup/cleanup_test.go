// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cleanup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/promise"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

type fakeRestorer struct{}

func (*fakeRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error {
	return nil
}

func (*fakeRestorer) WaitForEndpointRestore(context.Context) error {
	return nil
}

func (*fakeRestorer) WaitForInitialPolicy(context.Context) error {
	return nil
}

func TestRegisterCleanupEnabledCreatesMarker(t *testing.T) {
	stateDir := t.TempDir()
	markerPath := filepath.Join(stateDir, ztunnelStateFile)

	require.NoError(t, registerCleanup(cleanupParams{
		Lifecycle:     hivetest.Lifecycle(t),
		Config:        config.Config{EnableZTunnel: true},
		CleanupConfig: cleanupConfig{stateDir: stateDir},
	}))

	require.FileExists(t, markerPath)
}

func TestRegisterCleanupMarkerStatError(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(stateDir, nil, 0600))

	err := registerCleanup(cleanupParams{
		CleanupConfig: cleanupConfig{stateDir: stateDir},
	})
	require.ErrorContains(t, err, "stat ztunnel state marker")
}

func TestRunCleanupRemovesMarker(t *testing.T) {
	stateDir := t.TempDir()
	markerPath := filepath.Join(stateDir, ztunnelStateFile)
	require.NoError(t, os.WriteFile(markerPath, nil, 0600))

	resolver, restorerPromise := promise.New[endpointstate.Restorer]()
	resolver.Resolve(&fakeRestorer{})

	require.NoError(t, runCleanup(
		t.Context(),
		hivetest.Logger(t),
		restorerPromise,
		testendpointmanager.NewMockEndpointManager(),
		cleanupConfig{stateDir: stateDir},
	))
	require.NoFileExists(t, markerPath)
}

func TestRunCleanupNetnsOpenErrors(t *testing.T) {
	tests := []struct {
		name       string
		netnsPath  string
		wantErr    bool
		wantMarker bool
	}{
		{
			name:      "missing netns is ignored",
			netnsPath: filepath.Join(t.TempDir(), "does-not-exist"),
		},
		{
			name:       "other open error is returned",
			netnsPath:  "\x00",
			wantErr:    true,
			wantMarker: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := t.TempDir()
			markerPath := filepath.Join(stateDir, ztunnelStateFile)
			require.NoError(t, os.WriteFile(markerPath, nil, 0600))

			resolver, restorerPromise := promise.New[endpointstate.Restorer]()
			resolver.Resolve(&fakeRestorer{})

			ep := &endpoint.Endpoint{ID: 123}
			ep.SetContainerNetnsPath(tt.netnsPath)
			epMgr := testendpointmanager.NewMockEndpointManager()
			epMgr.Endpoints = []*endpoint.Endpoint{ep}

			err := runCleanup(
				t.Context(),
				hivetest.Logger(t),
				restorerPromise,
				epMgr,
				cleanupConfig{stateDir: stateDir},
			)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantMarker {
				require.FileExists(t, markerPath)
			} else {
				require.NoFileExists(t, markerPath)
			}
		})
	}
}
