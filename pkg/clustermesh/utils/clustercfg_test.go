// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"context"
	"errors"
	"path"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

var mockerr = errors.New("error")

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type mockBackend struct {
	data   lock.Map[string, []byte]
	errors lock.Map[string, error]
}

func (mb *mockBackend) withError(clusterName string) {
	mb.errors.Store(path.Join(kvstore.ClusterConfigPrefix, clusterName), mockerr)
}

func (mb *mockBackend) Get(_ context.Context, key string) ([]byte, error) {
	if err, ok := mb.errors.LoadAndDelete(key); ok {
		return nil, err
	}

	value, _ := mb.data.Load(key)
	return value, nil
}

func (mb *mockBackend) UpdateIfDifferent(_ context.Context, key string, value []byte, _ bool) (bool, error) {
	if err, ok := mb.errors.LoadAndDelete(key); ok {
		return false, err
	}

	mb.data.Store(key, value)
	return true, nil
}

func TestGetSetClusterConfig(t *testing.T) {
	ctx := context.Background()
	mb := mockBackend{}

	cfg1 := cmtypes.CiliumClusterConfig{ID: 11, Capabilities: cmtypes.CiliumClusterConfigCapabilities{SyncedCanaries: true}}
	cfg2 := cmtypes.CiliumClusterConfig{ID: 22, Capabilities: cmtypes.CiliumClusterConfigCapabilities{Cached: true}}
	cfg3 := cmtypes.CiliumClusterConfig{ID: 33, Capabilities: cmtypes.CiliumClusterConfigCapabilities{Cached: true}}

	require.NoError(t, SetClusterConfig(ctx, "foo", cfg1, &mb), "failed to write cluster configuration")
	require.NoError(t, SetClusterConfig(ctx, "bar", cfg2, &mb), "failed to write cluster configuration")
	require.NoError(t, SetClusterConfig(ctx, "bar", cfg3, &mb), "failed to update cluster configuration")
	require.NoError(t, SetClusterConfig(ctx, "bar", cfg3, &mb), "failed to update cluster configuration (same value)")

	mb.withError("error")
	require.ErrorIs(t, SetClusterConfig(ctx, "error", cfg1, &mb), mockerr, "kvstore error not propagated correctly")

	got, err := GetClusterConfig(ctx, "foo", &mb)
	require.NoError(t, err, "failed to read cluster configuration")
	require.Equal(t, got, cfg1, "retrieved configuration does not match expected one")

	got, err = GetClusterConfig(ctx, "bar", &mb)
	require.NoError(t, err, "failed to read cluster configuration")
	require.Equal(t, got, cfg3, "retrieved configuration does not match expected one")

	_, err = GetClusterConfig(ctx, "not-existing", &mb)
	require.ErrorIs(t, err, ErrClusterConfigNotFound, "incorrect error for not found configuration")

	mb.withError("error")
	_, err = GetClusterConfig(ctx, "error", &mb)
	require.ErrorIs(t, err, mockerr, "kvstore error not propagated correctly")

	// Simulate invalid data stored in the kvstore
	mb.UpdateIfDifferent(ctx, path.Join(kvstore.ClusterConfigPrefix, "invalid"), []byte("invalid"), true)
	_, err = GetClusterConfig(ctx, "invalid", &mb)
	require.ErrorContains(t, err, "invalid character", "unmarshaling error not propagated correctly")
}

func TestEnforceClusterConfig(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Configure a short run interval for testing purposes
	defer func(orig time.Duration) { runInterval = orig }(runInterval)
	runInterval = 25 * time.Millisecond

	ctx := context.Background()
	mb := mockBackend{}
	log := hivetest.Logger(t)

	cfg1 := cmtypes.CiliumClusterConfig{ID: 11, Capabilities: cmtypes.CiliumClusterConfigCapabilities{SyncedCanaries: true}}
	cfg2 := cmtypes.CiliumClusterConfig{ID: 22, Capabilities: cmtypes.CiliumClusterConfigCapabilities{Cached: true}}

	stopAndWait1, err := EnforceClusterConfig(ctx, "foo", cfg1, &mb, log)
	defer stopAndWait1()
	require.NoError(t, err, "failed to write cluster configuration")

	stopAndWait2, err := EnforceClusterConfig(ctx, "bar", cfg2, &mb, log)
	defer stopAndWait2()
	require.NoError(t, err, "failed to write cluster configuration")

	mb.withError("error")
	stopAndWait3, err := EnforceClusterConfig(ctx, "error", cfg2, &mb, log)
	defer stopAndWait3()
	require.ErrorIs(t, err, mockerr, "kvstore error not propagated correctly")

	got, err := GetClusterConfig(ctx, "foo", &mb)
	require.NoError(t, err, "failed to read cluster configuration")
	require.Equal(t, got, cfg1, "retrieved configuration does not match expected one")

	got, err = GetClusterConfig(ctx, "bar", &mb)
	require.NoError(t, err, "failed to read cluster configuration")
	require.Equal(t, got, cfg2, "retrieved configuration does not match expected one")

	// Externally mutate the cluster configuration, and assert that it gets eventually reconciled.
	require.NoError(t, SetClusterConfig(ctx, "bar", cfg1, &mb), "failed to override cluster configuration")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err = GetClusterConfig(ctx, "bar", &mb)
		assert.NoError(c, err, "failed to read cluster configuration")
		assert.Equal(c, got, cfg2, "retrieved configuration does not match expected one")
	}, timeout, tick)
}
