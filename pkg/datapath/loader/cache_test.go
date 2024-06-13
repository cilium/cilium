// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/types"
	fakeNodeMap "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestObjectCache(t *testing.T) {
	tmpDir := t.TempDir()

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(configWriterForTest(t), tmpDir)
	realEP := testutils.NewTestEndpoint()

	dir := getDirs(t)

	// First run should compile and generate the object.
	first, isNew, err := cache.fetchOrCompile(ctx, &localNodeConfig, &realEP, dir, nil)
	require.NoError(t, err)
	require.True(t, isNew)

	// Same EP should not be compiled twice.
	second, isNew, err := cache.fetchOrCompile(ctx, &localNodeConfig, &realEP, dir, nil)
	require.NoError(t, err)
	require.False(t, isNew)
	require.False(t, second == first)

	// Changing the ID should not generate a new object.
	realEP.Id++
	third, isNew, err := cache.fetchOrCompile(ctx, &localNodeConfig, &realEP, dir, nil)
	require.NoError(t, err)
	require.False(t, isNew)
	require.False(t, third == first)

	// Changing a setting on the EP should generate a new object.
	realEP.Opts.SetBool("foo", true)
	fourth, isNew, err := cache.fetchOrCompile(ctx, &localNodeConfig, &realEP, dir, nil)
	require.NoError(t, err)
	require.True(t, isNew)
	require.False(t, fourth == first)
}

func TestObjectCacheParallel(t *testing.T) {
	tmpDir := t.TempDir()

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(configWriterForTest(t), tmpDir)
	ep := testutils.NewTestEndpoint()

	var wg sync.WaitGroup
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.fetchOrCompile(ctx, &localNodeConfig, &ep, getDirs(t), nil)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

func configWriterForTest(t testing.TB) types.ConfigWriter {
	t.Helper()

	cfg, err := config.NewHeaderfileWriter(config.WriterParams{
		NodeMap:        fakeNodeMap.NewFakeNodeMapV2(),
		NodeAddressing: fakeTypes.NewNodeAddressing(),
		Sysctl:         nil,
	})
	if err != nil {
		t.Fatalf("failed to create header file writer: %v", err)
	}
	return cfg
}
