// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	datapathConfig "github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	fakeNodeMap "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestObjectCache(t *testing.T) {
	tmpDir := t.TempDir()

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(hivetest.Logger(t), configWriterForTest(t), tmpDir)
	realEP := testutils.NewTestEndpoint(t)

	dir := getDirs(t)

	// First run should compile and generate the object.
	first, hash, err := cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	// Same EP should not be compiled twice.
	second, hash2, err := cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, hash, hash2)
	require.NotSame(t, second, first)

	// Changing the ID should not generate a new object.
	realEP.Id++
	third, hash3, err := cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, hash, hash3)
	require.NotSame(t, third, first)

	// Changing a setting on the EP should generate a new object.
	realEP.Opts.SetBool("foo", true)
	fourth, hash4, err := cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.NotEqual(t, hash, hash4)
	require.NotSame(t, fourth, first)
}

func TestObjectCacheReuse(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "templates")

	setupCompilationDirectories(t)
	ctx := t.Context()

	ep := testutils.NewTestEndpoint(t)
	writer := configWriterForTest(t)
	dir := getDirs(t)

	restart := func(nodeCfg *datapathConfig.Config) (*objectCache, string, *metrics.SpanStat) {
		cache := newObjectCache(hivetest.Logger(t), writer, workDir)
		require.NoError(t, cache.UpdateDatapathHash(ctx, nodeCfg))
		stats := &metrics.SpanStat{}
		_, hash, err := cache.fetchOrCompile(ctx, &ep, dir, stats)
		require.NoError(t, err)
		return cache, hash, stats
	}

	_, hash, stats := restart(&localNodeConfig)
	require.NotZero(t, stats.BpfCompilation.Total())

	// A restarted agent loads the object its predecessor compiled.
	cache, reused, stats := restart(&localNodeConfig)
	require.Equal(t, hash, reused)
	require.Zero(t, stats.BpfCompilation.Total())

	// The cache recompiles an object that does not parse.
	require.NoError(t, os.Truncate(cache.objectPath(&ep, hash), 0))
	_, _, stats = restart(&localNodeConfig)
	require.NotZero(t, stats.BpfCompilation.Total())

	// A different base hash wipes the old templates.
	otherCfg := localNodeConfig
	otherCfg.NodeIPv4 = netip.MustParseAddr("192.0.2.1")
	_, other, _ := restart(&otherCfg)
	require.NotEqual(t, hash, other)
	require.NoDirExists(t, filepath.Join(workDir, hash))

	// Without the recorded base hash the cache reuses nothing.
	require.NoError(t, os.Remove(workDir+".key"))
	_, _, stats = restart(&otherCfg)
	require.NotZero(t, stats.BpfCompilation.Total())

	// A compiler environment change recompiles the templates.
	t.Setenv("CCC_OVERRIDE_OPTIONS", "# +-DCACHE_TEST_ENV")
	_, envHash, stats := restart(&otherCfg)
	require.NotEqual(t, other, envHash)
	require.NotZero(t, stats.BpfCompilation.Total())

	// Without a producer digest the cache records and reuses nothing.
	bpfDir := option.Config.BpfDir
	option.Config.BpfDir = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { option.Config.BpfDir = bpfDir })
	for range 2 {
		_, _, stats = restart(&otherCfg)
		require.NotZero(t, stats.BpfCompilation.Total())
		require.NoFileExists(t, workDir+".key")
	}
}

func TestObjectCacheParallel(t *testing.T) {
	tmpDir := t.TempDir()

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(hivetest.Logger(t), configWriterForTest(t), tmpDir)
	ep := testutils.NewTestEndpoint(t)

	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			_, _, err := cache.fetchOrCompile(ctx, &ep, getDirs(t), nil)
			assert.NoError(t, err)
		})
	}

	wg.Wait()
}

func configWriterForTest(t testing.TB) config.Writer {
	t.Helper()

	cfg, err := config.NewHeaderfileWriter(config.WriterParams{
		NodeMap:        fakeNodeMap.NewFakeNodeMapV2(),
		NodeAddressing: fakenode.NewAddressing(),
		Sysctl:         nil,
	})
	if err != nil {
		t.Fatalf("failed to create header file writer: %v", err)
	}
	return cfg
}
