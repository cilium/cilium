// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestObjectCache(t *testing.T) {
	tmpDir := t.TempDir()

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	cache := newObjectCache(configWriterForTest(t), nil, tmpDir)
	realEP := testutils.NewTestEndpoint()

	dir := getDirs(t)

	// First run should compile and generate the object.
	_, isNew, err := cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, isNew, true)

	// Same EP should not be compiled twice.
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, isNew, false)

	// Changing the ID should not generate a new object.
	realEP.Id++
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, isNew, false)

	// Changing a setting on the EP should generate a new object.
	realEP.Opts.SetBool("foo", true)
	_, isNew, err = cache.fetchOrCompile(ctx, &realEP, dir, nil)
	require.NoError(t, err)
	require.Equal(t, isNew, true)
}

type buildResult struct {
	goroutine int
	path      string
	compiled  bool
	err       error
}

func receiveResult(t *testing.T, results chan buildResult) (*buildResult, error) {
	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		return &result, nil
	case <-time.After(contextTimeout):
		return nil, fmt.Errorf("Timed out waiting for goroutines to return")
	}
}

func TestObjectCacheParallel(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	setupCompilationDirectories(t)

	tests := []struct {
		description string
		builds      int
		divisor     int
	}{
		{
			description: "One build, multiple blocking goroutines",
			builds:      8,
			divisor:     8,
		},
		{
			description: "Eight builds, half compile, half block",
			builds:      8,
			divisor:     2,
		},
		{
			description: "Eight unique builds",
			builds:      8,
			divisor:     1,
		},
	}

	for _, test := range tests {
		t.Logf("  %s", test.description)

		results := make(chan buildResult, test.builds)
		cache := newObjectCache(configWriterForTest(t), nil, tmpDir)
		for i := 0; i < test.builds; i++ {
			go func(i int) {
				ep := testutils.NewTestEndpoint()
				opt := fmt.Sprintf("OPT%d", i/test.divisor)
				ep.Opts.SetBool(opt, true)
				file, isNew, err := cache.fetchOrCompile(ctx, &ep, getDirs(t), nil)
				path := ""
				if file != nil {
					path = file.Name()
				}
				results <- buildResult{
					goroutine: i,
					path:      path,
					compiled:  isNew,
					err:       err,
				}
			}(i)
		}

		// First result will always be a compilation for the new set of options
		compiled := make(map[string]int, test.builds)
		used := make(map[string]int, test.builds)
		for i := 0; i < test.builds; i++ {
			result, err := receiveResult(t, results)
			require.NoError(t, err)

			used[result.path] = used[result.path] + 1
			if result.compiled {
				compiled[result.path] = compiled[result.path] + 1
			}
		}

		require.Len(t, compiled, test.builds/test.divisor)
		require.Len(t, used, test.builds/test.divisor)
		for _, templateCompileCount := range compiled {
			// Only one goroutine compiles each template
			require.Equal(t, templateCompileCount, 1)
		}
		for _, templateUseCount := range used {
			// Based on the test parameters, a number of goroutines
			// may share the same template.
			require.Equal(t, templateUseCount, test.divisor)
		}
	}
}

func configWriterForTest(t testing.TB) types.ConfigWriter {
	t.Helper()

	devices, err := tables.NewDeviceTable()
	if err != nil {
		t.Fatalf("failed to create device table: %v", err)
	}
	db := statedb.New()
	if err := db.RegisterTable(devices); err != nil {
		t.Fatalf("failed to register devices: %v", err)
	}
	cfg, err := config.NewHeaderfileWriter(config.WriterParams{
		DB:      db,
		Devices: devices,
	})
	if err != nil {
		t.Fatalf("failed to create header file writer: %v", err)
	}
	return cfg
}
