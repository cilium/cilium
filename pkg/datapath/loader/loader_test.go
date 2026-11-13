// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	// FIXME(#49861): 60 s hides BPF compile-time regressions.
	contextTimeout = 60 * time.Second
	benchTimeout   = 5*time.Minute + 5*time.Second

	bpfDir = filepath.Join("..", "..", "..", "bpf")
)

func initEndpoint(tb testing.TB, ep *testutils.TestEndpoint) {
	testutils.PrivilegedTest(tb)

	require.NoError(tb, rlimit.RemoveMemlock())

	ep.State = tb.TempDir()
	for _, iface := range []string{ep.InterfaceName(), defaults.SecondHostDevice} {
		link := netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: iface,
			},
		}
		if err := netlink.LinkAdd(&link); err != nil {
			if !os.IsExist(err) {
				tb.Fatalf("Failed to add link: %s", err)
			}
		}
		tb.Cleanup(func() {
			if err := netlink.LinkDel(&link); err != nil {
				tb.Fatalf("Failed to delete link: %s", err)
			}
		})
	}
}

func initBpffs(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	tb.Helper()

	require.NoError(tb, bpf.MkdirBPF(bpf.TCGlobalsPath()))
	require.NoError(tb, bpf.MkdirBPF(bpf.CiliumPath()))

	tb.Cleanup(func() {
		require.NoError(tb, os.RemoveAll(bpf.TCGlobalsPath()))
		require.NoError(tb, os.RemoveAll(bpf.CiliumPath()))
	})
}

func getDirs(tb testing.TB) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   bpfDir,
		Output:  tb.TempDir(),
	}
}

func getEpDirs(ep *testutils.TestEndpoint) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
}

func testReloadDatapath(t *testing.T, ep *testutils.TestEndpoint) {
	initBpffs(t)

	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	stats := &metrics.SpanStat{}

	l := newTestLoader(t)
	_, err := l.ReloadDatapath(ctx, ep, &localNodeConfig, stats, nil)
	require.NoError(t, err)

	mapNames := []string{policymap.PolicyCallMapName}
	if !ep.IsHost() {
		mapNames = append(mapNames, policymap.PolicyEgressCallMapName)
	}
	programs := func(t *testing.T) []ebpf.ProgramID {
		t.Helper()
		var ids []ebpf.ProgramID
		for _, name := range mapNames {
			m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.TCGlobalsPath(), name), nil)
			require.NoError(t, err)
			var id ebpf.ProgramID
			err = m.Lookup(uint32(ep.GetID()), &id)
			m.Close()
			require.NoError(t, err)
			ids = append(ids, id)
		}
		return ids
	}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "rejected", err: errors.New("proxy rejected update")},
		{name: "accepted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := programs(t)
			calls := 0
			_, err := l.ReloadDatapath(ctx, ep, &localNodeConfig, stats, func() error {
				calls++
				require.Equal(t, before, programs(t), "new policy programs must not be reachable before the hook succeeds")
				return tc.err
			})
			require.Equal(t, 1, calls)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Equal(t, before, programs(t), "a rejected update must retain the old programs")
			} else {
				require.NoError(t, err)
				for i, id := range programs(t) {
					require.NotEqual(t, before[i], id)
				}
			}
		})
	}
}

// TestPrivilegedCompileOrLoadDefaultEndpoint checks that the datapath can be compiled
// and loaded.
func TestPrivilegedCompileOrLoadDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint(t)
	initEndpoint(t, &ep)
	testReloadDatapath(t, &ep)
}

// TestPrivilegedCompileOrLoadHostEndpoint is the same as
// TestCompileAndLoadDefaultEndpoint, but for the host endpoint.
func TestPrivilegedCompileOrLoadHostEndpoint(t *testing.T) {
	hostEp := testutils.NewTestHostEndpoint(t)
	initEndpoint(t, &hostEp)

	testReloadDatapath(t, &hostEp)
}

// TestPrivilegedReload compiles and attaches the datapath.
func TestPrivilegedReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := testutils.NewTestEndpoint(t)
	initEndpoint(t, &ep)

	dirInfo := getEpDirs(&ep)
	logger := hivetest.Logger(t)
	err := compileDatapath(ctx, logger, dirInfo, false)
	require.NoError(t, err)

	l, err := safenetlink.LinkByName(ep.InterfaceName())
	require.NoError(t, err)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	tmp := testutils.TempBPFFS(t)

	spec, err := ebpf.LoadCollectionSpec(objPath)
	require.NoError(t, err)

	for range 2 {
		coll, commit, err := bpf.LoadCollection(logger, spec, &bpf.CollectionOptions{
			CollectionOptions: ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: tmp}},
		})
		require.NoError(t, err)

		require.NoError(t, attachSKBProgram(logger, l, coll.Programs[symbolFromEndpoint],
			symbolFromEndpoint, tmp, netlink.HANDLE_MIN_INGRESS, true))
		require.NoError(t, attachSKBProgram(logger, l, coll.Programs[symbolToEndpoint],
			symbolToEndpoint, tmp, netlink.HANDLE_MIN_EGRESS, true))

		require.NoError(t, commit())

		coll.Close()
	}
}

func testCompileFailure(t *testing.T, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	exit := make(chan struct{})
	defer close(exit)
	go func() {
		select {
		case <-time.After(100 * time.Millisecond):
			cancel()
		case <-exit:
			break
		}
	}()

	l := newTestLoader(t)
	timeout := time.Now().Add(contextTimeout)
	var err error
	stats := &metrics.SpanStat{}
	for err == nil && time.Now().Before(timeout) {
		_, err = l.ReloadDatapath(ctx, ep, &localNodeConfig, stats, nil)
	}
	require.Error(t, err)
}

// TestPrivilegedCompileFailureDefaultEndpoint attempts to compile then cancels the
// context and ensures that the failure paths may be hit.
func TestPrivilegedCompileFailureDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint(t)
	initEndpoint(t, &ep)
	testCompileFailure(t, &ep)
}

// TestPrivilegedCompileFailureHostEndpoint is the same as
// TestPrivilegedCompileFailureDefaultEndpoint, but for the host endpoint.
func TestPrivilegedCompileFailureHostEndpoint(t *testing.T) {
	hostEp := testutils.NewTestHostEndpoint(t)
	initEndpoint(t, &hostEp)
	testCompileFailure(t, &hostEp)
}

// BenchmarkCompileOnly benchmarks the just the entire compilation process.
func BenchmarkCompileOnly(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	dirInfo := getDirs(b)
	option.Config.Debug = true
	logger := hivetest.Logger(b)

	for b.Loop() {
		if err := compileDatapath(ctx, logger, dirInfo, false); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkPrivilegedReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	tmp := testutils.TempBPFFS(b)

	ep := testutils.NewTestEndpoint(b)
	initEndpoint(b, &ep)

	dirInfo := getEpDirs(&ep)

	logger := hivetest.Logger(b)
	if err := compileDatapath(ctx, logger, dirInfo, false); err != nil {
		b.Fatal(err)
	}

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		coll, commit, err := bpf.LoadCollection(logger, spec, &bpf.CollectionOptions{
			CollectionOptions: ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: tmp}},
		})
		if err != nil {
			b.Fatal(err)
		}
		if err := commit(); err != nil {
			b.Fatalf("committing bpf pins: %s", err)
		}
		coll.Close()
	}
}
