// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	contextTimeout = 10 * time.Second
	benchTimeout   = 5*time.Minute + 5*time.Second

	bpfDir = filepath.Join("..", "..", "..", "bpf")
)

func initEndpoint(tb testing.TB, ep *testutils.TestEndpoint) {
	testutils.PrivilegedTest(tb)

	require.Nil(tb, rlimit.RemoveMemlock())

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
	_, err := l.ReloadDatapath(ctx, ep, &localNodeConfig, stats)
	require.NoError(t, err)
}

// TestCompileOrLoadDefaultEndpoint checks that the datapath can be compiled
// and loaded.
func TestCompileOrLoadDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)
	testReloadDatapath(t, &ep)
}

// TestCompileOrLoadHostEndpoint is the same as
// TestCompileAndLoadDefaultEndpoint, but for the host endpoint.
func TestCompileOrLoadHostEndpoint(t *testing.T) {

	callsmap.HostMapName = fmt.Sprintf("test_%s", callsmap.MapName)
	callsmap.NetdevMapName = fmt.Sprintf("test_%s", callsmap.MapName)

	hostEp := testutils.NewTestHostEndpoint()
	initEndpoint(t, &hostEp)

	testReloadDatapath(t, &hostEp)
}

// TestReload compiles and attaches the datapath.
func TestReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)

	dirInfo := getEpDirs(&ep)
	err := compileDatapath(ctx, dirInfo, false, log)
	require.NoError(t, err)

	l, err := netlink.LinkByName(ep.InterfaceName())
	require.NoError(t, err)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	tmp := testutils.TempBPFFS(t)

	for range 2 {
		spec, err := bpf.LoadCollectionSpec(objPath)
		require.NoError(t, err)

		coll, commit, err := bpf.LoadCollection(spec, &bpf.CollectionOptions{
			CollectionOptions: ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: tmp}},
		})
		require.NoError(t, err)

		require.NoError(t, attachSKBProgram(l, coll.Programs[symbolFromEndpoint],
			symbolFromEndpoint, tmp, netlink.HANDLE_MIN_INGRESS, true))
		require.NoError(t, attachSKBProgram(l, coll.Programs[symbolToEndpoint],
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
		_, err = l.ReloadDatapath(ctx, ep, &localNodeConfig, stats)
	}
	require.Error(t, err)
}

// TestCompileFailureDefaultEndpoint attempts to compile then cancels the
// context and ensures that the failure paths may be hit.
func TestCompileFailureDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)
	testCompileFailure(t, &ep)
}

// TestCompileFailureHostEndpoint is the same as
// TestCompileFailureDefaultEndpoint, but for the host endpoint.
func TestCompileFailureHostEndpoint(t *testing.T) {
	hostEp := testutils.NewTestHostEndpoint()
	initEndpoint(t, &hostEp)
	testCompileFailure(t, &hostEp)
}

func TestBPFMasqAddrs(t *testing.T) {
	old4 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv4Masquerade = true
	old6 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv6Masquerade = true
	t.Cleanup(func() {
		option.Config.EnableIPv4Masquerade = old4
		option.Config.EnableIPv6Masquerade = old6
	})

	masq4, masq6 := bpfMasqAddrs("test", &localNodeConfig)
	require.Equal(t, masq4.IsValid(), false)
	require.Equal(t, masq6.IsValid(), false)

	newConfig := localNodeConfig
	newConfig.NodeAddresses = []tables.NodeAddress{
		{
			Addr:       netip.MustParseAddr("1.0.0.1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("1000::1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("2.0.0.2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
		{
			Addr:       netip.MustParseAddr("2000::2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
	}

	masq4, masq6 = bpfMasqAddrs("test", &newConfig)
	require.Equal(t, masq4.String(), "1.0.0.1")
	require.Equal(t, masq6.String(), "1000::1")

	masq4, masq6 = bpfMasqAddrs("unknown", &newConfig)
	require.Equal(t, masq4.String(), "2.0.0.2")
	require.Equal(t, masq6.String(), "2000::2")
}

// BenchmarkCompileOnly benchmarks the just the entire compilation process.
func BenchmarkCompileOnly(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	dirInfo := getDirs(b)
	option.Config.Debug = true

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	tmp := testutils.TempBPFFS(b)

	ep := testutils.NewTestEndpoint()
	initEndpoint(b, &ep)

	dirInfo := getEpDirs(&ep)

	if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
		b.Fatal(err)
	}

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spec, err := bpf.LoadCollectionSpec(objPath)
		if err != nil {
			b.Fatal(err)
		}

		coll, commit, err := bpf.LoadCollection(spec, &bpf.CollectionOptions{
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
