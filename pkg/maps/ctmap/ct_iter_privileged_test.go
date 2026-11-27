// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	datapathbpf "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func init() {
	// slogloggercheck: initialize lockdebug logger for standalone package tests.
	lock.SetLogger(logging.DefaultSlogLogger)
}

func ctCurTimeSec(t *testing.T) uint32 {
	t.Helper()
	now, err := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
	require.NoError(t, err)
	return uint32(now)
}

func ctKey4(dst, src types.IPv4, dport, sport uint16, proto u8proto.U8proto, flags uint8) *CtKey4Global {
	return &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   dst,
				SourceAddr: src,
				DestPort:   dport,
				SourcePort: sport,
				NextHeader: proto,
				Flags:      flags,
			},
		},
	}
}

func initCTIterOrSkip(t *testing.T) *ctIterator {
	t.Helper()
	it := newCTIterator(hivetest.Logger(t))
	err := it.init()
	t.Cleanup(func() { _ = it.close() })
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF CT scrub iterator not supported by kernel: %v", err)
		}
		require.NoError(t, err)
	}
	return it
}

func wrapScanCounter(t *testing.T, it *ctIterator) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	it.mu.Lock()
	orig := it.scan
	it.scan = func(m *Map, filterMap *ebpf.Map, prog *ebpf.Program, fltVal datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error) {
		calls.Add(1)
		return orig(m, filterMap, prog, fltVal)
	}
	it.mu.Unlock()
	t.Cleanup(func() {
		it.mu.Lock()
		it.scan = orig
		it.mu.Unlock()
	})
	return &calls
}

// snapshotIterFDs returns the counts of open per-scan BPF iterator FDs
// ("anon_inode:bpf-link" and "anon_inode:bpf_iter") in /proc/self/fd.
// Process-wide bpf-map and bpf-prog totals are deliberately excluded because
// unclosed ebpf.Map handles from sibling tests are reclaimed asynchronously
// via runtime.AddCleanup.
func snapshotIterFDs(t *testing.T) (links, iters int) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue
		}
		switch target {
		case "anon_inode:bpf-link":
			links++
		case "anon_inode:bpf_iter":
			iters++
		}
	}
	return links, iters
}

// countOpenBPFFDsByID counts open FDs in /proc/self/fd whose readlink target
// matches target (e.g. "anon_inode:bpf-prog") and whose /proc/self/fdinfo/<fd>
// contains an exact fdinfoLine (e.g. "prog_id:\t42").
func countOpenBPFFDsByID(t *testing.T, target, fdinfoLine string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	count := 0
	for _, e := range entries {
		linkTarget, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || linkTarget != target {
			continue
		}
		data, err := os.ReadFile("/proc/self/fdinfo/" + e.Name())
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			if line == fdinfoLine {
				count++
				break
			}
		}
	}
	return count
}

func withTempGlobalCTMapSizes(t *testing.T, tcpCap, anyCap int) {
	t.Helper()
	prevTCP := option.Config.CTMapEntriesGlobalTCP
	prevAny := option.Config.CTMapEntriesGlobalAny
	option.Config.CTMapEntriesGlobalTCP = tcpCap
	option.Config.CTMapEntriesGlobalAny = anyCap
	t.Cleanup(func() {
		option.Config.CTMapEntriesGlobalTCP = prevTCP
		option.Config.CTMapEntriesGlobalAny = prevAny
	})
}

func assertFilterMapSlotZeroed(t *testing.T, it *ctIterator) {
	t.Helper()
	it.mu.Lock()
	fltMap := it.filterMap
	it.mu.Unlock()
	require.NotNil(t, fltMap)

	var zero uint32
	var slotVal datapathbpf.CtScrubCtScrubFilter
	require.NoError(t, fltMap.Lookup(&zero, &slotVal))
	require.Equal(t, datapathbpf.CtScrubCtScrubFilter{}, slotVal,
		"cilium_ct_flt[0] must be zeroed after scan")
}

func openIsolatedCTAndNATMaps(t *testing.T, suffix string, mapCap int, it *ctIterator) (tcpMap, anyMap *Map, natMap *nat.Map) {
	t.Helper()
	withTempGlobalCTMapSizes(t, mapCap, mapCap)
	preserveMapInfo(t)

	natMap = nat.NewMap(nil, "cilium_snat_v4_"+suffix, nat.IPv4, mapCap)
	natMap.Logger = hivetest.Logger(t)
	require.NoError(t, natMap.OpenOrCreate())

	sharedLock := &lock.Mutex{}
	mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{natMap: natMap, natMapLock: sharedLock}
	mapInfo[mapTypeIPv4AnyGlobal] = mapAttributes{natMap: natMap, natMapLock: sharedLock}

	var opts []MapOption
	if it != nil {
		opts = append(opts, withCTIterator(it))
	}

	tcpMap = newMap(MapNameTCP4Global+"_"+suffix, mapTypeIPv4TCPGlobal, opts...)
	tcpMap.Logger = hivetest.Logger(t)
	require.NoError(t, tcpMap.OpenOrCreate())

	anyMap = newMap(MapNameAny4Global+"_"+suffix, mapTypeIPv4AnyGlobal, opts...)
	anyMap.Logger = hivetest.Logger(t)
	require.NoError(t, anyMap.OpenOrCreate())

	t.Cleanup(func() {
		_ = tcpMap.Map.Unpin()
		_ = tcpMap.Close()
		_ = anyMap.Map.Unpin()
		_ = anyMap.Close()
		_ = natMap.Map.Unpin()
		_ = natMap.Close()
	})

	return tcpMap, anyMap, natMap
}

func seedSNATFlow(t *testing.T, tcpMap *Map, natMap *nat.Map, pod, remote, gw types.IPv4, sport, snatPort uint16, proto u8proto.U8proto, lifetime uint32) {
	t.Helper()
	require.NoError(t, tcpMap.Map.Update(
		ctKey4(pod, remote, 80, sport, proto, tuple.TUPLE_F_OUT),
		&CtEntry{Packets: 10, Bytes: 1024, Lifetime: lifetime},
	))
	require.NoError(t, natMap.Map.Update(
		&nat.NatKey4{TupleKey4Global: ctKey4(remote, pod, 80, sport, proto, tuple.TUPLE_F_OUT).TupleKey4Global},
		&nat.NatEntry4{Created: 100, NeedsCT: 1, Addr: gw, Port: snatPort},
	))
	require.NoError(t, natMap.Map.Update(
		&nat.NatKey4{TupleKey4Global: ctKey4(gw, remote, snatPort, 80, proto, tuple.TUPLE_F_IN).TupleKey4Global},
		&nat.NatEntry4{Created: 100, NeedsCT: 1, Addr: pod, Port: sport},
	))
}

func TestPrivilegedCTIterLifecycleAndFDLeak(t *testing.T) {
	setupCTMap(t)
	_ = initCTIterOrSkip(t)

	// 64K entries avoids per-CPU LRU free-list exhaustion on high-core-count hosts.
	const mapCap = 65536
	withTempGlobalCTMapSizes(t, mapCap, mapCap)

	// 1. ctMaps.init() -> TCP4/Any4 scrubs -> <14B key reject -> ctMaps.close() -> fallback.
	it := newCTIterator(hivetest.Logger(t))
	r := &ctMaps{
		ctIter:   it,
		v4TCPMap: newMap(MapNameTCP4Global+"_iter_lc", mapTypeIPv4TCPGlobal, withCTIterator(it)),
		v4AnyMap: newMap(MapNameAny4Global+"_iter_lc", mapTypeIPv4AnyGlobal, withCTIterator(it)),
	}
	r.v4TCPMap.Logger = hivetest.Logger(t)
	r.v4AnyMap.Logger = hivetest.Logger(t)
	require.NoError(t, r.init())
	t.Cleanup(func() {
		_ = r.v4TCPMap.Map.Unpin()
		_ = r.v4AnyMap.Map.Unpin()
		_ = r.close()
	})
	lcCalls := wrapScanCounter(t, it)

	it.mu.Lock()
	prog := it.prog
	fltMap := it.filterMap
	it.mu.Unlock()
	require.NotNil(t, prog)
	require.NotNil(t, fltMap)

	// Negative <14B key-size attach check.
	smallKeyMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "ct_iter_k13",
		Type:       ebpf.Hash,
		KeySize:    13,
		ValueSize:  4,
		MaxEntries: 16,
	})
	require.NoError(t, err)
	defer smallKeyMap.Close()

	badLink, attachErr := link.AttachIter(link.IterOptions{
		Program: prog,
		Map:     smallKeyMap,
	})
	if badLink != nil {
		_ = badLink.Close()
	}
	require.Error(t, attachErr, "attaching 14B cil_ct4_scrub to a 13B-key map must fail")

	nowSec := ctCurTimeSec(t)
	podIP := netip.MustParseAddr("10.244.10.1")
	podArr := podIP.As4()
	val := &CtEntry{Packets: 3, Bytes: 300, Lifetime: nowSec + 3600}
	require.NoError(t, r.v4TCPMap.Map.Update(ctKey4(podArr, types.IPv4{172, 16, 0, 1}, 80, 40001, u8proto.TCP, tuple.TUPLE_F_OUT), val))
	require.NoError(t, r.v4AnyMap.Map.Update(ctKey4(podArr, types.IPv4{172, 16, 1, 1}, 53, 50001, u8proto.UDP, tuple.TUPLE_F_OUT), val))

	flt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: podIP, NetID: 0}: {}}}
	delTCP, err := r.v4TCPMap.GC(flt, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, delTCP)
	require.False(t, it.tripped.Load())
	require.Equal(t, int64(1), lcCalls.Load())
	assertFilterMapSlotZeroed(t, it)

	delAny, err := r.v4AnyMap.GC(flt, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, delAny)
	require.False(t, it.tripped.Load())
	require.Equal(t, int64(2), lcCalls.Load())
	assertFilterMapSlotZeroed(t, it)

	_ = r.v4TCPMap.Map.Unpin()
	_ = r.v4AnyMap.Map.Unpin()
	require.NoError(t, r.close())

	it.mu.Lock()
	progAfterClose := it.prog
	fltAfterClose := it.filterMap
	it.mu.Unlock()
	require.Nil(t, progAfterClose)
	require.Nil(t, fltAfterClose)

	postCloseMap := newMap(MapNameTCP4Global+"_post_close", mapTypeIPv4TCPGlobal, withCTIterator(it))
	postCloseMap.Logger = hivetest.Logger(t)
	require.NoError(t, postCloseMap.OpenOrCreate())
	defer func() {
		_ = postCloseMap.Map.Unpin()
		_ = postCloseMap.Close()
	}()
	postPod := netip.MustParseAddr("10.244.10.250")
	require.NoError(t, postCloseMap.Map.Update(ctKey4(postPod.As4(), types.IPv4{172, 16, 9, 1}, 80, 45000, u8proto.TCP, tuple.TUPLE_F_OUT), val))
	postFlt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: postPod, NetID: 0}: {}}}

	_, ok := postCloseMap.doScrub4WithIterator(postFlt, nil)
	require.False(t, ok)
	delPost, err := postCloseMap.GC(postFlt, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 1, delPost)
	require.Equal(t, int64(2), lcCalls.Load())

	// 2. /proc/self/fd BPF FD leak check across init() -> scrub GC() -> close().
	// Check per-scan bpf-link/bpf_iter counts directly and track the loaded
	// prog/filterMap by kernel object ID so async runtime.AddCleanup from
	// unrelated tests cannot perturb process-wide bpf-map/bpf-prog totals.
	fdIt := newCTIterator(hivetest.Logger(t))
	fdTCPMap, fdAnyMap, _ := openIsolatedCTAndNATMaps(t, "fd_leak", mapCap, fdIt)
	baseLinks, baseIters := snapshotIterFDs(t)

	require.NoError(t, fdIt.init())
	t.Cleanup(func() { _ = fdIt.close() })
	fdCalls := wrapScanCounter(t, fdIt)

	fdIt.mu.Lock()
	loadedProg := fdIt.prog
	loadedFltMap := fdIt.filterMap
	fdIt.mu.Unlock()
	require.NotNil(t, loadedProg)
	require.NotNil(t, loadedFltMap)

	progInfo, err := loadedProg.Info()
	require.NoError(t, err)
	progID, ok := progInfo.ID()
	require.True(t, ok, "kernel must report bpf_prog ID")

	fltMapInfo, err := loadedFltMap.Info()
	require.NoError(t, err)
	fltMapID, ok := fltMapInfo.ID()
	require.True(t, ok, "kernel must report bpf_map ID")

	progIDLine := fmt.Sprintf("prog_id:\t%d", progID)
	fltMapIDLine := fmt.Sprintf("map_id:\t%d", fltMapID)

	require.Equal(t, 1, countOpenBPFFDsByID(t, "anon_inode:bpf-prog", progIDLine))
	require.Equal(t, 1, countOpenBPFFDsByID(t, "anon_inode:bpf-map", fltMapIDLine))
	loadedLinks, loadedIters := snapshotIterFDs(t)
	require.Equal(t, baseLinks, loadedLinks)
	require.Equal(t, baseIters, loadedIters)

	for pass := range 4 {
		ip := netip.MustParseAddr(fmt.Sprintf("10.244.11.%d", pass+1))
		if pass%2 == 0 {
			require.NoError(t, fdTCPMap.Map.Update(
				ctKey4(ip.As4(), types.IPv4{172, 17, 0, byte(pass + 1)}, 443, uint16(46000+pass), u8proto.TCP, tuple.TUPLE_F_OUT),
				val,
			))
		}
		f := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: ip, NetID: 0}: {}}}
		_, err := fdTCPMap.GC(f, nil, nil)
		require.NoError(t, err)
		assertFilterMapSlotZeroed(t, fdIt)
		_, err = fdAnyMap.GC(f, nil, nil)
		require.NoError(t, err)
		assertFilterMapSlotZeroed(t, fdIt)
	}
	require.False(t, fdIt.tripped.Load())
	require.Equal(t, int64(8), fdCalls.Load())

	postScanLinks, postScanIters := snapshotIterFDs(t)
	require.Equal(t, baseLinks, postScanLinks, "per-scan bpf-link FDs must not leak")
	require.Equal(t, baseIters, postScanIters, "per-scan bpf_iter FDs must not leak")
	require.Equal(t, 1, countOpenBPFFDsByID(t, "anon_inode:bpf-prog", progIDLine))
	require.Equal(t, 1, countOpenBPFFDsByID(t, "anon_inode:bpf-map", fltMapIDLine))

	require.NoError(t, fdIt.close())
	require.Equal(t, -1, loadedProg.FD(), "close() must close loaded iterator prog FD")
	require.Equal(t, -1, loadedFltMap.FD(), "close() must close loaded filter map FD")
	require.Equal(t, 0, countOpenBPFFDsByID(t, "anon_inode:bpf-prog", progIDLine), "iterator prog FD must not remain open after close()")
	require.Equal(t, 0, countOpenBPFFDsByID(t, "anon_inode:bpf-map", fltMapIDLine), "filter map FD must not remain open after close()")
	postCloseLinks, postCloseIters := snapshotIterFDs(t)
	require.Equal(t, baseLinks, postCloseLinks)
	require.Equal(t, baseIters, postCloseIters)
}

func TestPrivilegedCTMapsCloseOrder(t *testing.T) {
	setupCTMap(t)
	probe := initCTIterOrSkip(t)
	_ = probe.close()

	const mapCap = 65536
	withTempGlobalCTMapSizes(t, mapCap, mapCap)

	it := newCTIterator(hivetest.Logger(t))
	r := &ctMaps{
		ctIter:   it,
		v4TCPMap: newMap(MapNameTCP4Global+"_close_order", mapTypeIPv4TCPGlobal, withCTIterator(it)),
		v4AnyMap: newMap(MapNameAny4Global+"_close_order", mapTypeIPv4AnyGlobal, withCTIterator(it)),
	}
	r.v4TCPMap.Logger = hivetest.Logger(t)
	r.v4AnyMap.Logger = hivetest.Logger(t)
	require.NoError(t, r.init())
	t.Cleanup(func() {
		_ = r.v4TCPMap.Map.Unpin()
		_ = r.v4AnyMap.Map.Unpin()
		_ = r.close()
	})

	entered := make(chan struct{})
	release := make(chan struct{})
	it.mu.Lock()
	orig := it.scan
	it.scan = func(m *Map, filterMap *ebpf.Map, prog *ebpf.Program, fltVal datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error) {
		close(entered)
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			return nil, 0, errors.New("timed out waiting to release blocked scan")
		}
		return orig(m, filterMap, prog, fltVal)
	}
	it.mu.Unlock()

	flt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: netip.MustParseAddr("10.244.12.1"), NetID: 0}: {}}}
	scanOK := make(chan bool, 1)
	go func() {
		_, ok := r.v4TCPMap.doScrub4WithIterator(flt, nil)
		scanOK <- ok
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for iterator scan to block")
	}

	closeErr := make(chan error, 1)
	go func() {
		closeErr <- r.close()
	}()

	// While the iterator scan is blocked, iterator-before-maps close order keeps r.close()
	// blocked on it.mu so active maps stay open.
	select {
	case err := <-closeErr:
		t.Fatalf("ctMaps.close() returned before iterator scan drained (err=%v)", err)
	case <-time.After(20 * time.Millisecond):
	}
	require.True(t, r.v4TCPMap.Map.IsOpen(), "v4TCPMap must stay open until iterator drains scan")
	require.True(t, r.v4AnyMap.Map.IsOpen(), "v4AnyMap must stay open until iterator drains scan")

	close(release)
	select {
	case ok := <-scanOK:
		require.True(t, ok, "in-flight iterator scan must succeed while maps remain open")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for iterator scan")
	}
	select {
	case err := <-closeErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ctMaps.close()")
	}

	require.False(t, it.tripped.Load())
	it.mu.Lock()
	require.Nil(t, it.prog)
	require.Nil(t, it.filterMap)
	it.mu.Unlock()
	require.False(t, r.v4TCPMap.Map.IsOpen())
	require.False(t, r.v4AnyMap.Map.IsOpen())
}

type countingStreamReader struct {
	r          io.Reader
	dataReads  int
	totalBytes int
}

func (c *countingStreamReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.dataReads++
		c.totalBytes += n
	}
	return n, err
}

func TestPrivilegedCTIterMultiReadAndPurge(t *testing.T) {
	setupCTMap(t)
	it := initCTIterOrSkip(t)
	scanCalls := wrapScanCounter(t, it)
	withTempCTMetrics(t)

	t.Run("MultiReadChunkResumeAndAlive", func(t *testing.T) {
		tcpMap, _, _ := openIsolatedCTAndNATMaps(t, "multi_read", 65536, it)
		nowSec := ctCurTimeSec(t)
		val := &CtEntry{Packets: 2, Bytes: 128, Lifetime: nowSec + 3600}

		targetPod := netip.MustParseAddr("10.244.15.42")
		targetArr := targetPod.As4()

		// Exceed ctIterReadChunkRecords (16 records = 224 B -> ~188 read() calls)
		// and CT_ITER_YIELD_INTERVAL (1,024 -> >=4 zero markers interleaved with
		// matches) to exercise real-kernel seq_file chunk boundary stop
		// (seq->count >= size), marker filtering across mixed chunks, and
		// multi-read() cursor resume without duplicate emission or alive drift.
		const (
			numMatches    = 3000
			numBystanders = 5000
		)
		for i := range numMatches {
			remote := types.IPv4{172, 19, byte(i >> 8), byte(i)}
			if i%2 == 0 {
				require.NoError(t, tcpMap.Map.Update(
					ctKey4(targetArr, remote, 443, uint16(20000+i), u8proto.TCP, tuple.TUPLE_F_OUT),
					val,
				))
			} else {
				require.NoError(t, tcpMap.Map.Update(
					ctKey4(remote, targetArr, uint16(20000+i), 8080, u8proto.TCP, tuple.TUPLE_F_IN),
					val,
				))
			}
		}

		bystanders := make([]*CtKey4Global, numBystanders)
		for i := range numBystanders {
			k := ctKey4(
				types.IPv4{10, 244, 16, byte(i >> 8)},
				types.IPv4{172, 20, byte(i >> 8), byte(i + 1)},
				8443, uint16(30000+i), u8proto.TCP, tuple.TUPLE_F_OUT,
			)
			bystanders[i] = k
			require.NoError(t, tcpMap.Map.Update(k, val))
		}

		callsBefore := scanCalls.Load()
		stats, ok := tcpMap.doScrub4WithIterator(GCFilter{
			MatchIPs: map[NetAddr]struct{}{{Addr: targetPod, NetID: 0}: {}},
		}, nil)
		require.True(t, ok)
		require.NoError(t, stats.dumpError)
		require.False(t, it.tripped.Load())
		require.Equal(t, callsBefore+1, scanCalls.Load())
		assertFilterMapSlotZeroed(t, it)
		require.Equal(t, uint32(numMatches), stats.deleted)
		require.Zero(t, stats.skipped, "multi-read resume must not emit duplicate keys")
		require.Equal(t, uint32(numBystanders), stats.aliveEntries)
		require.Equal(t, float64(numBystanders), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get())
		require.Equal(t, float64(numMatches), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsDeleted).Get())

		cnt, err := tcpMap.Count(t.Context())
		require.NoError(t, err)
		require.Equal(t, numBystanders, cnt)

		for i, k := range bystanders {
			_, err := tcpMap.Map.Lookup(k)
			require.NoError(t, err, "bystander key %d must survive multi-read scrub", i)
		}
	})

	t.Run("BoundedKernelPassZeroMatch", func(t *testing.T) {
		const numEntries = 20000 // > 16 * 1,024 = 16,384 non-matching entries per pass
		tcpMap, _, _ := openIsolatedCTAndNATMaps(t, "bounded_zero", 65536, it)
		nowSec := ctCurTimeSec(t)
		val := &CtEntry{Packets: 1, Bytes: 64, Lifetime: nowSec + 3600}

		for i := range numEntries {
			dst := types.IPv4{10, 245, byte(i >> 8), byte(i)}
			src := types.IPv4{172, 21, byte(i >> 8), byte(i)}
			require.NoError(t, tcpMap.Map.Update(
				ctKey4(dst, src, 8443, uint16(10000+(i%50000)), u8proto.TCP, tuple.TUPLE_F_OUT),
				val,
			))
		}

		absentPod := netip.MustParseAddr("10.244.17.99")
		filter := GCFilter{
			MatchIPs: map[NetAddr]struct{}{{Addr: absentPod, NetID: 0}: {}},
		}
		targetIP, ok := tcpMap.ctIteratorTargetIP(filter)
		require.True(t, ok)

		// Pin the bounded in-kernel pass directly against the real bpf_iter seq_file:
		// a >16K-entry 0-match scan must complete across >1 data read (via 1,024-entry
		// zero markers and 16-record reads) while filtering every marker and keeping
		// flt->alive exact.
		var dataReads int
		var markerBytes int
		candidates, rawAlive := func() ([]CtKey4Global, uint32) {
			it.mu.Lock()
			defer it.mu.Unlock()

			var zero uint32
			fltVal := buildCTIterFilter(targetIP)
			require.NoError(t, it.filterMap.Update(&zero, &fltVal, ebpf.UpdateAny))
			defer func() {
				var emptyFlt datapathbpf.CtScrubCtScrubFilter
				_ = it.filterMap.Update(&zero, &emptyFlt, ebpf.UpdateAny)
			}()

			iterLink, err := tcpMap.Map.AttachIter(it.prog)
			require.NoError(t, err)
			defer iterLink.Close()

			file, err := iterLink.Open()
			require.NoError(t, err)
			defer file.Close()

			probe := &countingStreamReader{r: file}
			cands, err := decodeCTIterStream(probe)
			require.NoError(t, err)
			dataReads = probe.dataReads
			markerBytes = probe.totalBytes

			var outFlt datapathbpf.CtScrubCtScrubFilter
			require.NoError(t, it.filterMap.Lookup(&zero, &outFlt))
			return cands, outFlt.Alive
		}()

		const wantMarkers = numEntries / 1024
		require.Greater(t, dataReads, 1, ">16K zero-match scan must yield after a bounded pass")
		require.Equal(t, wantMarkers*14, markerBytes)
		require.Nil(t, candidates, "zero markers must be filtered out leaving nil candidates")
		require.Equal(t, uint32(numEntries), rawAlive)

		callsBefore := scanCalls.Load()
		stats, ok := tcpMap.doScrub4WithIterator(filter, nil)
		require.True(t, ok)
		require.NoError(t, stats.dumpError)
		require.False(t, it.tripped.Load())
		require.Equal(t, callsBefore+1, scanCalls.Load())
		assertFilterMapSlotZeroed(t, it)
		require.Zero(t, stats.deleted)
		require.Zero(t, stats.skipped)
		require.Equal(t, uint32(numEntries), stats.aliveEntries)

		cnt, err := tcpMap.Count(t.Context())
		require.NoError(t, err)
		require.Equal(t, numEntries, cnt)
	})

	t.Run("PurgeNATDSRACTAndBatchParity", func(t *testing.T) {
		targetPod := netip.MustParseAddr("10.244.30.55")
		targetArr := targetPod.As4()
		otherPod := types.IPv4{10, 244, 30, 56}
		gw := types.IPv4{192, 0, 2, 1}

		runScenario := func(useIter bool) (deleted, remCT, remNAT int, failed4 [][2]uint32, gaugeAlive, gaugeDeleted float64) {
			var iterArg *ctIterator
			suffix := "purge_batch"
			if useIter {
				iterArg = it
				suffix = "purge_iter"
			}
			tcpMap, anyMap, natMap := openIsolatedCTAndNATMaps(t, suffix, 65536, iterArg)

			hook := &mockPurgeHook{}
			origACT := ACT
			ACT = hook
			defer func() { ACT = origACT }()

			nowSec := ctCurTimeSec(t)
			liveLifetime := nowSec + 3600
			expiredLifetime := uint32(0)
			if nowSec > 30 {
				expiredLifetime = nowSec - 30
			}

			for i := range 10 {
				seedSNATFlow(t, tcpMap, natMap, targetArr, types.IPv4{8, 8, 8, byte(i + 1)}, gw, uint16(30000+i), uint16(40000+i), u8proto.TCP, liveLifetime)
			}
			for i := range 6 {
				seedSNATFlow(t, tcpMap, natMap, otherPod, types.IPv4{8, 8, 4, byte(i + 1)}, gw, uint16(31000+i), uint16(41000+i), u8proto.TCP, liveLifetime)
			}

			// DSR reverse-NAT entry (Flags: DSRInternal -> DeleteSwappedMapping4).
			dsrClient := types.IPv4{1, 1, 1, 1}
			require.NoError(t, tcpMap.Map.Update(
				ctKey4(dsrClient, targetArr, 0x901f, 0x5704, u8proto.TCP, tuple.TUPLE_F_OUT),
				&CtEntry{Packets: 2, Bytes: 256, Lifetime: liveLifetime, Flags: DSRInternal},
			))
			dsrNatKey := &nat.NatKey4{TupleKey4Global: ctKey4(dsrClient, targetArr, 0x5704, 0x901f, u8proto.TCP, tuple.TUPLE_F_OUT).TupleKey4Global}
			require.NoError(t, natMap.Map.Update(dsrNatKey, &nat.NatEntry4{Created: 100, Addr: types.IPv4{2, 2, 2, 2}, Port: 0x50}))

			// TUPLE_F_SERVICE entry triggering ACT.CountFailed4.
			require.NoError(t, tcpMap.Map.Update(
				ctKey4(targetArr, types.IPv4{10, 96, 0, 10}, 80, 55123, u8proto.TCP, tuple.TUPLE_F_SERVICE),
				&CtEntry{Union0: [2]uint64{0, 777}, Packets: 1, Bytes: 60, Lifetime: liveLifetime, RevNAT: 42},
			))

			// Non-matching expired entry: IP-only scrub preserves it; RemoveExpired fallback deletes it.
			expiredOther := ctKey4(types.IPv4{10, 244, 31, 10}, types.IPv4{172, 20, 0, 3}, 443, 41003, u8proto.TCP, tuple.TUPLE_F_OUT)
			require.NoError(t, tcpMap.Map.Update(expiredOther, &CtEntry{Packets: 1, Bytes: 64, Lifetime: expiredLifetime}))

			// Also exercise Any4 map scrub.
			require.NoError(t, anyMap.Map.Update(
				ctKey4(targetArr, types.IPv4{172, 20, 0, 9}, 53, 41009, u8proto.UDP, tuple.TUPLE_F_OUT),
				&CtEntry{Packets: 1, Bytes: 64, Lifetime: liveLifetime},
			))

			mcast, next4, complete := stream.Multicast[GCEvent]()
			mcast.Observe(t.Context(), NatMapNext4, func(error) {})
			defer complete(nil)

			var err error
			flt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: targetPod, NetID: 0}: {}}}
			deleted, err = tcpMap.GC(flt, next4, nil)
			require.NoError(t, err)
			if useIter {
				assertFilterMapSlotZeroed(t, it)
			}

			gaugeAlive = metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get()
			gaugeDeleted = metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsDeleted).Get()

			require.True(t, natMap.IsOpen(), "global natMap must remain open after scrub")
			_, err = natMap.Map.Lookup(dsrNatKey)
			require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
			_, err = tcpMap.Map.Lookup(expiredOther)
			require.NoError(t, err, "IP-only scrub must preserve expired unrelated entries")

			delAny, err := anyMap.GC(flt, nil, nil)
			require.NoError(t, err)
			require.Equal(t, 1, delAny)

			// RemoveExpired=true must decline iterator and fall back to BatchIterate.
			delExp, err := tcpMap.GC(GCFilter{RemoveExpired: true, MatchIPs: flt.MatchIPs}, nil, nil)
			require.NoError(t, err)
			require.Equal(t, 1, delExp)
			_, err = tcpMap.Map.Lookup(expiredOther)
			require.ErrorIs(t, err, ebpf.ErrKeyNotExist)

			remCT, err = tcpMap.Count(t.Context())
			require.NoError(t, err)

			natDump := make(map[string][]string)
			require.NoError(t, natMap.Map.Dump(natDump))
			remNAT = len(natDump)

			hook.mu.Lock()
			failed4 = append(failed4, hook.failed4...)
			hook.mu.Unlock()
			return deleted, remCT, remNAT, failed4, gaugeAlive, gaugeDeleted
		}

		callsBeforeIter := scanCalls.Load()
		delIter, ctIter, natIter, actIter, aliveIter, delGaugeIter := runScenario(true)
		require.False(t, it.tripped.Load())
		require.Equal(t, callsBeforeIter+2, scanCalls.Load(), "iter scenario must invoke iterator scan for TCP4 and Any4 only")

		callsBeforeBatch := scanCalls.Load()
		delBatch, ctBatch, natBatch, actBatch, aliveBatch, delGaugeBatch := runScenario(false)
		require.Equal(t, callsBeforeBatch, scanCalls.Load())

		require.Equal(t, 12, delIter)
		require.Equal(t, 6, ctIter)
		require.Equal(t, 12, natIter)
		require.Equal(t, [][2]uint32{{42, 777}}, actIter)
		require.Equal(t, float64(7), aliveIter)
		require.Equal(t, float64(12), delGaugeIter)

		require.Equal(t, delBatch, delIter)
		require.Equal(t, ctBatch, ctIter)
		require.Equal(t, natBatch, natIter)
		require.Equal(t, actBatch, actIter)
		require.Equal(t, aliveBatch, aliveIter)
		require.Equal(t, delGaugeBatch, delGaugeIter)
	})

	t.Run("ConcurrentLRUEvictionTOCTOU", func(t *testing.T) {
		tcpMap, _, _ := openIsolatedCTAndNATMaps(t, "stale_lru", 65536, it)

		pinPath, err := tcpMap.Path()
		require.NoError(t, err)
		rawEBPFMap, err := ebpf.LoadPinnedMap(pinPath, nil)
		require.NoError(t, err)
		defer rawEBPFMap.Close()

		nowSec := ctCurTimeSec(t)
		targetPod := netip.MustParseAddr("10.244.40.10")
		targetArr := targetPod.As4()

		const (
			numTargetIP   = 8
			numToEvict    = 5
			numBystanders = 4
		)
		targetKeys := make([]*CtKey4Global, numTargetIP)
		for i := range numTargetIP {
			k := ctKey4(targetArr, types.IPv4{172, 18, 1, byte(i + 1)}, 443, uint16(30000+i), u8proto.TCP, tuple.TUPLE_F_OUT)
			targetKeys[i] = k
			require.NoError(t, tcpMap.Map.Update(k, &CtEntry{Packets: 1, Bytes: 100, Lifetime: nowSec + 600}))
		}
		for i := range numBystanders {
			k := ctKey4(types.IPv4{10, 244, 41, byte(i + 1)}, types.IPv4{172, 18, 2, byte(i + 1)}, 443, uint16(40000+i), u8proto.TCP, tuple.TUPLE_F_OUT)
			require.NoError(t, tcpMap.Map.Update(k, &CtEntry{Packets: 2, Bytes: 200, Lifetime: nowSec + 600}))
		}

		var evictOnce sync.Once
		var evictErr error
		var evicted int
		refreshedVal := CtEntry{Packets: 99, Bytes: 9900, Lifetime: nowSec + 7200}
		next4 := func(ev GCEvent) {
			evictOnce.Do(func() {
				firstDeleted := *(ev.Key.(*CtKey4Global))
				for _, k := range targetKeys {
					if *k == firstDeleted {
						continue
					}
					if evicted < numToEvict {
						evictErr = errors.Join(evictErr, rawEBPFMap.Delete(k))
						evicted++
					} else {
						evictErr = errors.Join(evictErr, rawEBPFMap.Update(k, &refreshedVal, ebpf.UpdateExist))
					}
				}
			})
		}

		callsBefore := scanCalls.Load()
		stats, ok := tcpMap.doScrub4WithIterator(GCFilter{
			MatchIPs: map[NetAddr]struct{}{{Addr: targetPod, NetID: 0}: {}},
		}, next4)
		require.True(t, ok)
		require.False(t, it.tripped.Load())
		require.Equal(t, callsBefore+1, scanCalls.Load())
		assertFilterMapSlotZeroed(t, it)
		require.NoError(t, evictErr)
		require.Equal(t, uint32(numToEvict), stats.skipped)
		require.Equal(t, uint32(numTargetIP-numToEvict), stats.deleted)
		require.Equal(t, uint32(numBystanders), stats.aliveEntries)
	})
}

type mockPurgeHook struct {
	mu      lock.Mutex
	failed4 [][2]uint32
}

func (h *mockPurgeHook) CountFailed4(revNAT uint16, backendID uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failed4 = append(h.failed4, [2]uint32{uint32(revNAT), backendID})
}

func (h *mockPurgeHook) CountFailed6(uint16, uint32) {}

func TestPrivilegedCTIterConcurrentGoroutineStress(t *testing.T) {
	setupCTMap(t)
	it := initCTIterOrSkip(t)
	scanCalls := wrapScanCounter(t, it)

	tcpMap, anyMap, natMap := openIsolatedCTAndNATMaps(t, "concurrent_stress", 131072, it)
	nowSec := ctCurTimeSec(t)
	liveLifetime := nowSec + 7200
	gw := types.IPv4{192, 0, 2, 10}

	const (
		numTargetPods = 16
		entriesPerPod = 20
		numZeroPods   = 4
		numBystanders = 200
	)

	for i := range numBystanders {
		k := ctKey4(types.IPv4{10, 244, 200, byte(i + 1)}, types.IPv4{198, 51, 100, byte(i%250 + 1)}, 443, uint16(15000+i), u8proto.TCP, tuple.TUPLE_F_OUT)
		anyK := *k
		anyK.NextHeader = u8proto.UDP
		require.NoError(t, tcpMap.Map.Update(k, &CtEntry{Packets: 2, Bytes: 200, Lifetime: liveLifetime}))
		require.NoError(t, anyMap.Map.Update(&anyK, &CtEntry{Packets: 2, Bytes: 200, Lifetime: liveLifetime}))
	}

	targetPods := make([]netip.Addr, numTargetPods)
	for p := range numTargetPods {
		podIP := netip.MustParseAddr(fmt.Sprintf("10.244.50.%d", p+1))
		targetPods[p] = podIP
		podArr := podIP.As4()

		for e := range entriesPerPod {
			sport := uint16(20000 + p*100 + e)
			snatPort := uint16(40000 + p*100 + e)
			remote := types.IPv4{203, 0, 113, byte(e + 1)}

			for _, mSpec := range []struct {
				m     *Map
				proto u8proto.U8proto
			}{
				{m: tcpMap, proto: u8proto.TCP},
				{m: anyMap, proto: u8proto.UDP},
			} {
				if e%2 == 0 {
					seedSNATFlow(t, mSpec.m, natMap, podArr, remote, gw, sport, snatPort, mSpec.proto, liveLifetime)
				} else {
					require.NoError(t, mSpec.m.Map.Update(
						ctKey4(remote, podArr, sport, 8080, mSpec.proto, tuple.TUPLE_F_IN),
						&CtEntry{Packets: 5, Bytes: 500, Lifetime: liveLifetime},
					))
				}
			}
		}
	}

	mcast, next4, complete := stream.Multicast[GCEvent]()
	mcast.Observe(t.Context(), NatMapNext4, func(error) {})
	defer complete(nil)

	type jobResult struct {
		deleted int
		want    int
		err     error
	}
	totalJobs := numTargetPods*2 + numZeroPods
	results := make([]jobResult, totalJobs)

	startBarrier := make(chan struct{})
	var ready atomic.Int32
	var wg sync.WaitGroup

	spawnScrub := func(jobIdx int, m *Map, podIP netip.Addr, wantDeleted int) {
		wg.Go(func() {
			flt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: podIP, NetID: 0}: {}}}
			ready.Add(1)
			<-startBarrier
			del, err := m.GC(flt, next4, nil)
			results[jobIdx] = jobResult{deleted: del, want: wantDeleted, err: err}
		})
	}

	job := 0
	for p := range numTargetPods {
		spawnScrub(job, tcpMap, targetPods[p], entriesPerPod)
		job++
		spawnScrub(job, anyMap, targetPods[p], entriesPerPod)
		job++
	}
	for z := range numZeroPods {
		targetM := tcpMap
		if z%2 == 1 {
			targetM = anyMap
		}
		spawnScrub(job, targetM, netip.MustParseAddr(fmt.Sprintf("10.244.99.%d", z+1)), 0)
		job++
	}

	for int(ready.Load()) < totalJobs {
		runtime.Gosched()
	}
	close(startBarrier)
	wg.Wait()
	require.False(t, it.tripped.Load())
	require.Equal(t, int64(totalJobs), scanCalls.Load())
	assertFilterMapSlotZeroed(t, it)

	for idx, res := range results {
		require.NoError(t, res.err, "goroutine %d", idx)
		require.Equal(t, res.want, res.deleted, "goroutine %d deleted mismatch", idx)
	}

	remTCP, err := tcpMap.Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, numBystanders, remTCP)

	remAny, err := anyMap.Count(t.Context())
	require.NoError(t, err)
	require.Equal(t, numBystanders, remAny)

	natDump := make(map[string][]string)
	require.NoError(t, natMap.Map.Dump(natDump))
	require.Empty(t, natDump)
}

func BenchmarkPrivilegedCTScrubVsBatch(b *testing.B) {
	nowSec := uint32(0)
	if now, err := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions()); err == nil {
		nowSec = uint32(now)
	}
	liveLifetime := nowSec + 7200
	targetIP := types.IPv4{10, 244, 77, 1}
	flt := GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: netip.AddrFrom4(targetIP), NetID: 0}: {}}}

	scenarios := []struct {
		name    string
		mapCap  int
		matches int
		useIter bool
	}{
		{name: "size=128Ki/matches=0/mode=iter", mapCap: 1 << 17, matches: 0, useIter: true},
		{name: "size=128Ki/matches=0/mode=batch", mapCap: 1 << 17, matches: 0, useIter: false},
		{name: "size=128Ki/matches=128/mode=iter", mapCap: 1 << 17, matches: 128, useIter: true},
		{name: "size=128Ki/matches=128/mode=batch", mapCap: 1 << 17, matches: 128, useIter: false},
		{name: "size=4Mi/matches=0/mode=iter", mapCap: 1 << 22, matches: 0, useIter: true},
		{name: "size=4Mi/matches=0/mode=batch", mapCap: 1 << 22, matches: 0, useIter: false},
		{name: "size=4Mi/matches=128/mode=iter", mapCap: 1 << 22, matches: 128, useIter: true},
		{name: "size=4Mi/matches=128/mode=batch", mapCap: 1 << 22, matches: 128, useIter: false},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			setupCTMap(b)

			var opts []MapOption
			var it *ctIterator
			if sc.useIter {
				it = newCTIterator(hivetest.Logger(b))
				if err := it.init(); err != nil {
					if errors.Is(err, ebpf.ErrNotSupported) {
						b.Skipf("BPF CT scrub iterator not supported by kernel: %v", err)
					}
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = it.close() })
				opts = append(opts, withCTIterator(it))
			}

			origAttr := mapInfo[mapTypeIPv4TCPGlobal]
			prevTCP := option.Config.CTMapEntriesGlobalTCP
			option.Config.CTMapEntriesGlobalTCP = sc.mapCap
			b.Cleanup(func() {
				option.Config.CTMapEntriesGlobalTCP = prevTCP
				mapInfo[mapTypeIPv4TCPGlobal] = origAttr
			})

			natMap := nat.NewMap(nil, "cilium_snat_v4_bench", nat.IPv4, sc.mapCap)
			require.NoError(b, natMap.OpenOrCreate())
			b.Cleanup(func() {
				_ = natMap.Map.Unpin()
				_ = natMap.Close()
			})
			mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{
				natMap:     natMap,
				natMapLock: &lock.Mutex{},
			}

			ctMap := newMap(MapNameTCP4Global+"_bench", mapTypeIPv4TCPGlobal, opts...)
			require.NoError(b, ctMap.OpenOrCreate())
			b.Cleanup(func() {
				_ = ctMap.Map.Unpin()
				_ = ctMap.Close()
			})

			fill := sc.mapCap * 3 / 4
			bystanderVal := &CtEntry{Packets: 4, Bytes: 512, Lifetime: liveLifetime}
			for i := range fill {
				dst := types.IPv4{10, byte((i >> 16) + 1), byte(i >> 8), byte(i)}
				src := types.IPv4{172, 24, byte(i >> 8), byte(i)}
				k := ctKey4(dst, src, 80, uint16(10000+(i%50000)), u8proto.TCP, tuple.TUPLE_F_OUT)
				if err := ctMap.Map.Update(k, bystanderVal); err != nil {
					b.Fatal(err)
				}
			}

			matchKeys := make([]*CtKey4Global, sc.matches)
			for j := range sc.matches {
				matchKeys[j] = ctKey4(targetIP, types.IPv4{172, 25, byte(j >> 8), byte(j)}, 443, uint16(20000+j), u8proto.TCP, tuple.TUPLE_F_OUT)
			}

			b.ResetTimer()
			for b.Loop() {
				if sc.matches > 0 {
					b.StopTimer()
					for _, mk := range matchKeys {
						if err := ctMap.Map.Update(mk, bystanderVal); err != nil {
							b.Fatal(err)
						}
					}
					b.StartTimer()
				}
				del, err := ctMap.GC(flt, nil, nil)
				if err != nil || del != sc.matches {
					b.Fatalf("scrub failed: del=%d want=%d err=%v", del, sc.matches, err)
				}
				if sc.useIter && it.tripped.Load() {
					b.Fatal("iterator unexpectedly tripped during benchmark")
				}
			}
		})
	}
}
