// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	datapathbpf "github.com/cilium/cilium/pkg/datapath/bpf"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/hive"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func newMockCTIter(t *testing.T, fltMap *ebpf.Map, prog *ebpf.Program) *ctIterator {
	t.Helper()
	it := newCTIterator(hivetest.Logger(t))
	it.filterMap = fltMap
	it.prog = prog
	return it
}

func newTestCTMap(t *testing.T, name string, mt mapType, it *ctIterator) *Map {
	t.Helper()
	m := newMap(name, mt, withCTIterator(it))
	m.Logger = hivetest.Logger(t)
	return m
}

func withTempCTMetrics(t *testing.T) {
	t.Helper()
	origSize := metrics.ConntrackGCSize
	origRuns := metrics.ConntrackGCRuns
	metrics.ConntrackGCSize = metric.NewGaugeVec(metric.GaugeOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.SubsystemDatapath,
		Name:      "conntrack_gc_entries",
	}, []string{metrics.LabelDatapathFamily, metrics.LabelProtocol, metrics.LabelStatus})
	metrics.ConntrackGCRuns = metric.NewCounterVec(metric.CounterOpts{
		Namespace: metrics.Namespace,
		Subsystem: metrics.SubsystemDatapath,
		Name:      "conntrack_gc_runs_total",
	}, []string{metrics.LabelDatapathFamily, metrics.LabelProtocol, metrics.LabelStatus})
	t.Cleanup(func() {
		metrics.ConntrackGCSize = origSize
		metrics.ConntrackGCRuns = origRuns
	})
}

func preserveMapInfo(t *testing.T) {
	t.Helper()
	orig := map[mapType]mapAttributes{
		mapTypeIPv4TCPGlobal: mapInfo[mapTypeIPv4TCPGlobal],
		mapTypeIPv4AnyGlobal: mapInfo[mapTypeIPv4AnyGlobal],
		mapTypeIPv6TCPGlobal: mapInfo[mapTypeIPv6TCPGlobal],
		mapTypeIPv6AnyGlobal: mapInfo[mapTypeIPv6AnyGlobal],
	}
	t.Cleanup(func() {
		maps.Copy(mapInfo, orig)
	})
}

func TestCTIterStructLayoutAndSpecsAndEndianness(t *testing.T) {
	require.Equal(t, uintptr(14), unsafe.Sizeof(CtKey4Global{}))
	require.Equal(t, 16, ctIterReadChunkRecords)
	require.Equal(t, 224, ctIterReadChunkRecords*int(unsafe.Sizeof(CtKey4Global{})))

	// Generated CtScrubCtScrubFilter wire layout: 12 bytes matching C struct ct_scrub_filter.
	require.Equal(t, uintptr(12), unsafe.Sizeof(datapathbpf.CtScrubCtScrubFilter{}))
	require.Equal(t, uintptr(0), unsafe.Offsetof(datapathbpf.CtScrubCtScrubFilter{}.TargetIp))
	require.Equal(t, uintptr(4), unsafe.Offsetof(datapathbpf.CtScrubCtScrubFilter{}.Alive))
	require.Equal(t, uintptr(8), unsafe.Offsetof(datapathbpf.CtScrubCtScrubFilter{}.FilterFlags))
	require.Equal(t, uintptr(10), unsafe.Offsetof(datapathbpf.CtScrubCtScrubFilter{}.Pad))

	spec, err := datapathbpf.LoadCtScrub()
	require.NoError(t, err)
	require.Len(t, spec.Maps, 1, "BPF iterator ELF must contain only cilium_ct_flt")
	fltMapSpec, ok := spec.Maps[datapathbpf.CtScrubMapCiliumCtFlt]
	require.True(t, ok)
	require.Equal(t, ebpf.Array, fltMapSpec.Type)
	require.Equal(t, uint32(1), fltMapSpec.MaxEntries)
	require.Equal(t, uint32(4), fltMapSpec.KeySize)
	require.Equal(t, uint32(12), fltMapSpec.ValueSize)
	require.Equal(t, ebpf.PinNone, fltMapSpec.Pinning)
	require.Empty(t, spec.Variables)
	require.Contains(t, spec.Programs, datapathbpf.CtScrubProgCilCt4Scrub)

	// Asymmetric octets verify native-endian uint32 encoding matches C __be32 bytes on the wire.
	it := newMockCTIter(t, &ebpf.Map{}, &ebpf.Program{})
	m := newTestCTMap(t, MapNameTCP4Global+"_endian", mapTypeIPv4TCPGlobal, it)
	rawIP, ok := m.ctIteratorTargetIP(GCFilter{
		MatchIPs: map[NetAddr]struct{}{{Addr: netip.MustParseAddr("10.244.3.99"), NetID: 0}: {}},
	})
	require.True(t, ok)
	flt := buildCTIterFilter(rawIP)
	require.Equal(t, uint16(filterMatchIP), flt.FilterFlags)
	require.Zero(t, flt.Alive)
	require.Zero(t, flt.Pad)

	fltBytes := unsafe.Slice((*byte)(unsafe.Pointer(&flt)), unsafe.Sizeof(flt))
	require.Equal(t, []byte{10, 244, 3, 99}, fltBytes[:4])
}

func TestCTIterConfigFlags(t *testing.T) {
	require.Equal(t, "conntrack-scrub-bpf-iterator", conntrackScrubBPFIteratorName)
	require.True(t, defaultConfig.ConntrackScrubBPFIterator)

	fs := pflag.NewFlagSet("ctmap-test", pflag.ContinueOnError)
	defaultConfig.Flags(fs)
	flag := fs.Lookup(conntrackScrubBPFIteratorName)
	require.NotNil(t, flag)
	require.Equal(t, "true", flag.DefValue)
	require.True(t, flag.Hidden)

	var cfg Config
	fs2 := pflag.NewFlagSet("ctmap-parse", pflag.ContinueOnError)
	cfg.Flags(fs2)
	require.NoError(t, fs2.Parse([]string{"--" + conntrackScrubBPFIteratorName + "=false"}))
	val, err := fs2.GetBool(conntrackScrubBPFIteratorName)
	require.NoError(t, err)
	require.False(t, val)
}

func newStartedTestMapRegistry(t *testing.T) *mapregistry.MapRegistry {
	t.Helper()
	var reg *mapregistry.MapRegistry
	h := hive.New(
		mapregistry.Cell,
		cell.Invoke(func(r *mapregistry.MapRegistry) {
			reg = r
		}),
	)
	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() {
		require.NoError(t, h.Stop(tlog, context.Background()))
	})
	return reg
}

func TestCTMapsIteratorWiring(t *testing.T) {
	preserveMapInfo(t)
	logger := hivetest.Logger(t)
	reg := newStartedTestMapRegistry(t)

	// Enabled dual-stack: newCTMaps allocates one *ctIterator; registry-created
	// IPv4 maps share it while IPv6 maps stay nil.
	cfgDual := &option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: true,
	}
	outOn := newCTMaps(logger, &cell.DefaultLifecycle{}, Config{ConntrackScrubBPFIterator: true}, cfgDual, nil, reg, nil, nil)
	rOn := outOn.Map.(*ctMaps)
	require.NotNil(t, rOn.ctIter)

	v4TCP, err := newCTMapFromRegistry(reg, datapathmaps.CiliumCT4Global, mapTypeIPv4TCPGlobal, nil, withCTIterator(rOn.ctIter))
	require.NoError(t, err)
	v4Any, err := newCTMapFromRegistry(reg, datapathmaps.CiliumCTAny4Global, mapTypeIPv4AnyGlobal, nil, withCTIterator(rOn.ctIter))
	require.NoError(t, err)
	v6TCP, err := newCTMapFromRegistry(reg, datapathmaps.CiliumCT6Global, mapTypeIPv6TCPGlobal, nil)
	require.NoError(t, err)
	require.Same(t, rOn.ctIter, v4TCP.ctIter)
	require.Same(t, rOn.ctIter, v4Any.ctIter)
	require.Nil(t, v6TCP.ctIter)

	// Flag disabled: ctIter is nil and withCTIterator(nil) leaves maps nil.
	outOff := newCTMaps(logger, &cell.DefaultLifecycle{}, Config{ConntrackScrubBPFIterator: false}, cfgDual, nil, reg, nil, nil)
	rOff := outOff.Map.(*ctMaps)
	require.Nil(t, rOff.ctIter)
	v4TCPDisabled, err := newCTMapFromRegistry(reg, datapathmaps.CiliumCT4Global, mapTypeIPv4TCPGlobal, nil, withCTIterator(rOff.ctIter))
	require.NoError(t, err)
	require.Nil(t, v4TCPDisabled.ctIter)

	// IPv4 disabled: no iterator allocated even when flag is true.
	cfgV6Only := &option.DaemonConfig{
		EnableIPv4: false,
		EnableIPv6: true,
	}
	outV6Only := newCTMaps(logger, &cell.DefaultLifecycle{}, Config{ConntrackScrubBPFIterator: true}, cfgV6Only, nil, reg, nil, nil)
	rV6Only := outV6Only.Map.(*ctMaps)
	require.Nil(t, rV6Only.ctIter)
}

func TestCTMapsCloseWaitsForInFlightScan(t *testing.T) {
	preserveMapInfo(t)
	logger := hivetest.Logger(t)

	daemonCfg := &option.DaemonConfig{
		EnableIPv4: true,
	}
	out := newCTMaps(logger, &cell.DefaultLifecycle{}, Config{ConntrackScrubBPFIterator: true}, daemonCfg, nil, nil, nil, nil)
	r := out.Map.(*ctMaps)
	it := r.ctIter
	require.NotNil(t, it)
	r.v4TCPMap = newTestCTMap(t, MapNameTCP4Global+"_close_wait", mapTypeIPv4TCPGlobal, it)
	r.v4AnyMap = newTestCTMap(t, MapNameAny4Global+"_close_wait", mapTypeIPv4AnyGlobal, it)

	entered := make(chan struct{})
	release := make(chan struct{})
	var scanCalls int

	it.mu.Lock()
	it.prog = &ebpf.Program{}
	it.filterMap = &ebpf.Map{}
	it.scan = func(*Map, *ebpf.Map, *ebpf.Program, datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error) {
		scanCalls++
		close(entered)
		<-release
		// Clear non-kernel dummy handles before releasing mu so it.close() does
		// not call Close() on zero-value ebpf structs; real-handle teardown
		// order is pinned by TestPrivilegedCTMapsCloseOrder.
		it.prog = nil
		it.filterMap = nil
		return nil, 0, nil
	}
	it.mu.Unlock()

	filter := GCFilter{
		MatchIPs: map[NetAddr]struct{}{{Addr: netip.MustParseAddr("10.244.9.10"), NetID: 0}: {}},
	}

	scanDone := make(chan bool, 1)
	go func() {
		_, ok := r.v4TCPMap.doScrub4WithIterator(filter, nil)
		scanDone <- ok
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for in-flight iterator scan to start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- r.close()
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("ctMaps.close() returned before in-flight iterator scan finished (err=%v)", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	select {
	case ok := <-scanDone:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for iterator scan to finish")
	}
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ctMaps.close() to return")
	}

	// Post-close scrubs decline without re-entering scan.
	_, okAfter := r.v4TCPMap.doScrub4WithIterator(filter, nil)
	require.False(t, okAfter)
	require.Equal(t, 1, scanCalls)
}

func TestCTIteratorTargetIPMatrix(t *testing.T) {
	logger := hivetest.Logger(t)
	gateMap := func(mt mapType, clusterID, networkID uint32) *Map {
		return &Map{
			Map:       &bpf.Map{Logger: logger},
			mapType:   mt,
			clusterID: clusterID,
			networkID: networkID,
		}
	}

	podIP := netip.MustParseAddr("10.244.1.42")
	podIP2 := netip.MustParseAddr("10.244.1.43")
	podIPv6 := netip.MustParseAddr("fd00::42")
	ipBytes := podIP.As4()
	wantRawIP := binary.NativeEndian.Uint32(ipBytes[:])

	singleV4Filter := GCFilter{
		MatchIPs: map[NetAddr]struct{}{{Addr: podIP, NetID: 0}: {}},
	}

	tests := []struct {
		name    string
		nilIter bool
		tripped bool
		m       *Map
		filter  GCFilter
		wantOK  bool
		wantIP  uint32
	}{
		{
			name:   "valid single IPv4 on TCP4 global map",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: singleV4Filter,
			wantOK: true,
			wantIP: wantRawIP,
		},
		{
			name:   "valid single IPv4 on Any4 global map",
			m:      gateMap(mapTypeIPv4AnyGlobal, 0, 0),
			filter: singleV4Filter,
			wantOK: true,
			wantIP: wantRawIP,
		},
		{
			name: "valid single IPv4 alongside IPv6 and zero-value Addr",
			m:    gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{
				MatchIPs: map[NetAddr]struct{}{
					{Addr: podIP, NetID: 0}:         {},
					{Addr: podIPv6, NetID: 0}:       {},
					{Addr: netip.Addr{}, NetID: 0}:  {},
					{Addr: netip.Addr{}, NetID: 99}: {},
				},
			},
			wantOK: true,
			wantIP: wantRawIP,
		},
		{
			name:   "reject nil MatchIPs",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{},
		},
		{
			name:   "reject empty MatchIPs",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{MatchIPs: map[NetAddr]struct{}{}},
		},
		{
			name:   "reject RemoveExpired with valid IP",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{RemoveExpired: true, Time: 1000, MatchIPs: singleV4Filter.MatchIPs},
		},
		{
			name:   "reject unspecified IPv4 0.0.0.0",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: netip.IPv4Unspecified(), NetID: 0}: {}}},
		},
		{
			name:   "reject IPv6-only MatchIPs",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: podIPv6, NetID: 0}: {}}},
		},
		{
			name: "reject multiple IPv4 addresses",
			m:    gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{
				MatchIPs: map[NetAddr]struct{}{
					{Addr: podIP, NetID: 0}:  {},
					{Addr: podIP2, NetID: 0}: {},
				},
			},
		},
		{
			name:   "reject IPv6 map",
			m:      gateMap(mapTypeIPv6TCPGlobal, 0, 0),
			filter: singleV4Filter,
		},
		{
			name:   "reject clusterID != 0",
			m:      gateMap(mapTypeIPv4TCPGlobal, 2, 0),
			filter: singleV4Filter,
		},
		{
			name:   "reject networkID != 0 even when NetAddr matches",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 7),
			filter: GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: podIP, NetID: 7}: {}}},
		},
		{
			name:   "reject NetAddr.NetID mismatch",
			m:      gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{MatchIPs: map[NetAddr]struct{}{{Addr: podIP, NetID: 7}: {}}},
		},
		{
			name: "reject NetAddr.NetID mismatch on IPv6 entry",
			m:    gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{
				MatchIPs: map[NetAddr]struct{}{
					{Addr: podIP, NetID: 0}:   {},
					{Addr: podIPv6, NetID: 7}: {},
				},
			},
		},
		{
			name: "reject EmitCTEntryCB != nil",
			m:    gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter: GCFilter{
				MatchIPs:      singleV4Filter.MatchIPs,
				EmitCTEntryCB: func(NetAddr, NetAddr, uint16, uint16, uint8, uint8, *CtEntry) {},
			},
		},
		{
			name:    "reject nil iterator handle",
			nilIter: true,
			m:       gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter:  singleV4Filter,
		},
		{
			name:    "reject tripped circuit breaker",
			tripped: true,
			m:       gateMap(mapTypeIPv4TCPGlobal, 0, 0),
			filter:  singleV4Filter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.m.Logger = logger
			if !tt.nilIter {
				it := newMockCTIter(t, &ebpf.Map{}, &ebpf.Program{})
				it.tripped.Store(tt.tripped)
				tt.m.ctIter = it
			}

			gotIP, ok := tt.m.ctIteratorTargetIP(tt.filter)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantIP, gotIP)
		})
	}
}

type chunkedReader struct {
	r    io.Reader
	size int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if len(p) > c.size {
		p = p[:c.size]
	}
	return c.r.Read(p)
}

type repeatingReader struct {
	err   error
	calls int
}

func (r *repeatingReader) Read([]byte) (int, error) {
	r.calls++
	return 0, r.err
}

func makeTestIterKeys(t *testing.T, count int) ([]CtKey4Global, []byte) {
	t.Helper()
	var raw bytes.Buffer
	keys := make([]CtKey4Global, count)
	for i := range count {
		dst := types.IPv4{10, byte(i >> 16), byte(i >> 8), byte(i)}
		src := types.IPv4{192, 168, byte((i >> 8) & 0x7f), byte(i%250 + 1)}
		switch i {
		case 0:
			// Exercise zero DestAddr with non-zero SourceAddr so partial zero-marker checks fail.
			dst = types.IPv4{}
		case 1:
			// Exercise non-zero DestAddr with zero SourceAddr as well.
			src = types.IPv4{}
		}
		k := CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					DestAddr:   dst,
					SourceAddr: src,
					DestPort:   uint16(80 + (i % 1000)),
					SourcePort: uint16(10000 + (i % 50000)),
					NextHeader: u8proto.TCP,
					Flags:      tuple.TUPLE_F_OUT,
				},
			},
		}
		keys[i] = k
		rawBytes := unsafe.Slice((*byte)(unsafe.Pointer(&k)), unsafe.Sizeof(k))
		_, err := raw.Write(rawBytes)
		require.NoError(t, err)
	}
	return keys, raw.Bytes()
}

func TestDecodeCTIterStream(t *testing.T) {
	t.Run("multi-chunk reads and zero marker filtering", func(t *testing.T) {
		expected, rawBytes := makeTestIterKeys(t, 50)

		gotDirect, err := decodeCTIterStream(bytes.NewReader(rawBytes))
		require.NoError(t, err)
		require.Equal(t, expected, gotDirect)

		gotExact, err := decodeCTIterStream(bytes.NewReader(rawBytes[:ctIterReadChunkRecords*14]))
		require.NoError(t, err)
		require.Equal(t, expected[:ctIterReadChunkRecords], gotExact)

		zeroMarkers := make([]byte, 35*14)
		gotZeros, err := decodeCTIterStream(bytes.NewReader(zeroMarkers))
		require.NoError(t, err)
		require.Nil(t, gotZeros)

		zeroRec := make([]byte, 14)
		var interleaved bytes.Buffer
		for range 17 {
			interleaved.Write(zeroRec)
		}
		interleaved.Write(rawBytes[:5*14])
		interleaved.Write(zeroRec)
		interleaved.Write(zeroRec)
		interleaved.Write(rawBytes[5*14 : 25*14])
		for range 16 {
			interleaved.Write(zeroRec)
		}
		interleaved.Write(rawBytes[25*14:])
		for range 3 {
			interleaved.Write(zeroRec)
		}
		gotInterleaved, err := decodeCTIterStream(&chunkedReader{
			r:    bytes.NewReader(interleaved.Bytes()),
			size: 14 * 3,
		})
		require.NoError(t, err)
		require.Equal(t, expected, gotInterleaved)
	})

	t.Run("read error propagation", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := decodeCTIterStream(&repeatingReader{err: boom})
		require.ErrorIs(t, err, boom)
	})

	t.Run("misaligned record read returns io.ErrUnexpectedEOF", func(t *testing.T) {
		_, chunkPlusTrailing := makeTestIterKeys(t, ctIterReadChunkRecords+1)
		gotPartial, err := decodeCTIterStream(bytes.NewReader(chunkPlusTrailing[:ctIterReadChunkRecords*14+7]))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Len(t, gotPartial, ctIterReadChunkRecords)
	})
}

func TestCTIterAliveAndCircuitBreakerFallback(t *testing.T) {
	withTempCTMetrics(t)

	it := newMockCTIter(t, &ebpf.Map{}, &ebpf.Program{})
	m := newTestCTMap(t, MapNameTCP4Global+"_cb_unit", mapTypeIPv4TCPGlobal, it)
	filter := GCFilter{
		MatchIPs: map[NetAddr]struct{}{{Addr: netip.MustParseAddr("10.244.9.1"), NetID: 0}: {}},
	}

	var calls int
	aliveRet := uint32(137)
	var errRet error
	it.scan = func(*Map, *ebpf.Map, *ebpf.Program, datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error) {
		calls++
		return nil, aliveRet, errRet
	}

	stats, ok := m.doScrub4WithIterator(filter, nil)
	require.True(t, ok)
	require.Equal(t, uint32(137), stats.aliveEntries)
	require.Equal(t, float64(137), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get())
	require.Equal(t, float64(1), metrics.ConntrackGCRuns.WithLabelValues("ipv4", "TCP", "completed").Get())

	aliveRet = 0
	stats, ok = m.doScrub4WithIterator(filter, nil)
	require.True(t, ok)
	require.Zero(t, stats.aliveEntries)
	require.Equal(t, float64(0), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get())
	require.Equal(t, float64(2), metrics.ConntrackGCRuns.WithLabelValues("ipv4", "TCP", "completed").Get())

	// Seed a non-zero alive sentinel before tripping the breaker so a spurious zeroing fails.
	aliveRet = 42
	stats, ok = m.doScrub4WithIterator(filter, nil)
	require.True(t, ok)
	require.Equal(t, uint32(42), stats.aliveEntries)
	require.Equal(t, float64(42), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get())
	require.Equal(t, float64(3), metrics.ConntrackGCRuns.WithLabelValues("ipv4", "TCP", "completed").Get())

	// Scan failure trips breaker and leaves gauges and run counters untouched.
	errRet = io.ErrUnexpectedEOF
	aliveRet = 88
	_, ok = m.doScrub4WithIterator(filter, nil)
	require.False(t, ok)
	require.Equal(t, 4, calls)
	require.True(t, it.tripped.Load())
	require.Equal(t, float64(3), metrics.ConntrackGCRuns.WithLabelValues("ipv4", "TCP", "completed").Get())
	require.Zero(t, metrics.ConntrackGCRuns.WithLabelValues("ipv4", "TCP", "uncompleted").Get())
	require.Equal(t, float64(42), metrics.ConntrackGCSize.WithLabelValues("ipv4", "TCP", metricsAlive).Get())

	// Subsequent doGC bypasses iterator scan via tripped and falls back to BatchIterate
	// (which fails to open the unpinned map).
	_, err := m.doGC(filter, nil, nil)
	require.Error(t, err)
	require.Equal(t, 4, calls)
}
