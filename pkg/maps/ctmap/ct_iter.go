// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	datapathbpf "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// filterMatchIP must stay in sync with CT_FILTER_MATCH_IP in bpf/bpf_ct_scrub_iterator.c.
	filterMatchIP = 1 << 0

	// ctIterReadChunkRecords sizes the userspace stream buffer to 16 * 14 = 224 bytes.
	// Paired with CT_ITER_YIELD_INTERVAL (1,024) in bpf/bpf_ct_scrub_iterator.c,
	// each bpf_seq_read() pass stops after at most 16 * 1,024 = 16,384 non-matching
	// entries (~5 ms on a non-preemptible kernel; empty buckets are not paced) before
	// returning to userspace.
	ctIterReadChunkRecords = 16
)

// Compile-time binary wire layout assertions matching bpf/lib/ct_tuple.h
// and bpf/bpf_ct_scrub_iterator.c: 14-byte ipv4_ct_tuple and 12-byte ct_scrub_filter.
var (
	_ = [1]struct{}{}[int(unsafe.Sizeof(CtKey4Global{}))-14]
	_ = [1]struct{}{}[int(unsafe.Sizeof(datapathbpf.CtScrubCtScrubFilter{}))-12]
)

type ctIterScanFunc func(m *Map, filterMap *ebpf.Map, prog *ebpf.Program, fltVal datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error)

// ctIterator owns the singleton eBPF map-iterator program, its 1-slot filter
// map, and the scan mutex shared by the global IPv4 conntrack tables.
type ctIterator struct {
	logger *slog.Logger

	// mu serializes singleton filter map slot 0 programming, per-scan
	// iterator link attachment, stream consumption, and teardown in close().
	// Always released before userspace purge acquires natMapLock or globalDeleteLock.
	mu lock.Mutex

	filterMap *ebpf.Map
	prog      *ebpf.Program

	// tripped latches fallback to BatchIterate for the remainder of the
	// process lifetime after an init failure or runtime scan error.
	// Latching avoids taking it.mu or retrying scans on broken kernels.
	tripped atomic.Bool

	// scan executes iterator filter programming, stream decoding, and alive
	// count readback while mu is held. Overridable in tests.
	scan ctIterScanFunc
}

func newCTIterator(logger *slog.Logger) *ctIterator {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	it := &ctIterator{
		logger: logger,
	}
	it.scan = it.defaultScan
	return it
}

// init loads the BPF CT scrub iterator collection if not already loaded.
func (it *ctIterator) init() error {
	it.mu.Lock()
	defer it.mu.Unlock()

	if it.prog != nil {
		return nil
	}

	spec, err := datapathbpf.LoadCtScrub()
	if err != nil {
		it.tripped.Store(true)
		it.logger.Warn("BPF CT scrub iterator ELF load failed; falling back to batch conntrack scrub",
			logfields.Error, err)
		return err
	}

	var objs datapathbpf.CtScrubObjects
	commit, err := bpf.LoadAndAssign(it.logger, &objs, spec, &bpf.CollectionOptions{})
	if err != nil {
		it.tripped.Store(true)
		if errors.Is(err, ebpf.ErrNotSupported) {
			it.logger.Info("BPF CT scrub iterator not supported by kernel; using batch conntrack scrub",
				logfields.Error, err)
		} else {
			it.logger.Warn("BPF CT scrub iterator unavailable; falling back to batch conntrack scrub",
				logfields.Error, err)
		}
		return err
	}
	if err := commit(); err != nil {
		it.tripped.Store(true)
		_ = objs.Close()
		it.logger.Warn("BPF CT scrub iterator pin commit failed; falling back to batch conntrack scrub",
			logfields.Error, err)
		return err
	}

	it.filterMap = objs.CiliumCtFlt
	it.prog = objs.CilCt4Scrub
	it.tripped.Store(false)
	it.logger.Info("In-kernel eBPF conntrack scrub iterator initialized")
	return nil
}

// close releases the BPF CT scrub iterator program and filter map after
// draining any in-flight iterator scan.
func (it *ctIterator) close() error {
	it.mu.Lock()
	defer it.mu.Unlock()

	var errs []error
	if it.prog != nil {
		errs = append(errs, it.prog.Close())
		it.prog = nil
	}
	if it.filterMap != nil {
		errs = append(errs, it.filterMap.Close())
		it.filterMap = nil
	}
	return errors.Join(errs...)
}

func (m *Map) ctIteratorTargetIP(filter GCFilter) (uint32, bool) {
	if m.ctIter == nil || m.ctIter.tripped.Load() {
		return 0, false
	}
	// cil_ct4_scrub casts ctx->key to a 14-byte ipv4_ct_tuple; attaching it
	// to a 38-byte IPv6 CT map would pass the kernel's >=14B key-size attach
	// check and misparse IPv6 tuples.
	if !m.mapType.isIPv4() {
		return 0, false
	}
	// Conjunctive multi-cluster and multi-network gate: only global default-network maps.
	if m.clusterID != 0 || m.networkID != 0 {
		return 0, false
	}
	if filter.RemoveExpired || filter.EmitCTEntryCB != nil || len(filter.MatchIPs) == 0 {
		return 0, false
	}

	var targetIP netip.Addr
	var numIPv4s int
	for netAddr := range filter.MatchIPs {
		if !netAddr.Addr.IsValid() {
			continue
		}
		if netAddr.NetID != m.networkID {
			return 0, false
		}
		if netAddr.Addr.Is4() {
			numIPv4s++
			targetIP = netAddr.Addr
		}
	}
	if numIPv4s != 1 || !targetIP.IsValid() || targetIP.IsUnspecified() {
		return 0, false
	}

	ipBytes := targetIP.As4()
	return binary.NativeEndian.Uint32(ipBytes[:]), true
}

func buildCTIterFilter(targetIP uint32) datapathbpf.CtScrubCtScrubFilter {
	return datapathbpf.CtScrubCtScrubFilter{
		TargetIp:    targetIP,
		Alive:       0,
		FilterFlags: filterMatchIP,
	}
}

func (it *ctIterator) defaultScan(m *Map, filterMap *ebpf.Map, prog *ebpf.Program, fltVal datapathbpf.CtScrubCtScrubFilter) ([]CtKey4Global, uint32, error) {
	var zero uint32
	if err := filterMap.Update(&zero, &fltVal, ebpf.UpdateAny); err != nil {
		return nil, 0, fmt.Errorf("programming CT scrub iterator filter map: %w", err)
	}
	defer func() {
		var emptyFlt datapathbpf.CtScrubCtScrubFilter
		_ = filterMap.Update(&zero, &emptyFlt, ebpf.UpdateAny)
	}()

	iterLink, err := m.Map.AttachIter(prog)
	if err != nil {
		return nil, 0, fmt.Errorf("attaching CT scrub iterator program: %w", err)
	}
	defer iterLink.Close()

	file, err := iterLink.Open()
	if err != nil {
		return nil, 0, fmt.Errorf("opening CT scrub iterator stream: %w", err)
	}
	defer file.Close()

	candidates, err := decodeCTIterStream(file)
	if err != nil {
		return nil, 0, fmt.Errorf("reading CT scrub iterator stream: %w", err)
	}

	var outFlt datapathbpf.CtScrubCtScrubFilter
	if err := filterMap.Lookup(&zero, &outFlt); err != nil {
		return nil, 0, fmt.Errorf("reading CT scrub iterator alive counter: %w", err)
	}
	return candidates, outFlt.Alive, nil
}

func (m *Map) doScrub4WithIterator(filter GCFilter, next4 func(GCEvent)) (gcStats, bool) {
	targetIP, ok := m.ctIteratorTargetIP(filter)
	if !ok {
		return gcStats{}, false
	}

	it := m.ctIter
	fltVal := buildCTIterFilter(targetIP)

	// Iterator scan: In-kernel RCU traversal & filtering (zero natMapLock or globalDeleteLock held).
	var stats gcStats
	var candidates []CtKey4Global
	var alive uint32
	var scanErr error
	var abortedBeforeScan bool
	func() {
		it.mu.Lock()
		defer it.mu.Unlock()

		if it.tripped.Load() || it.prog == nil || it.filterMap == nil {
			abortedBeforeScan = true
			return
		}

		// Start scrub duration timer after acquiring it.mu, matching doGCForFamily
		// (which calls statStartGc after acquiring natMapLock).
		stats = statStartGc(m)

		candidates, alive, scanErr = it.scan(m, it.filterMap, it.prog, fltVal)
		if scanErr != nil {
			it.tripped.Store(true)
			it.logger.Warn("Disabling BPF CT scrub iterator after runtime scan error; falling back to batch conntrack scrub",
				logfields.Error, scanErr)
		}
	}()
	if abortedBeforeScan || scanErr != nil {
		return gcStats{}, false
	}

	stats.aliveEntries += alive

	// Userspace purge: Coordinated deletion under locks (skipped completely when 0 candidates match).
	if len(candidates) > 0 {
		func() {
			ctMapAttr := mapInfo[m.mapType]
			if ctMapAttr.natMapLock != nil {
				ctMapAttr.natMapLock.Lock()
				defer ctMapAttr.natMapLock.Unlock()
			}
			natMap := ctMapAttr.natMap

			globalDeleteLock[m.mapType].Lock()
			defer globalDeleteLock[m.mapType].Unlock()

			countFailedFn := countFailedFunc(false)
			scratch := &CtEntry{}
			for i := range candidates {
				m.purgeCtEntryAndRecord(&candidates[i], &candidates[i], scratch, filter, natMap, &stats, next4, countFailedFn)
			}
		}()
	}

	stats.Completed = true
	stats.finish()
	return stats, true
}

// decodeCTIterStream reads 14-byte CtKey4Global tuples from a bpf_iter seq_file
// until EOF.
//
// The scan is best-effort and gives a weaker guarantee than
// BPF_MAP_LOOKUP_BATCH, which copies each bucket under the bucket lock. The
// kernel iterator walks a bucket's chain under RCU only, so an entry that is
// present for the whole scan can be missed, or visited twice, in two cases:
//
//   - LRU maps are preallocated and reuse a freed element without waiting for
//     an RCU grace period. If the element the iterator is standing on is
//     evicted and relinked into another bucket, the walk follows that bucket's
//     chain and skips the rest of the original bucket.
//   - Between read() calls (every <= 16 emitted records) the iterator resumes by
//     (bucket_id, skip_elems), so an insertion or deletion in that bucket in
//     the meantime shifts its position by one element.
//
// Kernel bpf_map_elem omits BPF_ITER_RESCHED in bpf_seq_read(). To bound
// non-preemptible scan latency instead of running up to MAX_ITER_OBJECTS
// (1,000,000) elements per read(), bpf/bpf_ct_scrub_iterator.c emits an
// all-zero 14-byte marker every CT_ITER_YIELD_INTERVAL (1,024) non-matching
// entries. Combined with ctIterReadChunkRecords (16 records = 224 B << 32 KiB
// seq_file buffer), each bpf_seq_read() pass stops at seq->count >= size after
// at most 16,384 non-matching entries (~5 ms on a non-preemptible kernel;
// empty buckets are scanned in-loop without pacing, same as batch) and at most
// 16 matches without triggering -EOVERFLOW or -EAGAIN. Every successful read
// returns a whole multiple of 14 bytes (n == 0 is mapped to io.EOF by Go's
// os.File ZeroReadIsEOF; EINTR is handled inside poll.FD.Read).
//
// All-zero markers cannot collide with real matching entries because
// cil_ct4_scrub requires target_ip != 0 and matches saddr == target_ip ||
// daddr == target_ip; decodeCTIterStream discards all-zero records while
// keeping candidates == nil when no real matches exist.
//
// A missed entry is not deleted by this scan. When an IP is reused on the same
// node, both the deleted endpoint's scrub and the new endpoint's first
// regeneration scrub before attaching its datapath (pkg/endpoint/bpf.go) cover
// it. Across nodes, the old node only scrubs once on endpoint deletion, so a
// missed entry on that node persists until periodic GC removes it on expiry.
//
// A key emitted twice is harmless: the second purge finds it gone and counts
// it as skipped. A non-matching entry visited twice is counted twice in alive.
func decodeCTIterStream(file io.Reader) ([]CtKey4Global, error) {
	const recordSize = int(unsafe.Sizeof(CtKey4Global{}))
	backing := make([]CtKey4Global, ctIterReadChunkRecords)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&backing[0])), len(backing)*recordSize)
	var candidates []CtKey4Global

	for {
		n, err := file.Read(buf)
		if n > 0 {
			if n%recordSize != 0 {
				return candidates, fmt.Errorf("short CT iterator read (%d bytes, not a multiple of %d): %w", n, recordSize, io.ErrUnexpectedEOF)
			}
			numRecords := n / recordSize
			for i := range numRecords {
				k := backing[i]
				if k == (CtKey4Global{}) {
					continue
				}
				if candidates == nil {
					candidates = make([]CtKey4Global, 0, max(numRecords-i, 8))
				}
				candidates = append(candidates, k)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return candidates, nil
			}
			return candidates, err
		}
	}
}
