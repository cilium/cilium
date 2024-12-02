// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"iter"
	"strconv"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "nat-stats")

// Stats provides a implementation of performing nat map stats
// counting.
type Stats struct {
	metrics natMetrics

	db    *statedb.DB
	table statedb.RWTable[NatMapStats]

	maxPorts int
	config   Config
	natMap4  nat.NatMap4
	natMap6  nat.NatMap6

	observable4 stream.Observable[TupleCountIterator]
	next4       func(TupleCountIterator)
	complete4   func(error)

	observable6 stream.Observable[TupleCountIterator]
	next6       func(TupleCountIterator)
	complete6   func(error)
}

// Observable4 returns the state iteration observable for ipv4 nat.
func (s *Stats) Observable4() stream.Observable[TupleCountIterator] {
	return s.observable4
}

// Observable6 returns the state iteration observable for ipv6 nat.
func (s *Stats) Observable6() stream.Observable[TupleCountIterator] {
	return s.observable6
}

// TupleCountIterator is a k/v iterator type that allows for opaquely
// accessing a set of snat tuple source port counts.
// This is used by the exported Observable{4,6} streams to allow for
// external consumers to iterate over the current set of nat map stats
// following a countNat operation.
type TupleCountIterator iter.Seq2[SNATTupleAccessor, uint16]

// NatMapStats is a nat-map table entry key/value. This
// contains a count of connection 3-tuple utilization.
type NatMapStats struct {
	Type       string
	EgressIP   string
	EndpointIP string
	RemotePort uint16
	Proto      string
	Count      int
	Nth        int
}

func (s NatMapStats) Key() index.Key {
	k := index.String(s.Type + " " + s.EgressIP +
		" " + s.EndpointIP + ":")
	k = append(k, index.Uint16(s.RemotePort)...)
	return k
}

func (s NatMapStats) addrs() (string, string) {
	if s.Type == nat.IPv6.String() {
		return "[" + s.EgressIP + "]", "[" + s.EndpointIP + "]"
	}
	return s.EgressIP, s.EndpointIP
}

func (NatMapStats) TableHeader() []string {
	return []string{"IPFamily", "Proto", "EgressIP", "RemoteAddr", "Count"}
}

func (s NatMapStats) TableRow() []string {
	var raddr string
	eip, rip := s.addrs()
	if s.RemotePort == 0 {
		raddr = rip
	} else {
		raddr = fmt.Sprintf("%s:%d", rip, s.RemotePort)
	}
	return []string{s.Type, s.Proto, eip, raddr, strconv.Itoa(s.Count)}
}

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
	DB        *statedb.DB
	Table     statedb.RWTable[NatMapStats]
	NatMap4   promise.Promise[nat.NatMap4]
	NatMap6   promise.Promise[nat.NatMap6]
	Jobs      job.Group
	Metrics   natMetrics
	Config    Config
	Health    cell.Health
}

func newStats(params params) (*Stats, error) {
	if err := probes.HaveBatchAPI(); err != nil {
		if errors.Is(err, probes.ErrNotSupported) {
			log.WithError(err).Info("nat-stats is not supported")
			return nil, nil
		}
		log.WithError(err).Error("could not probe for nat-stats feature")
	}

	if params.Config.NATMapStatInterval == 0 {
		return nil, nil
	}

	if params.Config.NatMapStatKStoredEntries > maxNatMapStatKStoredEntries ||
		params.Config.NatMapStatKStoredEntries < minNatMapStatKStoredEntries {
		return nil, fmt.Errorf("nat-stats config: %q must be between [%d, %d]",
			natMapStatsEntriesName, minNatMapStatKStoredEntries, maxNatMapStatKStoredEntries)
	}

	// number of available source-ports is ephemeral range subtracting those
	// used by node-ports.
	maxAvailPorts := config.NodePortMaxNAT - (option.Config.NodePortMax + 1)
	m := &Stats{
		metrics:  params.Metrics,
		config:   params.Config,
		maxPorts: maxAvailPorts,
		db:       params.DB,
		table:    params.Table,
	}

	m.observable4, m.next4, m.complete4 =
		stream.Multicast[TupleCountIterator]()
	m.observable6, m.next6, m.complete6 =
		stream.Multicast[TupleCountIterator]()

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*120)
			defer cancel()
			nmap4, err := params.NatMap4.Await(ctx)
			if err != nil {
				if !errors.Is(err, nat.MapDisabled) {
					return err
				}
			}
			nmap6, err := params.NatMap6.Await(ctx)
			if err != nil {
				if !errors.Is(err, nat.MapDisabled) {
					return err
				}
			}
			m.natMap4 = nmap4
			m.natMap6 = nmap6
			if m.natMap4 == nil && m.natMap6 == nil {
				return nil
			}

			tr := job.NewTrigger()
			params.Jobs.Add(job.Timer("nat-stats", m.countNat, params.Config.NATMapStatInterval,
				job.WithTrigger(tr)))
			// Wait a couple seconds, and then trigger the initial count.
			// This is to give time for init time CT/NAT gc scanning to complete
			// to avoid NAT map GC timeouts at startup.
			go func() {
				<-time.After(5 * time.Second)
				tr.Trigger()
			}()
			return params.Jobs.Start(hc)
		},
		OnStop: func(hc cell.HookContext) error {
			m.complete4(nil)
			m.complete6(nil)
			return nil
		},
	})
	return m, nil
}

func upsertStat(m *Stats, topk *topk, family nat.IPFamily) error {
	tx := m.db.WriteTxn(m.table)
	defer tx.Abort()

	var errs error
	for entry := range m.table.All(tx) {
		if entry.Type == family.String() {
			_, _, err := m.table.Delete(tx, entry)
			errors.Join(errs, err)
		}
	}

	topk.popForEach(func(key SNATTupleAccessor, count, ith int) {
		if ith == 1 {
			m.metrics.updateLocalPorts(family, count, m.maxPorts)
		}
		endpointIP, rport := key.GetEndpointAddr()
		egressIP, _ := key.GetEgressAddr()
		proto := key.GetProto()
		_, _, err := m.table.Insert(tx, NatMapStats{
			Type:       family.String(),
			EgressIP:   egressIP.String(),
			EndpointIP: endpointIP.String(),
			RemotePort: rport,
			Proto:      proto.String(),
			Count:      count,
		})
		if err != nil {
			errs = errors.Join(errs, err)
		}
	})
	if errs != nil {
		return fmt.Errorf("failures occurred updating stats table, transaction will not be committed: %w", errs)
	}
	tx.Commit()
	return nil
}

func flagsIsIn(flags uint8) bool {
	return flags&tuple.TUPLE_F_IN == tuple.TUPLE_F_IN
}

func (m *Stats) countNat(ctx context.Context) error {
	var errs error
	if m.natMap4 != nil {
		tupleToPortCount := make(map[SNATTuple4]uint16, 128)
		_, err := m.natMap4.DumpBatch4(func(k *tuple.TupleKey4, _ *nat.NatEntry4) {
			key := *k.ToHost().(*tuple.TupleKey4)
			if flagsIsIn(key.Flags) &&
				(key.NextHeader == u8proto.TCP || key.NextHeader == u8proto.ICMP ||
					key.NextHeader == u8proto.UDP) {
				key.DestPort = 0
				ports := tupleToPortCount[SNATTuple4(key)]
				ports++
				tupleToPortCount[SNATTuple4(key)] = ports
			}
		})

		if err != nil {
			log.WithError(err).
				Error("failed to count ipv4 nat map entries, " +
					"this may result in out of date nat-stats data and nat_endpoint_ metrics")
			errs = errors.Join(errs, err)
		} else {
			m.next4(toIter(tupleToPortCount))
			topk := newTopK(m.config.NatMapStatKStoredEntries)
			for tupleKey, bucket := range tupleToPortCount {
				topk.Push(tupleKey, int(bucket))
			}
			errors.Join(errs, upsertStat(m, topk, nat.IPv4))
		}

	}
	if m.natMap6 != nil {
		tupleToPortCount := make(map[SNATTuple6]uint16, 128)
		_, err := m.natMap6.DumpBatch6(func(k *tuple.TupleKey6, _ *nat.NatEntry6) {
			key := *k.ToHost().(*tuple.TupleKey6)
			if flagsIsIn(key.Flags) &&
				(key.NextHeader == u8proto.TCP || key.NextHeader == u8proto.ICMPv6 ||
					key.NextHeader == u8proto.UDP) {
				key.DestPort = 0
				ports := tupleToPortCount[SNATTuple6(key)]
				ports++
				tupleToPortCount[SNATTuple6(key)] = ports
			}
		})

		if err != nil {
			log.WithError(err).
				Error("failed to count ipv6 nat map entries, " +
					"this may result in out of date nat-stats data and nat_endpoint_ metrics")
			errs = errors.Join(errs, err)
		} else {
			m.next6(toIter(tupleToPortCount))
			topk := newTopK(m.config.NatMapStatKStoredEntries)
			for tupleKey, bucket := range tupleToPortCount {
				topk.Push(tupleKey, int(bucket))
			}
			errors.Join(errs, upsertStat(m, topk, nat.IPv6))
		}
	}
	return errs
}

type tupleBucket struct {
	key   SNATTupleAccessor
	count int
}

type topk struct {
	mq      *minQueue
	k, size int
}

func newTopK(k int) *topk {
	mq := make(minQueue, 0, k)
	heap.Init(&mq)
	return &topk{mq: &mq, k: k}
}

func (t *topk) Push(key SNATTupleAccessor, count int) {
	heap.Push(t.mq, tupleBucket{key: key, count: count})
	t.size++
	if t.size > t.k {
		heap.Pop(t.mq)
		t.size--
	}
}

func (t *topk) popForEach(fn func(key SNATTupleAccessor, count, ith int)) {
	for i := 0; i < t.size; i++ {
		tuple := heap.Pop(t.mq).(tupleBucket)
		fn(tuple.key, tuple.count, t.size-i)
	}
	t.size = 0
}

type minQueue []tupleBucket

func (pq minQueue) Len() int { return len(pq) }

func (pq minQueue) Less(i, j int) bool {
	return pq[i].count < pq[j].count
}

func (pq minQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *minQueue) Push(x any) {
	*pq = append(*pq, x.(tupleBucket))
}

func (pq *minQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}
