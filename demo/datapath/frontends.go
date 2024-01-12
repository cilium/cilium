package datapath

import (
	"net/netip"
	"time"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var frontendsCell = cell.Module(
	"frontends",
	"Frontends state, BPF map and reconciler",

	// Provide access to the frontend desired state to the rest of the
	// application with the 'Frontends' API that wraps Table[*Frontend]
	// and provides methods for manipulating the state.
	cell.Provide(NewFrontends),

	cell.ProvidePrivate(
		// The 'frontends' BPF map. Created and pinned at start.
		newFrontendsMap,

		// Privately provide the RWTable for the reconciler.
		func(fes Frontends) statedb.RWTable[*Frontend] {
			return fes.rw
		},

		newFrontendsReconcilerConfig,
	),

	// Create and register reconciler to reconcile objects from
	// Table[*Frontend] to the 'frontends' BPF map.
	cell.Invoke(reconciler.Register[*Frontend]),
)

// Frontends wraps RWTable[*Frontend] to provide a safe API for modifying
// the frontends table and deals with managing the referenced backends
// to maintain consistency.
type Frontends struct {
	statedb.Table[*Frontend]

	rw  statedb.RWTable[*Frontend]
	bes Backends
}

func NewFrontends(db *statedb.DB, bes Backends) (Frontends, statedb.Table[*Frontend], error) {
	tbl, err := statedb.NewTable[*Frontend](
		"frontends",
		FrontendIDIndex,
		FrontendAddrIndex,
		FrontendNameIndex,
	)
	if err != nil {
		return Frontends{}, nil, err
	}
	return Frontends{tbl, tbl, bes}, tbl, db.RegisterTable(tbl)
}

func (fes Frontends) UpdateBackends(txn statedb.WriteTxn, name string, newIDs ImmSet[BackendID]) {
	fe, _, ok := fes.First(txn, FrontendNameIndex.Query(name))
	if !ok {
		return
	}

	// Drop references to the removed backends
	for _, id := range fe.Backends.Difference(newIDs) {
		fes.bes.Release(txn, id, fe.Name)
	}

	fe.Status = reconciler.StatusPending()
	fe.Backends = newIDs
	fes.rw.Insert(txn, fe)
}

func (fes Frontends) Upsert(txn statedb.WriteTxn, meta FrontendMeta) ID {
	fe, _, ok := fes.First(txn, FrontendNameIndex.Query(meta.Name))
	if ok {
		fe = fe.Clone()
	} else {
		fe = &Frontend{
			// Use the revision that will be assigned to this object as the unique
			// identifier.
			ID: ID(fes.Revision(txn) + 1),
		}
	}
	fe.FrontendMeta = meta
	fe.Status = reconciler.StatusPending()
	fe.Backends = fes.bes.ReferencedBy(txn, meta.Name)
	fes.rw.Insert(txn, fe)

	return fe.ID
}

func (fes Frontends) Delete(txn statedb.WriteTxn, name string) bool {
	fe, _, ok := fes.First(txn, FrontendNameIndex.Query(name))
	if ok {
		// Drop references to the backends
		for _, id := range fe.Backends {
			fes.bes.Release(txn, id, name)
		}
		fe = fe.Clone()
		fe.Status = reconciler.StatusPendingDelete()
		fes.rw.Insert(txn, fe)
	}
	return ok
}

var (
	FrontendIDIndex   = newIDIndex[*Frontend](func(fe *Frontend) ID { return fe.ID })
	FrontendAddrIndex = statedb.Index[*Frontend, netip.Addr]{
		Name: "addr",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(fe.Addr))
		},
		FromKey: index.NetIPAddr,
		Unique:  true,
	}
	FrontendNameIndex = statedb.Index[*Frontend, string]{
		Name: "name",
		FromObject: func(fe *Frontend) index.KeySet {
			return index.NewKeySet(index.String(fe.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func newFrontendsReconcilerConfig(m frontendsMap, log logrus.FieldLogger) reconciler.Config[*Frontend] {
	ops := NewMapOps[*Frontend](m.Map, log)
	return reconciler.Config[*Frontend]{
		// Once a minute perform a full reconciliation which does full
		// refresh of the BPF map and deletes anything that shouldn't
		// be there. This recovers from outside manipulation of the BPF
		// map, but is of course expensive.
		FullReconcilationInterval: time.Minute,

		// The retry backoff durations control how often the reconciliation
		// of a failing object is retried. Each object will have its own
		// backoff.
		RetryBackoffMinDuration: 100 * time.Millisecond,
		RetryBackoffMaxDuration: time.Second,

		// The round size sets an upper limit for how many objects to reconcile
		// in one go. If batch operations are used, this is also the batch size
		// limit. If this is set very high and operations are slow, this will
		// delay the status updates. So in cases which status changes are followed
		// and low latency is preferred over higher throughput this should be set
		// quite low.
		IncrementalRoundSize: 1000,

		// GetObjectStatus tells the reconciler how to retrieve the status of the
		// object.
		GetObjectStatus: func(fe *Frontend) reconciler.Status {
			return fe.Status
		},

		// WithObjectStatus tells the reconciler how to update the status of the
		// object. It should return a copy of the object with the new status set.
		// Be sure to design the object in such a way that doing a shallow copy
		// is cheap (e.g. keep large unchanging data behind a pointer).
		WithObjectStatus: func(fe *Frontend, newStatus reconciler.Status) *Frontend {
			fe = fe.Clone()
			fe.Status = newStatus
			return fe
		},

		// RateLimiter throttles how often to reconcile changes. This is useful
		// with batch operations to give a higher chance of building larger batches.
		RateLimiter: nil,

		// Operations defines how to reconcile a single object.
		Operations: ops,

		// BatchOperations defines how to reconcile a batch of objects in one
		// go. This is optional.
		BatchOperations: nil,
	}
}

type frontendsMap struct{ *ebpf.Map }

func newFrontendsMap(lc hive.Lifecycle, log logrus.FieldLogger) frontendsMap {
	e := frontendsMap{
		Map: ebpf.NewMap(&ebpf.MapSpec{
			Name:       "frontends",
			Type:       ebpf.Hash,
			KeySize:    uint32(IDSize),
			ValueSize:  uint32(maxFrontendSize),
			MaxEntries: 10000,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		})}
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			return e.OpenOrCreate()
		},
	})
	return e
}
