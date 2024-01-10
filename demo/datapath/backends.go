package datapath

import (
	"time"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var backendsCell = cell.Module(
	"backends",
	"Backends state, BPF map and reconciler",

	cell.Provide(
		NewBackends,
	),

	cell.ProvidePrivate(
		newBackendsMap,
		func(bes Backends) statedb.RWTable[*Backend] {
			return bes.rw
		},
		newBackendsReconcilerConfig,
	),
	cell.Invoke(reconciler.Register[*Backend]),
)

// Backends wraps RWTable[*Backend] to provide a safe API for modifying
// the backends table.
type Backends struct {
	statedb.Table[*Backend]

	rw statedb.RWTable[*Backend]
}

func (bes Backends) ReferencedBy(txn statedb.ReadTxn, ref string) ImmSet[BackendID] {
	iter, _ := bes.Get(txn, BackendRefIndex.Query(ref))
	ids := statedb.Collect(statedb.Map(iter, func(b *Backend) BackendID { return b.ID }))
	return NewImmSet(ids...)
}

func (bes Backends) Upsert(txn statedb.WriteTxn, ref string, key BackendKey) BackendID {
	be, _, ok := bes.First(txn, BackendKeyIndex.Query(key))
	if !ok {
		be = &Backend{
			BackendKey: key,
			// Use the revision that will be assigned to this object as the unique
			// identifier.
			ID: ID(bes.Revision(txn) + 1),

			// Reconciliation only needed if the backend is new.
			Status: reconciler.StatusPending(),

			Refs: nil,
		}
	} else {
		be = be.Clone()
	}
	be.Refs = be.Refs.Insert(ref)

	bes.rw.Insert(txn, be)
	return be.ID
}

func (bes Backends) Delete(txn statedb.WriteTxn, k BackendKey) bool {
	fe, _, ok := bes.First(txn, BackendKeyIndex.Query(k))
	if ok {
		_, ok, _ = bes.rw.Delete(txn, fe)
	}
	return ok
}

func (bes Backends) Release(txn statedb.WriteTxn, id BackendID, ref string) {
	be, _, ok := bes.First(txn, BackendIDIndex.Query(id))
	if !ok {
		return
	}

	newRefs := be.Refs.Delete(ref)

	if len(newRefs) == 0 {
		bes.rw.Delete(txn, be)
	} else {
		be = be.Clone()
		be.Refs = newRefs
		bes.rw.Insert(txn, be)
	}
}

func (bes Backends) ReleaseAll(txn statedb.WriteTxn, ref string) {
	iter, _ := bes.Get(txn, BackendRefIndex.Query(ref))
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		newRefs := be.Refs.Delete(ref)

		if len(newRefs) == 0 {
			bes.rw.Delete(txn, be)
		} else {
			be = be.Clone()
			be.Refs = newRefs
			bes.rw.Insert(txn, be)
		}
	}
}

func NewBackends(db *statedb.DB) (Backends, statedb.Table[*Backend], error) {
	tbl, err := statedb.NewTable[*Backend](
		"backends",
		BackendIDIndex,
		BackendKeyIndex,
		BackendRefIndex,
	)
	if err != nil {
		return Backends{}, nil, err
	}
	return Backends{tbl, tbl}, tbl, db.RegisterTable(tbl)
}

var (
	BackendIDIndex  = newIDIndex[*Backend](func(be *Backend) ID { return be.ID })
	BackendKeyIndex = statedb.Index[*Backend, BackendKey]{
		Name: "key",
		FromObject: func(be *Backend) index.KeySet {
			return index.NewKeySet(be.BackendKey.IndexKey())
		},
		FromKey: BackendKey.IndexKey,
		Unique:  true,
	}
	BackendRefIndex = statedb.Index[*Backend, string]{
		Name: "ref",
		FromObject: func(be *Backend) index.KeySet {
			return index.StringSlice(be.Refs)
		},
		FromKey: index.String,
		Unique:  false,
	}
)

func newBackendsReconcilerConfig(m backendsMap) reconciler.Config[*Backend] {
	ops, batchOps := ops.NewMapOps[*Backend](m.Map)
	return reconciler.Config[*Backend]{
		// See newFrontendsReconcilerConfig for comments on these.
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Second,
		IncrementalRoundSize:      1000,
		GetObjectStatus: func(be *Backend) reconciler.Status {
			return be.Status
		},
		WithObjectStatus: func(be *Backend, newStatus reconciler.Status) *Backend {
			be = be.Clone()
			be.Status = newStatus
			return be
		},
		RateLimiter:     nil,
		Operations:      ops,
		BatchOperations: batchOps,
	}
}

type backendsMap struct{ *ebpf.Map }

func newBackendsMap(lc hive.Lifecycle, log logrus.FieldLogger) backendsMap {
	e := backendsMap{
		Map: ebpf.NewMap(&ebpf.MapSpec{
			Name:       "backends",
			Type:       ebpf.Hash,
			KeySize:    uint32(IDSize),
			ValueSize:  uint32(backendSize),
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
