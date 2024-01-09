package datapath

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"
)

var tablesCell = cell.Module(
	"tables",
	"Demo datapath tables",

	cell.Provide(
		NewFrontends,
		NewBackends,
	),
)

// Frontends wraps RWTable[*Frontend] to provide a safe API for modifying
// the frontends table and deals with managing the referenced backends
// to maintain consistency.
type Frontends struct {
	statedb.Table[*Frontend]

	rw  statedb.RWTable[*Frontend]
	bes Backends
}

func (fes Frontends) Upsert(txn statedb.WriteTxn, fe *Frontend) ID {
	orig, _, ok := fes.First(txn, FrontendNameIndex.Query(fe.Name))
	if ok {
		fe.ID = orig.ID

		// Drop references to the removed backends
		for _, id := range orig.Backends.Difference(fe.Backends) {
			fes.bes.Release(txn, id, fe.Name)
		}
	} else {
		// Use the revision that will be assigned to this object as the unique
		// identifier.
		fe.ID = ID(fes.Revision(txn) + 1)
	}
	fe.Status = reconciler.StatusPending()
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
		fes.rw.Delete(txn, fe)
	}
	return ok
}

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
	be = be.Clone()
	be.Refs = be.Refs.Delete(ref)

	if len(be.Refs) == 0 {
		bes.rw.Delete(txn, be)
	} else {
		bes.rw.Insert(txn, be)
	}
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

func newIDIndex[T any](getID func(T) ID) statedb.Index[T, ID] {
	return statedb.Index[T, ID]{
		Name: "id",
		FromObject: func(x T) index.KeySet {
			return index.NewKeySet(index.Uint64(uint64(getID(x))))
		},
		FromKey: func(id ID) index.Key {
			return index.Uint64(uint64(id))
		},
		Unique: true,
	}
}

// ImmSet is an immutable set optimized for a smallish set of items.
// Implemented as a sorted slice.
type ImmSet[T constraints.Ordered] []T

func NewImmSet[T constraints.Ordered](items ...T) ImmSet[T] {
	s := ImmSet[T](items)
	slices.Sort(s)
	return s
}

func (s ImmSet[T]) Has(x T) bool {
	_, found := slices.BinarySearch(s, x)
	return found
}

func (s ImmSet[T]) Insert(x T) ImmSet[T] {
	idx, found := slices.BinarySearch(s, x)
	if found {
		return s
	}
	return slices.Insert(slices.Clone(s), idx, x)
}

func (s ImmSet[T]) Delete(x T) ImmSet[T] {
	idx, found := slices.BinarySearch(s, x)
	if found {
		return slices.Delete(slices.Clone(s), idx, idx+1)
	}
	return s
}

func (s ImmSet[T]) Union(s2 ImmSet[T]) ImmSet[T] {
	result := make(ImmSet[T], 0, len(s)+len(s2))
	copy(result, s)
	copy(result[len(s):], s2)
	slices.Sort(result)
	return result
}

func (s ImmSet[T]) Difference(s2 ImmSet[T]) ImmSet[T] {
	result := ImmSet[T]{}
	for _, x := range s {
		if !s2.Has(x) {
			result = result.Insert(x)
		}
	}
	return result
}
