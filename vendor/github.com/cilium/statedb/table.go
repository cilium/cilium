// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"iter"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/statedb/internal"
	"github.com/cilium/statedb/part"
	"go.yaml.in/yaml/v3"

	"github.com/cilium/statedb/index"
)

// NewTable creates a new table with given name and indexes.
// Can fail if the indexes or the name are malformed.
// The name must match regex "^[a-z][a-z0-9_\\-]{0,30}$".
//
// To provide access to the table via Hive:
//
//	cell.Provide(
//		// Provide statedb.RWTable[*MyObject]. Often only provided to the module with ProvidePrivate.
//		statedb.NewTable[*MyObject]("my-objects", MyObjectIDIndex, MyObjectNameIndex),
//		// Provide the read-only statedb.Table[*MyObject].
//		statedb.RWTable[*MyObject].ToTable,
//	)
func NewTable[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) (RWTable[Obj], error) {
	if err := validateTableName(tableName); err != nil {
		return nil, err
	}

	toAnyIndexer := func(idx Indexer[Obj]) anyIndexer {
		return anyIndexer{
			name: idx.indexName(),
			fromObject: func(iobj object) index.KeySet {
				return idx.fromObject(iobj.data.(Obj))
			},
			fromString: idx.fromString,
			unique:     idx.isUnique(),
		}
	}

	table := &genTable[Obj]{
		table:                tableName,
		smu:                  internal.NewSortableMutex(),
		primaryAnyIndexer:    toAnyIndexer(primaryIndexer),
		primaryIndexer:       primaryIndexer,
		secondaryAnyIndexers: make(map[string]anyIndexer, len(secondaryIndexers)),
		indexPositions:       make(map[string]int),
		pos:                  -1,
	}

	table.indexPositions[primaryIndexer.indexName()] = PrimaryIndexPos

	// Internal indexes
	table.indexPositions[RevisionIndex] = RevisionIndexPos
	table.indexPositions[GraveyardIndex] = GraveyardIndexPos
	table.indexPositions[GraveyardRevisionIndex] = GraveyardRevisionIndexPos

	indexPos := SecondaryIndexStartPos
	for _, indexer := range secondaryIndexers {
		name := indexer.indexName()
		anyIndexer := toAnyIndexer(indexer)
		anyIndexer.pos = indexPos
		table.secondaryAnyIndexers[name] = anyIndexer
		table.indexPositions[name] = indexPos
		indexPos++
	}

	// Primary index must always be unique
	if !primaryIndexer.isUnique() {
		return nil, tableError(tableName, ErrPrimaryIndexNotUnique)
	}

	// Validate that indexes have unique ids.
	indexNames := map[string]struct{}{}
	indexNames[primaryIndexer.indexName()] = struct{}{}
	for _, indexer := range secondaryIndexers {
		if _, ok := indexNames[indexer.indexName()]; ok {
			return nil, tableError(tableName, fmt.Errorf("index %q: %w", indexer.indexName(), ErrDuplicateIndex))
		}
		indexNames[indexer.indexName()] = struct{}{}
	}
	for name := range indexNames {
		if strings.HasPrefix(name, reservedIndexPrefix) {
			return nil, tableError(tableName, fmt.Errorf("index %q: %w", name, ErrReservedPrefix))
		}
	}
	return table, nil
}

// MustNewTable creates a new table with given name and indexes.
// Panics if indexes are malformed.
func MustNewTable[Obj any](
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj]) RWTable[Obj] {
	t, err := NewTable(tableName, primaryIndexer, secondaryIndexers...)
	if err != nil {
		panic(err)
	}
	return t
}

var nameRegex = regexp.MustCompile(`^[a-z][a-z0-9_\-]{0,30}$`)

func validateTableName(name string) error {
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("invalid table name %q, expected to match %q", name, nameRegex)
	}
	return nil
}

type genTable[Obj any] struct {
	pos                  int
	table                TableName
	smu                  internal.SortableMutex
	primaryIndexer       Indexer[Obj]
	primaryAnyIndexer    anyIndexer
	secondaryAnyIndexers map[string]anyIndexer
	indexPositions       map[string]int
	lastWriteTxn         atomic.Pointer[writeTxn]
}

func (t *genTable[Obj]) acquired(txn *writeTxn) {
	t.lastWriteTxn.Store(txn)
}

func (t *genTable[Obj]) getAcquiredInfo() string {
	return t.lastWriteTxn.Load().acquiredInfo()
}

func (t *genTable[Obj]) tableEntry() tableEntry {
	var entry tableEntry
	entry.meta = t
	entry.deleteTrackers = part.New[anyDeleteTracker]()

	// A new table is initialized, as no initializers are registered.
	entry.initialized = true
	entry.initWatchChan = make(chan struct{})
	close(entry.initWatchChan)

	entry.indexes = make([]indexEntry, len(t.indexPositions))
	entry.indexes[t.indexPositions[t.primaryIndexer.indexName()]] = indexEntry{part.New[object](), nil, nil, true}

	for index, indexer := range t.secondaryAnyIndexers {
		entry.indexes[t.indexPositions[index]] = indexEntry{part.New[object](), nil, nil, indexer.unique}
	}
	// For revision indexes we only need to watch the root.
	entry.indexes[t.indexPositions[RevisionIndex]] = indexEntry{part.New[object](part.RootOnlyWatch), nil, nil, true}
	entry.indexes[t.indexPositions[GraveyardRevisionIndex]] = indexEntry{part.New[object](part.RootOnlyWatch), nil, nil, true}
	entry.indexes[t.indexPositions[GraveyardIndex]] = indexEntry{part.New[object](), nil, nil, true}

	return entry
}

func (t *genTable[Obj]) setTablePos(pos int) {
	t.pos = pos
}

func (t *genTable[Obj]) tablePos() int {
	return t.pos
}

func (t *genTable[Obj]) tableKey() []byte {
	return []byte(t.table)
}

func (t *genTable[Obj]) indexPos(name string) int {
	if t.primaryAnyIndexer.name == name {
		return PrimaryIndexPos
	}
	return t.indexPositions[name]
}

func (t *genTable[Obj]) getIndexer(name string) *anyIndexer {
	if name == "" || t.primaryAnyIndexer.name == name {
		return &t.primaryAnyIndexer
	}
	if indexer, ok := t.secondaryAnyIndexers[name]; ok {
		return &indexer
	}
	return nil
}

func (t *genTable[Obj]) PrimaryIndexer() Indexer[Obj] {
	return t.primaryIndexer
}

func (t *genTable[Obj]) primary() anyIndexer {
	return t.primaryAnyIndexer
}

func (t *genTable[Obj]) secondary() map[string]anyIndexer {
	return t.secondaryAnyIndexers
}

func (t *genTable[Obj]) Name() string {
	return t.table
}

func (t *genTable[Obj]) Indexes() []string {
	idxs := make([]string, 0, 1+len(t.secondaryAnyIndexers))
	idxs = append(idxs, t.primaryAnyIndexer.name)
	for k := range t.secondaryAnyIndexers {
		idxs = append(idxs, k)
	}
	sort.Strings(idxs)
	return idxs
}

func (t *genTable[Obj]) ToTable() Table[Obj] {
	return t
}

func (t *genTable[Obj]) Initialized(txn ReadTxn) (bool, <-chan struct{}) {
	table := txn.getTableEntry(t)
	return len(table.pendingInitializers) == 0, table.initWatchChan
}

func (t *genTable[Obj]) PendingInitializers(txn ReadTxn) []string {
	return txn.getTableEntry(t).pendingInitializers
}

func (t *genTable[Obj]) RegisterInitializer(txn WriteTxn, name string) func(WriteTxn) {
	table := txn.getTxn().modifiedTables[t.pos]
	if table != nil {
		if slices.Contains(table.pendingInitializers, name) {
			panic(fmt.Sprintf("RegisterInitializer: %q already registered", name))
		}

		if len(table.pendingInitializers) == 0 {
			table.initialized = false
			table.initWatchChan = make(chan struct{})
		}

		table.pendingInitializers =
			append(slices.Clone(table.pendingInitializers), name)
		var once sync.Once
		return func(txn WriteTxn) {
			once.Do(func() {
				if table := txn.getTxn().modifiedTables[t.pos]; table != nil {
					table.pendingInitializers = slices.DeleteFunc(
						slices.Clone(table.pendingInitializers),
						func(n string) bool { return n == name },
					)
				} else {
					panic(fmt.Sprintf("RegisterInitializer/MarkDone: Table %q not locked for writing", t.table))
				}
			})
		}
	} else {
		panic(fmt.Sprintf("RegisterInitializer: Table %q not locked for writing", t.table))
	}
}

func (t *genTable[Obj]) Revision(txn ReadTxn) Revision {
	return txn.getTableEntry(t).revision
}

func (t *genTable[Obj]) NumObjects(txn ReadTxn) int {
	table := txn.getTableEntry(t)
	return table.numObjects()
}

func (t *genTable[Obj]) numDeletedObjects(txn ReadTxn) int {
	table := txn.getTableEntry(t)
	return table.numDeletedObjects()
}

func (t *genTable[Obj]) Get(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, ok bool) {
	obj, revision, _, ok = t.GetWatch(txn, q)
	return
}

func (t *genTable[Obj]) GetWatch(txn ReadTxn, q Query[Obj]) (obj Obj, revision uint64, watch <-chan struct{}, ok bool) {
	indexPos := t.indexPos(q.index)
	var (
		ops    part.Ops[object]
		unique bool
	)
	if wtxn, ok := txn.(WriteTxn); ok {
		itxn := wtxn.getTxn()
		if itxn.modifiedTables != nil {
			if table := itxn.modifiedTables[t.tablePos()]; table != nil {
				// Since we're not returning an iterator here we can optimize and not use
				// indexReadTxn which clones if this is a WriteTxn (to avoid invalidating iterators).
				indexEntry := &table.indexes[indexPos]
				if indexEntry.txn != nil {
					ops = indexEntry.txn
				} else {
					ops = indexEntry.tree
				}
				unique = indexEntry.unique
			}
		}
	}

	if ops == nil {
		entry := txn.root()[t.tablePos()].indexes[indexPos]
		ops = entry.tree
		unique = entry.unique
	}

	var iobj object
	if unique {
		// On a unique index we can do a direct get rather than a prefix search.
		iobj, watch, ok = ops.Get(q.key)
		if !ok {
			return
		}
		obj = iobj.data.(Obj)
		revision = iobj.revision
		return
	}

	// For a non-unique index we need to do a prefix search.
	iter, watch := ops.Prefix(q.key)
	for {
		var key []byte
		key, iobj, ok = iter.Next()
		if !ok {
			break
		}

		// Check that we have a full match on the key
		if nonUniqueKey(key).secondaryLen() == len(q.key) {
			break
		}
	}

	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func (t *genTable[Obj]) LowerBound(txn ReadTxn, q Query[Obj]) iter.Seq2[Obj, Revision] {
	iter, _ := t.LowerBoundWatch(txn, q)
	return iter
}

func (t *genTable[Obj]) LowerBoundWatch(txn ReadTxn, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, t.indexPos(q.index))
	// Since LowerBound query may be invalidated by changes in another branch
	// of the tree, we cannot just simply watch the node we seeked to. Instead
	// we watch the whole table for changes.
	watch := indexTxn.RootWatch()
	iter := indexTxn.LowerBound(q.key)
	if indexTxn.unique {
		return partSeq[Obj](iter), watch
	}
	return nonUniqueLowerBoundSeq[Obj](iter, q.key), watch
}

func (t *genTable[Obj]) Prefix(txn ReadTxn, q Query[Obj]) iter.Seq2[Obj, Revision] {
	iter, _ := t.PrefixWatch(txn, q)
	return iter
}

func (t *genTable[Obj]) PrefixWatch(txn ReadTxn, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, t.indexPos(q.index))
	iter, watch := indexTxn.Prefix(q.key)
	if indexTxn.unique {
		return partSeq[Obj](iter), watch
	}
	return nonUniqueSeq[Obj](iter, true, q.key), watch
}

func (t *genTable[Obj]) All(txn ReadTxn) iter.Seq2[Obj, Revision] {
	iter, _ := t.AllWatch(txn)
	return iter
}

func (t *genTable[Obj]) AllWatch(txn ReadTxn) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, PrimaryIndexPos)
	return partSeq[Obj](indexTxn.Iterator()), indexTxn.RootWatch()
}

func (t *genTable[Obj]) List(txn ReadTxn, q Query[Obj]) iter.Seq2[Obj, Revision] {
	iter, _ := t.ListWatch(txn, q)
	return iter
}

func (t *genTable[Obj]) ListWatch(txn ReadTxn, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, t.indexPos(q.index))
	if indexTxn.unique {
		// Unique index means that there can be only a single matching object.
		// Doing a Get() is more efficient than constructing an iterator.
		value, watch, ok := indexTxn.Get(q.key)
		seq := func(yield func(Obj, Revision) bool) {
			if ok {
				yield(value.data.(Obj), value.revision)
			}
		}
		return seq, watch
	}

	// For a non-unique index we do a prefix search. The keys are of
	// form <secondary key><primary key><secondary key length>, and thus the
	// iteration will continue until key length mismatches, e.g. we hit a
	// longer key sharing the same prefix.
	iter, watch := indexTxn.Prefix(q.key)
	return nonUniqueSeq[Obj](iter, false, q.key), watch
}

func (t *genTable[Obj]) Insert(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	oldObj, hadOld, _, err = t.InsertWatch(txn, obj)
	return
}

func (t *genTable[Obj]) InsertWatch(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, watch <-chan struct{}, err error) {
	var old object
	old, hadOld, watch, err = txn.getTxn().insert(t, Revision(0), obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) Modify(txn WriteTxn, obj Obj, merge func(old, new Obj) Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, _, err = txn.getTxn().modify(t, Revision(0), obj,
		func(old any) any {
			return merge(old.(Obj), obj)
		})
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndSwap(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, _, err = txn.getTxn().insert(t, rev, obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) Delete(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, err = txn.getTxn().delete(t, Revision(0), obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndDelete(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, err = txn.getTxn().delete(t, rev, obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) DeleteAll(txn WriteTxn) error {
	itxn := txn.getTxn()
	for obj := range t.All(txn) {
		_, _, err := itxn.delete(t, Revision(0), obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *genTable[Obj]) Changes(txn WriteTxn) (ChangeIterator[Obj], error) {
	iter := &changeIterator[Obj]{
		revision: 0,

		// Don't observe any past deletions.
		deleteRevision: t.Revision(txn),
		table:          t,
		watch:          closedWatchChannel,
	}
	// Set a finalizer to unregister the delete tracker when the iterator
	// is dropped.
	runtime.SetFinalizer(iter, func(iter *changeIterator[Obj]) {
		iter.close()
	})

	itxn := txn.getTxn()
	name := fmt.Sprintf("changes-%p", iter)
	iter.dt = &deleteTracker[Obj]{
		db:          itxn.db,
		trackerName: name,
		table:       t,
	}

	iter.dt.setRevision(iter.deleteRevision)
	err := itxn.addDeleteTracker(t, name, iter.dt)
	if err != nil {
		return nil, err
	}

	// Prime it.
	iter.refresh(txn)

	return iter, nil
}

// anyChanges returns the anyChangeIterator. Used for implementing the /changes HTTP
// API where we can't work with concrete object types as they're not known and thus
// uninstantiatable.
func (t *genTable[Obj]) anyChanges(txn WriteTxn) (anyChangeIterator, error) {
	iter, err := t.Changes(txn)
	if err != nil {
		return nil, err
	}
	return iter.(*changeIterator[Obj]), err
}

func (t *genTable[Obj]) sortableMutex() internal.SortableMutex {
	return t.smu
}

func (t *genTable[Obj]) proto() any {
	var zero Obj
	return zero
}

func (t *genTable[Obj]) unmarshalYAML(data []byte) (any, error) {
	var obj Obj
	if err := yaml.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

var _ Table[bool] = &genTable[bool]{}
var _ RWTable[bool] = &genTable[bool]{}
