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
	"time"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/internal"
	"github.com/cilium/statedb/part"
	"go.yaml.in/yaml/v3"
)

// NewTable creates a new table with given name and indexes, and registers it
// with the database. Can fail if the indexes or the name are malformed, or a
// table with the same name is already registered.
// The name must match regex "^[a-z][a-z0-9_\\-]{0,30}$".
//
// To provide access to the table via Hive:
//
//	cell.Provide(
//		// Provide statedb.RWTable[*MyObject]. Often only provided to the module with ProvidePrivate.
//		func(db *statedb.DB) (statedb.RWTable[*MyObject], error) {
//			return NewTable(db, "my-objects", MyObjectIDIndex, MyObjectNameIndex)
//		},
//		// Provide the read-only statedb.Table[*MyObject].
//		statedb.RWTable[*MyObject].ToTable,
//	)
func NewTable[Obj TableWritable](
	db *DB,
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj],
) (RWTable[Obj], error) {
	var obj Obj
	return NewTableAny[Obj](
		db,
		tableName,
		obj.TableHeader,
		Obj.TableRow,
		primaryIndexer,
		secondaryIndexers...,
	)
}

// MustNewTable creates a new table with given name and indexes, and registers
// it with the database. Panics if indexes are malformed, or a table with the
// same name is already registered.
func MustNewTable[Obj TableWritable](
	db *DB,
	tableName TableName,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj]) RWTable[Obj] {
	t, err := NewTable(db, tableName, primaryIndexer, secondaryIndexers...)
	if err != nil {
		panic(err)
	}
	return t
}

// NewTableAny creates a new table for any type object with the given table
// header and row functions.
func NewTableAny[Obj any](
	db *DB,
	tableName TableName,
	tableHeader func() []string,
	tableRow func(Obj) []string,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj]) (RWTable[Obj], error) {
	if err := validateTableName(tableName); err != nil {
		return nil, err
	}

	toAnyIndexer := func(idx Indexer[Obj], pos int) anyIndexer {
		return anyIndexer{
			name:          idx.indexName(),
			fromString:    idx.fromString,
			newTableIndex: idx.newTableIndex,
			pos:           pos,
		}
	}

	table := &genTable[Obj]{
		table:                tableName,
		smu:                  internal.NewSortableMutex(),
		primaryAnyIndexer:    toAnyIndexer(primaryIndexer, PrimaryIndexPos),
		primaryIndexer:       primaryIndexer,
		secondaryAnyIndexers: make([]anyIndexer, 0, len(secondaryIndexers)),
		indexPositions:       make([]string, SecondaryIndexStartPos+len(secondaryIndexers)),
		pos:                  -1,
		tableHeaderFunc:      tableHeader,
		tableRowFunc:         tableRow,
	}

	// Internal indexes
	table.indexPositions[RevisionIndexPos] = RevisionIndex
	table.indexPositions[GraveyardIndexPos] = GraveyardIndex
	table.indexPositions[GraveyardRevisionIndexPos] = GraveyardRevisionIndex

	table.indexPositions[PrimaryIndexPos] = primaryIndexer.indexName()

	indexPos := SecondaryIndexStartPos
	for _, indexer := range secondaryIndexers {
		name := indexer.indexName()
		anyIndexer := toAnyIndexer(indexer, indexPos)
		table.secondaryAnyIndexers = append(table.secondaryAnyIndexers, anyIndexer)
		table.indexPositions[indexPos] = name
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
	return table, db.registerTable(table)
}

// MustNewTableAny creates a new table with given name and indexes, and registers
// it with the database. Panics if indexes are malformed, or a table with the
// same name is already registered.
func MustNewTableAny[Obj any](
	db *DB,
	tableName TableName,
	tableHeader func() []string,
	tableRow func(Obj) []string,
	primaryIndexer Indexer[Obj],
	secondaryIndexers ...Indexer[Obj]) RWTable[Obj] {
	t, err := NewTableAny(db, tableName, tableHeader, tableRow, primaryIndexer, secondaryIndexers...)
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
	secondaryAnyIndexers []anyIndexer
	indexPositions       []string
	tableHeaderFunc      func() []string
	tableRowFunc         func(Obj) []string
	lastWriteTxn         acquiredInfo
}

type acquiredInfo struct {
	mu         sync.Mutex
	handle     string
	acquiredAt time.Time
	duration   time.Duration
}

func (t *genTable[Obj]) acquired(txn *writeTxnState) {
	t.lastWriteTxn.mu.Lock()
	t.lastWriteTxn.handle = txn.handle
	t.lastWriteTxn.acquiredAt = txn.acquiredAt
	t.lastWriteTxn.mu.Unlock()
}

func (t *genTable[Obj]) released() {
	t.lastWriteTxn.mu.Lock()
	t.lastWriteTxn.duration = time.Since(t.lastWriteTxn.acquiredAt)
	t.lastWriteTxn.mu.Unlock()
}

func (t *genTable[Obj]) indexPos(name string) int {
	// By default don't consider the internal indexes.
	start := PrimaryIndexPos

	if name[0] == '_' {
		// Might be one of the internal indexes
		start = 0
	}

	for i, n := range t.indexPositions[start:] {
		if n == name {
			return start + i
		}
	}
	panic(fmt.Sprintf("BUG: index position not found for %s", name))

}

func (t *genTable[Obj]) getAcquiredInfo() string {
	t.lastWriteTxn.mu.Lock()
	defer t.lastWriteTxn.mu.Unlock()
	info := &t.lastWriteTxn
	if info.handle == "" {
		return ""
	}

	since := internal.PrettySince(info.acquiredAt)
	if info.duration == 0 {
		// Still locked
		return fmt.Sprintf("%s (locked for %s)", info.handle, since)
	}
	dur := time.Duration(info.duration)
	return fmt.Sprintf("%s (%s ago, locked for %s)", info.handle, since, internal.PrettyDuration(dur))
}

func (t *genTable[Obj]) tableEntry() *tableEntry {
	var entry tableEntry
	entry.meta = t
	deleteTrackers := part.New[anyDeleteTracker]()
	entry.deleteTrackers = &deleteTrackers

	// A new table is initialized, as no initializers are registered.
	entry.indexes = make([]tableIndex, len(t.indexPositions))

	primaryIndex := t.primaryIndexer.newTableIndex()
	entry.indexes[PrimaryIndexPos] = primaryIndex

	for _, indexer := range t.secondaryAnyIndexers {
		entry.indexes[t.indexPos(indexer.name)] = indexer.newTableIndex()
	}
	// For revision indexes we only need to watch the root.
	entry.indexes[RevisionIndexPos] = newRevisionIndex()
	entry.indexes[GraveyardRevisionIndexPos] = newRevisionIndex()
	entry.indexes[GraveyardIndexPos] = newGraveyardIndex(primaryIndex)

	return &entry
}

// newRevisionIndex constructs an index for storing objects by revision.
func newRevisionIndex() tableIndex {
	return &partIndex{
		tree: part.New[object](part.RootOnlyWatch),
		partIndexTxn: partIndexTxn{
			objectToKeys: func(obj object) index.KeySet {
				return index.NewKeySet(index.Uint64(obj.revision))
			},
			unique: true,
		},
	}
}

// newGraveyardIndex constructs an index for storing dead objects that
// are waiting to be observed via Changes().
func newGraveyardIndex(primaryIndex tableIndex) tableIndex {
	return &partIndex{
		tree: part.New[object](part.RootOnlyWatch),
		partIndexTxn: partIndexTxn{
			objectToKeys: func(obj object) index.KeySet {
				return index.NewKeySet(primaryIndex.objectToKey(obj))
			},
			unique: true,
		},
	}
}

func (t *genTable[Obj]) setTablePos(pos int) {
	t.pos = pos
}

func (t *genTable[Obj]) tablePos() int {
	return t.pos
}

func (t *genTable[Obj]) getIndexer(name string) *anyIndexer {
	if name == "" || t.primaryAnyIndexer.name == name {
		return &t.primaryAnyIndexer
	}
	for i, indexer := range t.secondaryAnyIndexers {
		if indexer.name == name {
			return &t.secondaryAnyIndexers[i]
		}
	}
	return nil
}

func (t *genTable[Obj]) PrimaryIndexer() Indexer[Obj] {
	return t.primaryIndexer
}

func (t *genTable[Obj]) secondary() []anyIndexer {
	return t.secondaryAnyIndexers
}

func (t *genTable[Obj]) Name() string {
	return t.table
}

func (t *genTable[Obj]) Indexes() []string {
	idxs := make([]string, 0, 1+len(t.secondaryAnyIndexers))
	idxs = append(idxs, t.primaryAnyIndexer.name)
	for _, idx := range t.secondaryAnyIndexers {
		idxs = append(idxs, idx.name)
	}
	sort.Strings(idxs)
	return idxs
}

func (t *genTable[Obj]) ToTable() Table[Obj] {
	return t
}

func (t *genTable[Obj]) Initialized(txn ReadTxn) (bool, <-chan struct{}) {
	table := txn.getTableEntry(t)
	if init := table.init; init != nil {
		if len(init.pending) == 0 {
			// Table has been initialized in this write transaction, but not yet
			// committed. [init.watch] is closed on Commit(), so return an already
			// closed watch channel here.
			return true, closedWatchChannel
		}
		return false, init.watch
	}
	return true, closedWatchChannel
}

func (t *genTable[Obj]) PendingInitializers(txn ReadTxn) []string {
	table := txn.getTableEntry(t)
	if init := table.init; init != nil {
		return init.pending
	}
	return nil
}

func (t *genTable[Obj]) RegisterInitializer(txn WriteTxn, name string) func(WriteTxn) {
	table := txn.unwrap().tableEntries[t.pos]
	if !table.locked {
		panic(fmt.Sprintf("RegisterInitializer: Table %q not locked for writing", t.table))
	}

	var init *tableInitialization
	if table.init == nil {
		init = &tableInitialization{
			watch: make(chan struct{}),
		}
		table.init = init
	} else {
		// Clone
		init2 := *table.init
		init2.pending = slices.Clone(init2.pending)
		init = &init2
		table.init = init
	}

	if slices.Contains(init.pending, name) {
		panic(fmt.Sprintf("RegisterInitializer: %q already registered", name))
	}

	init.pending = append(init.pending, name)
	var once sync.Once
	return func(txn WriteTxn) {
		once.Do(func() {
			table := txn.unwrap().tableEntries[t.pos]
			if !table.locked {
				panic(fmt.Sprintf("RegisterInitializer/MarkDone: Table %q not locked for writing", t.table))
			}
			init := *table.init
			init.pending = slices.DeleteFunc(
				slices.Clone(init.pending),
				func(n string) bool { return n == name },
			)
			table.init = &init
		})
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
	index := txn.root()[t.pos].indexes[t.indexPos(q.index)]
	iobj, watch, ok := index.get(q.key)
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
	iter, watch := indexTxn.lowerBound(q.key)
	return objSeq[Obj](iter), watch
}

func (t *genTable[Obj]) Prefix(txn ReadTxn, q Query[Obj]) iter.Seq2[Obj, Revision] {
	iter, _ := t.PrefixWatch(txn, q)
	return iter
}

func (t *genTable[Obj]) PrefixWatch(txn ReadTxn, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, t.indexPos(q.index))
	iter, watch := indexTxn.prefix(q.key)
	return objSeq[Obj](iter), watch
}

func (t *genTable[Obj]) All(txn ReadTxn) iter.Seq2[Obj, Revision] {
	iter, _ := t.AllWatch(txn)
	return iter
}

func (t *genTable[Obj]) AllWatch(txn ReadTxn) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, PrimaryIndexPos)
	iter, watch := indexTxn.all()
	return func(yield func(Obj, Revision) bool) {
		iter.All(func(_ []byte, obj object) bool {
			return yield(obj.data.(Obj), obj.revision)
		})
	}, watch
}

func (t *genTable[Obj]) List(txn ReadTxn, q Query[Obj]) iter.Seq2[Obj, Revision] {
	iter, _ := t.ListWatch(txn, q)
	return iter
}

func (t *genTable[Obj]) ListWatch(txn ReadTxn, q Query[Obj]) (iter.Seq2[Obj, Revision], <-chan struct{}) {
	indexTxn := txn.mustIndexReadTxn(t, t.indexPos(q.index))
	iter, watch := indexTxn.list(q.key)
	return objSeq[Obj](iter), watch
}

func (t *genTable[Obj]) Insert(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	oldObj, hadOld, _, err = t.InsertWatch(txn, obj)
	return
}

func (t *genTable[Obj]) InsertWatch(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, watch <-chan struct{}, err error) {
	var old object
	old, hadOld, watch, err = txn.unwrap().insert(t, Revision(0), obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) Modify(txn WriteTxn, obj Obj, merge func(old, new Obj) Obj) (oldObj Obj, hadOld bool, err error) {
	mergeObjects := func(old object, new object) object {
		new.data = merge(old.data.(Obj), new.data.(Obj))
		return new
	}
	var old object
	old, hadOld, _, err = txn.unwrap().modify(t, Revision(0), obj, mergeObjects)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndSwap(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, _, err = txn.unwrap().insert(t, rev, obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) Delete(txn WriteTxn, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, err = txn.unwrap().delete(t, Revision(0), obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) CompareAndDelete(txn WriteTxn, rev Revision, obj Obj) (oldObj Obj, hadOld bool, err error) {
	var old object
	old, hadOld, err = txn.unwrap().delete(t, rev, obj)
	if hadOld {
		oldObj = old.data.(Obj)
	}
	return
}

func (t *genTable[Obj]) DeleteAll(txn WriteTxn) error {
	itxn := txn.unwrap()
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

	itxn := txn.unwrap()
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

	// Add a cleanup to unregister the delete tracker.
	runtime.AddCleanup(
		iter,
		func(dt *deleteTracker[Obj]) { dt.close() },
		iter.dt,
	)

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

func (t *genTable[Obj]) typeName() string {
	var zero Obj
	return fmt.Sprintf("%T", zero)
}

func (t *genTable[Obj]) tableHeader() []string {
	return t.tableHeaderFunc()
}

func (t *genTable[Obj]) tableRowAny(obj any) []string {
	return t.tableRowFunc(obj.(Obj))
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
