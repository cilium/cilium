// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"iter"
	"net/netip"
	"slices"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/lpm"
)

// NetIPPrefixIndex indexes objects with a [netip.Prefix] in a LPM
// index.
type NetIPPrefixIndex[Obj any] struct {
	// Name of the index
	Name string

	// FromObject returns the prefixes to index. Use [Just] to
	// return a single prefix.
	FromObject func(obj Obj) iter.Seq[netip.Prefix]

	// Unique marks the index as unique. If true each prefix maps to exactly
	// one object.
	Unique bool
}

func (a NetIPPrefixIndex[Obj]) Query(addr netip.Addr) Query[Obj] {
	addr16 := addr.As16()
	return Query[Obj]{
		index: a.Name,
		key:   lpm.EncodeLPMKey(addr16[:], 128),
	}
}

func (a NetIPPrefixIndex[Obj]) QueryPrefix(prefix netip.Prefix) Query[Obj] {
	return Query[Obj]{
		index: a.Name,
		key:   lpm.NetIPPrefixToIndexKey(prefix),
	}
}

// ObjectToKey implements Indexer.
func (a NetIPPrefixIndex[Obj]) ObjectToKey(obj Obj) index.Key {
	for prefix := range a.FromObject(obj) {
		return lpm.NetIPPrefixToIndexKey(prefix)
	}
	return nil
}

// QueryFromObject implements Indexer.
func (a NetIPPrefixIndex[Obj]) QueryFromObject(obj Obj) Query[Obj] {
	for prefix := range a.FromObject(obj) {
		return Query[Obj]{
			index: a.Name,
			key:   lpm.NetIPPrefixToIndexKey(prefix),
		}
	}
	return Query[Obj]{}
}

// fromString implements Indexer.
func (a NetIPPrefixIndex[Obj]) fromString(s string) (index.Key, error) {
	prefix, err := netip.ParsePrefix(s)
	if err == nil {
		return lpm.NetIPPrefixToIndexKey(prefix), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return index.Key{}, err
	}
	return lpm.NetIPPrefixToIndexKey(netip.PrefixFrom(addr, addr.BitLen())), nil
}

// indexName implements Indexer.
func (a NetIPPrefixIndex[Obj]) indexName() string {
	return a.Name
}

// isIndexerOf implements Indexer.
func (a NetIPPrefixIndex[Obj]) isIndexerOf(Obj) {
	panic("isIndexerOf")
}

func (i NetIPPrefixIndex[Obj]) isUnique() bool {
	return i.Unique
}

// newTableIndex implements Indexer.
func (a NetIPPrefixIndex[Obj]) newTableIndex() tableIndex {
	return lpmIndex{
		lpm:    lpm.New[lpmEntry](),
		unique: a.Unique,
		objectToKeys: func(obj object) index.KeySet {
			keys := make([]index.Key, 0, 2)
			for prefix := range a.FromObject(obj.data.(Obj)) {
				keys = append(keys, lpm.NetIPPrefixToIndexKey(prefix))
			}
			return index.NewKeySet(keys...)
		},
		watch: make(chan struct{}),
	}
}

type PrefixLen = lpm.PrefixLen

// LPMIndex implements bitwise Longest-Prefix Match indexing
type LPMIndex[Obj any] struct {
	// Name of the index
	Name string

	// FromObject maps the object to a set of LPM keys
	FromObject func(obj Obj) iter.Seq2[[]byte, PrefixLen]

	// FromString maps a string to a key
	FromString func(key string) ([]byte, PrefixLen, error)

	// Unique marks the index as unique. If true each key
	// (specific data and prefix length) maps to exactly
	// one object.
	Unique bool
}

func (l LPMIndex[Obj]) isIndexerOf(Obj) {
	panic("isIndexerOf")
}

// fromString implements Indexer.
func (l LPMIndex[Obj]) fromString(s string) (index.Key, error) {
	data, plen, err := l.FromString(s)
	if err != nil {
		return index.Key{}, err
	}
	return lpm.EncodeLPMKey(data, plen), nil
}

// indexName implements Indexer.
func (l LPMIndex[Obj]) indexName() string {
	return l.Name
}

func (l LPMIndex[Obj]) ObjectToKey(obj Obj) index.Key {
	for key := range l.FromObject(obj) {
		return key
	}
	return nil
}

// Query constructs a query against the index with the given prefix.
func (l LPMIndex[Obj]) Query(data []byte, prefixLen lpm.PrefixLen) Query[Obj] {
	return Query[Obj]{
		index: l.Name,
		key:   lpm.EncodeLPMKey(data, prefixLen),
	}
}

func (l LPMIndex[Obj]) QueryFromObject(obj Obj) Query[Obj] {
	for key, length := range l.FromObject(obj) {
		return Query[Obj]{
			index: l.Name,
			key:   lpm.EncodeLPMKey(key, length),
		}
	}
	return Query[Obj]{}
}

func (l LPMIndex[Obj]) newTableIndex() tableIndex {
	return lpmIndex{
		lpm:     lpm.New[lpmEntry](),
		prevTxn: nil,
		unique:  l.Unique,
		objectToKeys: func(obj object) index.KeySet {
			keys := make([]index.Key, 0, 2)
			for data, prefixLen := range l.FromObject(obj.data.(Obj)) {
				keys = append(keys, lpm.EncodeLPMKey(data, prefixLen))
			}
			return index.NewKeySet(keys...)
		},
		watch: make(chan struct{}),
	}
}

func (l LPMIndex[Obj]) isUnique() bool {
	return l.Unique
}

var _ Indexer[struct{}] = LPMIndex[struct{}]{}

type lpmIndex struct {
	lpm          lpm.Trie[lpmEntry]
	prevTxn      *lpm.Txn[lpmEntry]
	unique       bool
	size         int
	objectToKeys func(object) index.KeySet
	watch        chan struct{}
}

// all implements tableIndex.
func (l lpmIndex) all() (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.lpm.All()), l.watch
}

// get implements tableIndex.
func (l lpmIndex) get(ikey index.Key) (object, <-chan struct{}, bool) {
	entry, found := l.lpm.Lookup(ikey)
	if !found {
		return object{}, l.watch, false
	}
	if obj, ok := entry.first(); ok {
		return obj, l.watch, true
	}
	return object{}, l.watch, false
}

// len implements tableIndex.
func (l lpmIndex) len() int {
	return l.size
}

// list implements tableIndex.
func (l lpmIndex) list(key index.Key) (tableIndexIterator, <-chan struct{}) {
	entry, found := l.lpm.Lookup(key)
	if !found || entry.len() == 0 {
		return emptyTableIndexIterator, l.watch
	}
	return &entry, l.watch
}

// lowerBound implements tableIndex.
func (l lpmIndex) lowerBound(key index.Key) (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.lpm.LowerBound(key)), l.watch
}

// lowerBoundNext implements tableIndexTxn.
func (l lpmIndex) lowerBoundNext(key index.Key) (func() ([]byte, object, bool), <-chan struct{}) {
	return newLPMNextFunc(l.lpm.LowerBound(key)), l.watch
}

// objectToKey implements tableIndex.
func (l lpmIndex) objectToKey(obj object) index.Key {
	return l.objectToKeys(obj).First()
}

// prefix implements tableIndex.
func (l lpmIndex) prefix(key index.Key) (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.lpm.Prefix(key)), l.watch
}

// rootWatch implements tableIndex.
func (l lpmIndex) rootWatch() <-chan struct{} {
	return l.watch
}

func (l lpmIndex) commit() (tableIndex, tableIndexTxnNotify) {
	return l, nil
}

// txn implements tableIndex.
func (l lpmIndex) txn() (tableIndexTxn, bool) {
	if l.prevTxn != nil {
		return &lpmIndexTxn{
			index: l,
			tx:    l.prevTxn.Reuse(l.lpm),
			size:  l.size,
		}, true
	}
	return &lpmIndexTxn{
		index: l,
		tx:    l.lpm.Txn(),
		size:  l.size,
	}, true
}

var _ tableIndex = lpmIndex{}

type lpmIndexTxn struct {
	index lpmIndex
	tx    *lpm.Txn[lpmEntry]
	size  int
}

// all implements tableIndexTxn.
func (l *lpmIndexTxn) all() (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.tx.All()), l.index.watch
}

// commit implements tableIndexTxn.
func (l *lpmIndexTxn) commit() (tableIndex, tableIndexTxnNotify) {
	lpm := l.tx.Commit()
	l.tx.Clear()
	return lpmIndex{
		lpm:          lpm,
		prevTxn:      l.tx,
		unique:       l.index.unique,
		size:         l.size,
		objectToKeys: l.index.objectToKeys,
		watch:        make(chan struct{}),
	}, l
}

// delete implements tableIndexTxn.
func (l *lpmIndexTxn) delete(key index.Key) (old object, hadOld bool) {
	panic("LPM index cannot be the primary index")
}

// insert implements tableIndexTxn.
func (l *lpmIndexTxn) insert(key index.Key, obj object) (old object, hadOld bool, watch <-chan struct{}) {
	panic("LPM index cannot be the primary index")
}

// modify implements tableIndexTxn.
func (l *lpmIndexTxn) modify(key index.Key, obj object, mod func(old, new object) object) (old object, hadOld bool, watch <-chan struct{}) {
	panic("LPM index cannot be the primary index")
}

// get implements tableIndexTxn.
func (l *lpmIndexTxn) get(key index.Key) (object, <-chan struct{}, bool) {
	entry, found := l.tx.Lookup(key)
	if !found {
		return object{}, l.index.watch, false
	}
	if obj, ok := entry.first(); ok {
		return obj, l.index.watch, true
	}
	return object{}, l.index.watch, false
}

// len implements tableIndexTxn.
func (l *lpmIndexTxn) len() int {
	return l.size
}

// list implements tableIndexTxn.
func (l *lpmIndexTxn) list(key index.Key) (tableIndexIterator, <-chan struct{}) {
	entry, found := l.tx.Lookup(key)
	if !found || entry.len() == 0 {
		return emptyTableIndexIterator, l.index.watch
	}
	return &entry, l.index.watch
}

// lowerBound implements tableIndexTxn.
func (l *lpmIndexTxn) lowerBound(key index.Key) (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.tx.LowerBound(key)), l.index.watch
}

// lowerBoundNext implements tableIndexTxn.
func (l *lpmIndexTxn) lowerBoundNext(key index.Key) (func() ([]byte, object, bool), <-chan struct{}) {
	return newLPMNextFunc(l.tx.LowerBound(key)), l.index.watch
}

// notify implements tableIndexTxn.
func (l *lpmIndexTxn) notify() {
	if l.index.watch != nil {
		close(l.index.watch)
		l.index.watch = nil
	}
}

// objectToKey implements tableIndexTxn.
func (l *lpmIndexTxn) objectToKey(obj object) index.Key {
	return l.index.objectToKey(obj)
}

// prefix implements tableIndexTxn.
func (l *lpmIndexTxn) prefix(key index.Key) (tableIndexIterator, <-chan struct{}) {
	return newLPMIterator(l.tx.Prefix(key)), l.index.watch
}

// reindex implements tableIndexTxn.
func (l *lpmIndexTxn) reindex(primaryKey index.Key, old object, new object) {
	var newKeys index.KeySet
	if new.revision != 0 {
		newKeys = l.index.objectToKeys(new)
		newKeys.Foreach(func(key index.Key) {
			l.insertKey(primaryKey, key, new)
		})
	}
	if old.revision != 0 {
		// The old object existed, remove any obsolete keys
		l.index.objectToKeys(old).Foreach(func(oldKey index.Key) {
			if !newKeys.Exists(oldKey) {
				l.removeKey(primaryKey, oldKey)
			}
		})
	}
}

// rootWatch implements tableIndexTxn.
func (l *lpmIndexTxn) rootWatch() <-chan struct{} {
	return l.index.watch
}

func (l *lpmIndexTxn) txn() (tableIndexTxn, bool) {
	return l, false
}

var _ tableIndexTxn = &lpmIndexTxn{}

func (l *lpmIndexTxn) insertKey(primaryKey, key index.Key, obj object) {
	if l.index.unique {
		// The index is unique and thus the [lpmEntry] will only have the head.
		entry, found := l.tx.LookupExact(key)
		if found {
			entry.head = lpmEntryObject{
				primary: primaryKey,
				obj:     obj,
			}
		} else {
			entry = lpmEntry{
				head: lpmEntryObject{
					primary: primaryKey,
					obj:     obj,
				},
				used: true,
			}
		}
		if !found {
			l.size++
		}
		_ = l.tx.Insert(key, entry)
		return
	}

	entry, found := l.tx.LookupExact(key)
	if !found {
		entry.init(key)
	}
	if entry.upsert(primaryKey, obj) {
		l.size++
	}
	_ = l.tx.Insert(key, entry)
}

func (l *lpmIndexTxn) removeKey(primaryKey, key index.Key) {
	entry, found := l.tx.LookupExact(key)
	if !found {
		return
	}
	if entry.len() == 1 {
		if bytes.Equal(entry.head.primary, primaryKey) {
			l.size--
			l.tx.Delete(key)
		}
		return
	}
	if _, removed := entry.delete(primaryKey); !removed {
		return
	}
	l.size--
	if entry.len() == 0 {
		l.tx.Delete(key)
		return
	}
	_ = l.tx.Insert(key, entry)
}

type lpmEntry struct {
	secondary index.Key
	head      lpmEntryObject
	tail      []lpmEntryObject
	used      bool
}

type lpmEntryObject struct {
	primary index.Key
	obj     object
}

func (e *lpmEntry) init(secondary index.Key) {
	e.secondary = secondary
}

func (e lpmEntry) len() int {
	if !e.used {
		return 0
	}
	return 1 + len(e.tail)
}

func (e lpmEntry) first() (object, bool) {
	return e.head.obj, e.used
}

func (e *lpmEntry) upsert(primaryKey index.Key, obj object) bool {
	if !e.used {
		e.head = lpmEntryObject{primary: primaryKey, obj: obj}
		e.used = true
		return true
	}
	switch bytes.Compare(primaryKey, e.head.primary) {
	case 0:
		e.head.obj = obj
		return false
	case -1:
		oldHead := e.head
		e.head = lpmEntryObject{primary: primaryKey, obj: obj}
		e.tail = append(e.tail, lpmEntryObject{})
		copy(e.tail[1:], e.tail[:len(e.tail)-1])
		e.tail[0] = oldHead
		return true
	}
	idx, found := e.searchTail(primaryKey)
	if found {
		e.tail[idx].obj = obj
		return false
	}
	entry := lpmEntryObject{primary: primaryKey, obj: obj}
	e.tail = append(e.tail, lpmEntryObject{})
	copy(e.tail[idx+1:], e.tail[idx:])
	e.tail[idx] = entry
	return true
}

func (e *lpmEntry) delete(key index.Key) (object, bool) {
	if e == nil || !e.used {
		return object{}, false
	}
	switch bytes.Compare(key, e.head.primary) {
	case 0:
		obj := e.head.obj
		if len(e.tail) == 0 {
			e.head = lpmEntryObject{}
			e.used = false
			return obj, true
		}
		e.head = e.tail[0]
		newTail := make([]lpmEntryObject, len(e.tail)-1)
		copy(newTail, e.tail[1:])
		e.tail = newTail
		return obj, true
	case -1:
		return object{}, false
	}
	idx, found := e.searchTail(key)
	if !found {
		return object{}, false
	}
	obj := e.tail[idx].obj
	newTail := make([]lpmEntryObject, len(e.tail)-1)
	copy(newTail, e.tail[:idx])
	copy(newTail[idx:], e.tail[idx+1:])
	e.tail = newTail
	return obj, true
}

func (e *lpmEntry) searchTail(key index.Key) (int, bool) {
	return slices.BinarySearchFunc(
		e.tail,
		key,
		func(a lpmEntryObject, k index.Key) int {
			return bytes.Compare(a.primary, k)
		})
}

func (e *lpmEntry) All(yield func([]byte, object) bool) {
	if e == nil || !e.used {
		return
	}
	if !yield(e.secondary, e.head.obj) {
		return
	}
	for _, b := range e.tail {
		if !yield(e.secondary, b.obj) {
			return
		}
	}
}

func (e *lpmEntry) appendObjects(dst []object) []object {
	dst = dst[:0]
	if e == nil || !e.used {
		return dst
	}
	dst = append(dst, e.head.obj)
	for _, entry := range e.tail {
		dst = append(dst, entry.obj)
	}
	return dst
}

type lpmIteratorAdapter struct {
	iter *lpm.Iterator[lpmEntry]
}

func newLPMIterator(iter *lpm.Iterator[lpmEntry]) tableIndexIterator {
	return &lpmIteratorAdapter{iter: iter}
}

func (l *lpmIteratorAdapter) All(yield func([]byte, object) bool) {
	l.iter.All(func(key []byte, entry lpmEntry) bool {
		for _, obj := range entry.All {
			if !yield(key, obj) {
				return false
			}
		}
		return true
	})
}

type lpmNextIterator struct {
	iter    *lpm.Iterator[lpmEntry]
	pending []object
	idx     int
	key     []byte
}

func newLPMNextFunc(iter *lpm.Iterator[lpmEntry]) func() ([]byte, object, bool) {
	next := &lpmNextIterator{iter: iter}
	return next.next
}

func (l *lpmNextIterator) next() ([]byte, object, bool) {
	for {
		if l.idx < len(l.pending) {
			obj := l.pending[l.idx]
			l.idx++
			return l.key, obj, true
		}
		if l.iter == nil {
			return nil, object{}, false
		}
		key, entry, ok := l.iter.Next()
		if !ok {
			l.iter = nil
			return nil, object{}, false
		}
		l.pending = entry.appendObjects(l.pending)
		l.idx = 0
		l.key = key
	}
}
