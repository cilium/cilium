// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
)

// Index implements the indexing of objects (FromObjects) and
// querying of objects from the index (FromKey).
//
// The objects are indexed in a Persistent Adaptive Radix Tree [part].
type Index[Obj any, Key any] struct {
	// Name of the index
	Name string

	// FromObject extracts key(s) from the object. The key set
	// can contain 0, 1 or more keys. Must contain exactly one
	// key for primary indices.
	FromObject func(obj Obj) index.KeySet

	// FromKey converts the index key into a raw key.
	// With this we can perform Query() against this index with
	// the [Key] type.
	FromKey func(key Key) index.Key

	// FromString is an optional conversion from string to a raw key.
	// If implemented allows script commands to query with this index.
	FromString func(key string) (index.Key, error)

	// Unique marks the index as unique. Primary index must always be
	// unique. A secondary index may be non-unique in which case a single
	// key may map to multiple objects.
	Unique bool
}

func (i Index[Obj, Key]) isIndexerOf(Obj) {
	panic("isIndexerOf")
}

func (i Index[Obj, Key]) isUnique() bool {
	return i.Unique
}

// fromString implements Indexer.
func (i Index[Obj, Key]) fromString(s string) (index.Key, error) {
	return i.FromString(s)
}

var _ Indexer[struct{}] = &Index[struct{}, bool]{}

// The nolint:unused below are needed due to linter not seeing
// the use-sites due to generics.

//nolint:unused
func (i Index[Key, Obj]) indexName() string {
	return i.Name
}

// Query constructs a query against this index from a key.
func (i Index[Obj, Key]) Query(key Key) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   i.FromKey(key),
	}
}

func (i Index[Obj, Key]) QueryFromObject(obj Obj) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   i.FromObject(obj).First(),
	}
}

// QueryFromKey constructs a query against the index using the given
// user-supplied key. Be careful when using this and prefer [Index.Query]
// over this if possible.
func (i Index[Obj, Key]) QueryFromKey(key index.Key) Query[Obj] {
	return Query[Obj]{
		index: i.Name,
		key:   key,
	}
}

func (i Index[Obj, Key]) ObjectToKey(obj Obj) index.Key {
	return i.FromObject(obj).First()
}

// newTableIndex constructs a new instance of this index type.
func (i Index[Obj, Key]) newTableIndex() tableIndex {
	return &partIndex{
		tree: part.New[object](),
		partIndexTxn: partIndexTxn{
			objectToKeys: func(obj object) index.KeySet {
				return i.FromObject(obj.data.(Obj))
			},
			unique: i.Unique,
		},
	}
}

// partIndex indexes objects in a [part.Tree], e.g. an adaptive radix tree.
type partIndex struct {
	tree part.Tree[object]

	// partIndexTxn is the current transaction against the index. It's embedded
	// here to avoid heap allocations.
	partIndexTxn
}

// list implements tableIndex.
func (r *partIndex) list(key index.Key) (tableIndexIterator, <-chan struct{}) {
	return partList(r.unique, &r.tree, key)
}

var emptyTableIndexIterator = &singletonTableIndexIterator{}

func partList(unique bool, tree part.Ops[object], key index.Key) (tableIndexIterator, <-chan struct{}) {
	if unique {
		// Unique index means that there can be only a single matching object.
		// Doing a Get() is more efficient than constructing an iterator.
		obj, watch, ok := tree.Get(key)
		if ok {
			return &singletonTableIndexIterator{key, obj}, watch
		}
		return emptyTableIndexIterator, watch
	}

	key = encodeNonUniqueBytes(key)

	// For a non-unique index we do a prefix search. The keys are of
	// form <secondary key><primary key><secondary key length>, and thus the
	// iteration will continue until key length mismatches, e.g. we hit a
	// longer key sharing the same prefix.
	iter, watch := tree.Prefix(key)
	return newNonUniquePartIterator(iter, false, key), watch
}

// rootWatch implements tableIndex.
func (r *partIndex) rootWatch() <-chan struct{} {
	return r.tree.RootWatch()
}

func (r *partIndex) objectToKey(obj object) index.Key {
	return r.objectToKeys(obj).First()
}

func (r *partIndex) commit() (tableIndex, tableIndexTxnNotify) {
	return r, nil
}

// get implements tableIndex.
func (r *partIndex) get(ikey index.Key) (iobj object, watch <-chan struct{}, found bool) {
	return partGet(r.unique, &r.tree, ikey)
}

func partGet(unique bool, tree part.Ops[object], ikey index.Key) (iobj object, watch <-chan struct{}, found bool) {
	searchKey := ikey
	if unique {
		// On a unique index we can do a direct get rather than a prefix search.
		return tree.Get(searchKey)
	}

	searchKey = encodeNonUniqueBytes(searchKey)

	// For a non-unique index we need to do a prefix search.
	iter, watch := tree.Prefix(searchKey)
	for {
		var key []byte
		key, iobj, found = iter.Next()
		if !found {
			break
		}

		// Check that we have a full match on the key
		if nonUniqueKey(key).secondaryLen() == len(searchKey) {
			break
		}
	}
	return iobj, watch, found
}

// len implements tableIndex.
func (r *partIndex) len() int {
	return r.tree.Len()
}

func (r *partIndex) all() (tableIndexIterator, <-chan struct{}) {
	return &r.tree, r.rootWatch()
}

// prefix implements tableIndex.
func (r *partIndex) prefix(ikey index.Key) (tableIndexIterator, <-chan struct{}) {
	return partPrefix(r.unique, &r.tree, ikey)
}

func partPrefix(unique bool, tree part.Ops[object], key index.Key) (tableIndexIterator, <-chan struct{}) {
	if !unique {
		key = encodeNonUniqueBytes(key)
	}
	iter, watch := tree.Prefix(key)
	if unique {
		return iter, watch
	}
	return newNonUniquePartIterator(iter, true, key), watch
}

// lowerBound implements tableIndexTxn.
func (r *partIndex) lowerBound(ikey index.Key) (tableIndexIterator, <-chan struct{}) {
	return partLowerBound(r.unique, &r.tree, ikey), r.rootWatch()
}

// lowerBoundNext implements tableIndexTxn.
func (r *partIndex) lowerBoundNext(key index.Key) (func() ([]byte, object, bool), <-chan struct{}) {
	if !r.unique {
		key = encodeNonUniqueBytes(key)
	}
	iter := r.tree.LowerBound(key)
	if r.unique {
		return iter.Next, r.rootWatch()
	}
	return newNonUniqueLowerBoundPartIterator(iter, key).Next, r.rootWatch()
}

func partLowerBound(unique bool, tree part.Ops[object], key index.Key) tableIndexIterator {
	if !unique {
		key = encodeNonUniqueBytes(key)
	}
	iter := tree.LowerBound(key)
	if unique {
		return &iter
	}
	return newNonUniqueLowerBoundPartIterator(iter, key)
}

// txn implements tableIndex.
func (r *partIndex) txn() (tableIndexTxn, bool) {
	txn := &r.partIndexTxn
	txn.tx = r.tree.Txn()
	return txn, true
}

var _ tableIndex = &partIndex{}

type partIndexTxn struct {
	objectToKeys func(object) index.KeySet
	unique       bool
	tx           *part.Txn[object]
}

// all implements tableIndexTxn.
func (r *partIndexTxn) all() (tableIndexIterator, <-chan struct{}) {
	snapshot := r.tx.Clone()
	return &snapshot, r.rootWatch()
}

// list implements tableIndexTxn.
func (r *partIndexTxn) list(ikey index.Key) (tableIndexIterator, <-chan struct{}) {
	snapshot := r.tx.Clone()
	return partList(r.unique, &snapshot, ikey)
}

// lowerBound implements tableIndexTxn.
func (r *partIndexTxn) lowerBound(ikey index.Key) (tableIndexIterator, <-chan struct{}) {
	snapshot := r.tx.Clone()
	return partLowerBound(r.unique, &snapshot, ikey), r.rootWatch()
}

// lowerBoundNext implements tableIndexTxn.
func (r *partIndexTxn) lowerBoundNext(key index.Key) (func() ([]byte, object, bool), <-chan struct{}) {
	if !r.unique {
		key = encodeNonUniqueBytes(key)
	}
	snapshot := r.tx.Clone()
	iter := snapshot.LowerBound(key)
	if r.unique {
		return iter.Next, r.rootWatch()
	}
	return newNonUniqueLowerBoundPartIterator(iter, key).Next, r.rootWatch()
}

// rootWatch implements tableIndexTxn.
func (r *partIndexTxn) rootWatch() <-chan struct{} {
	return r.tx.RootWatch()
}

// commit implements tableIndexTxn.
func (r *partIndexTxn) commit() (tableIndex, tableIndexTxnNotify) {
	return &partIndex{
		tree: r.tx.Commit(),
		partIndexTxn: partIndexTxn{
			unique:       r.unique,
			objectToKeys: r.objectToKeys,
		},
	}, r
}

// delete implements tableIndexTxn.
func (r *partIndexTxn) delete(key index.Key) (old object, hadOld bool) {
	return r.tx.Delete(key)
}

// get implements tableIndexTxn.
func (r *partIndexTxn) get(key index.Key) (iobj object, watch <-chan struct{}, ok bool) {
	return partGet(r.unique, r.tx, key)
}

// insert implements tableIndexTxn.
func (r *partIndexTxn) insert(key index.Key, obj object) (old object, hadOld bool, watch <-chan struct{}) {
	return r.tx.InsertWatch(key, obj)
}

// len implements tableIndexTxn.
func (r *partIndexTxn) len() int {
	return r.tx.Len()
}

// modify implements tableIndexTxn.
func (r *partIndexTxn) modify(key index.Key, obj object, mod func(old, new object) object) (old object, hadOld bool, watch <-chan struct{}) {
	return r.tx.ModifyWatch(key, obj, mod)
}

// notify implements tableIndexTxn.
func (r *partIndexTxn) notify() {
	if r.tx != nil {
		r.tx.Notify()
		r.tx = nil
	}
}

// prefix implements tableIndexTxn.
func (r *partIndexTxn) prefix(ikey index.Key) (tableIndexIterator, <-chan struct{}) {
	snapshot := r.tx.Clone()
	return partPrefix(r.unique, &snapshot, ikey)
}

func (r *partIndexTxn) objectToKey(obj object) index.Key {
	return r.objectToKeys(obj).First()
}

// reindex implements tableIndexTxn.
func (r *partIndexTxn) reindex(idKey index.Key, old object, new object) {
	unique := r.unique
	var newKeys index.KeySet
	if new.revision != 0 {
		newKeys = r.objectToKeys(new)
		newKeys.Foreach(func(newKey index.Key) {
			// Non-unique secondary indexes are formed by concatenating them
			// with the primary key.
			if !unique {
				newKey = encodeNonUniqueKey(idKey, newKey)
			}
			r.tx.Insert(newKey, new)
		})
	}

	if old.revision != 0 {
		// The old object existed, remove any obsolete keys
		r.objectToKeys(old).Foreach(
			func(oldKey index.Key) {
				if !newKeys.Exists(oldKey) {
					if !unique {
						oldKey = encodeNonUniqueKey(idKey, oldKey)
					}
					_, hadOld := r.tx.Delete(oldKey)
					if !unique && !hadOld {
						panic("BUG: delete did not find old object")
					}
				}
			},
		)
	}
}

func (r *partIndexTxn) txn() (tableIndexTxn, bool) {
	return r, false
}

var _ tableIndexTxn = &partIndexTxn{}

const (
	// nonUniqueSeparator is the byte that delimits the secondary and primary keys.
	// It has to be 0x00 for correct ordering, e.g. if secondary prefix is "ab",
	// then it must hold that "ab<sep>" < "abc<sep>", which is only possible if sep=0x00.
	nonUniqueSeparator = 0x00

	// nonUniqueSubstitute is the byte that is used to escape 0x00 and 0x01 in
	// order to make sure the non-unique key has only a single 0x00 byte that is
	// the separator.
	nonUniqueSubstitute = 0x01
)

// appendEncode encodes the 'src' into 'dst'.
func appendEncode(dst, src []byte) (int, []byte) {
	n := 0
	for _, b := range src {
		switch b {
		case nonUniqueSeparator:
			dst = append(dst, nonUniqueSubstitute, 0x01)
			n += 2
		case nonUniqueSubstitute:
			dst = append(dst, nonUniqueSubstitute, 0x02)
			n += 2
		default:
			dst = append(dst, b)
			n++
		}
	}
	return n, dst
}

func encodedLength(src []byte) int {
	n := len(src)
	for _, b := range src {
		if b == nonUniqueSeparator || b == nonUniqueSubstitute {
			n++
		}
	}
	return n
}

func encodeNonUniqueBytes(src []byte) []byte {
	n := encodedLength(src)
	if n == len(src) {
		// No substitutions needed.
		return src
	}
	_, out := appendEncode(make([]byte, 0, n), src)
	return out
}

// encodeNonUniqueKey constructs the internal key to use with non-unique indexes.
//
// This schema allows looking up from the non-unique index with the secondary key by
// doing a prefix search. The length is used to safe-guard against indexers that don't
// terminate the key properly (e.g. if secondary key is "foo", then we don't want
// "foobar" to match).
func encodeNonUniqueKey(primary, secondary index.Key) []byte {
	key := make([]byte, 0,
		encodedLength(secondary)+
			1 /* delimiter */ +
			encodedLength(primary)+
			2 /* primary length */)

	_, key = appendEncode(key, secondary)
	key = append(key, 0x00)
	primaryLen, key := appendEncode(key, primary)
	return binary.BigEndian.AppendUint16(key, uint16(primaryLen))
}

type nonUniqueKey []byte

func (k nonUniqueKey) primaryLen() int {
	// Non-unique key is [<secondary...>, 0x00, <primary...>, <primary length>]
	if len(k) <= 3 {
		return 0
	}
	return int(binary.BigEndian.Uint16(k[len(k)-2:]))
}

func (k nonUniqueKey) secondaryLen() int {
	return len(k) - k.primaryLen() - 3
}

func (k nonUniqueKey) encodedPrimary() []byte {
	primaryLen := k.primaryLen()
	return k[len(k)-2-primaryLen : len(k)-2]
}

func (k nonUniqueKey) encodedSecondary() []byte {
	return k[:k.secondaryLen()]
}

type nonUniquePartIterator struct {
	iter         part.Iterator[object]
	prefixSearch bool
	searchKey    []byte
}

// All implements tableIndexIterator.
func (it *nonUniquePartIterator) All(yield func([]byte, object) bool) {
	var visited map[string]struct{}
	if it.prefixSearch {
		// When prefix searching, keep track of objects we've already seen as
		// multiple keys in non-unique index may map to a single object.
		// When just doing a List() on a non-unique index we will see each object
		// only once and do not need to track this.
		//
		// This of course makes iterating over a non-unique index with a prefix
		// (or lowerbound search) about 20x slower than normal!
		visited = map[string]struct{}{}
	}
	for key, iobj := range it.iter.All {
		nuk := nonUniqueKey(key)
		secondaryLen := nuk.secondaryLen()

		switch {
		case !it.prefixSearch && secondaryLen != len(it.searchKey):
			// This a List(), thus secondary key must match length exactly.
			continue
		case it.prefixSearch && secondaryLen < len(it.searchKey):
			// This is Prefix(), thus key must be equal or longer to search key.
			continue
		}

		if it.prefixSearch {
			primary := nuk.encodedPrimary()

			// When doing a prefix search on a non-unique index we may see the
			// same object multiple times since multiple keys may point it.
			// Skip if we've already seen this object.
			if _, found := visited[string(primary)]; found {
				continue
			}
			visited[string(primary)] = struct{}{}
		}

		if !yield(key, iobj) {
			return
		}
	}
}

func (it *nonUniquePartIterator) Next() ([]byte, object, bool) {
	panic("not implemented")
}

var _ tableIndexIterator = &nonUniquePartIterator{}

// nonUniqueSeq returns a sequence of objects for a non-unique index.
// Non-unique indexes work by concatenating the secondary key with the
// primary key and then prefix searching for the items:
//
//	<secondary>\0<primary><secondary length>
//	^^^^^^^^^^^
//
// Since the primary key can be of any length and we're prefix searching,
// we need to iterate over all objects matching the prefix and only emitting
// those which have the correct secondary key length.
// For example if we search for the key "aaaa", then we might have the following
// matches (_ is just delimiting, not part of the key):
//
//	aaaa\0bbb4
//	aaa\0abab3
//	aaaa\0ccc4
//
// We yield "aaaa\0bbb4", skip "aaa\0abab3" and yield "aaaa\0ccc4".
func newNonUniquePartIterator(iter part.Iterator[object], prefixSearch bool, searchKey []byte) tableIndexIterator {
	return &nonUniquePartIterator{
		iter:         iter,
		prefixSearch: prefixSearch,
		searchKey:    searchKey,
	}
}

type nonUniqueLowerBoundPartIterator struct {
	iter      part.Iterator[object]
	searchKey []byte

	// Keep track of objects we've already seen as multiple keys in non-unique
	// index may map to a single object. Only used by Next().
	visited map[string]struct{}
}

// All implements tableIndexIterator.
func (it *nonUniqueLowerBoundPartIterator) All(yield func([]byte, object) bool) {
	visited := map[string]struct{}{}
	for key, iobj := range it.iter.All {
		// With a non-unique index we have a composite key <secondary><primary><secondary len>.
		// This means we need to check every key that it's larger or equal to the search key.
		// Just seeking to the first one isn't enough as the secondary key length may vary.
		nuk := nonUniqueKey(key)
		secondary := nuk.encodedSecondary()
		if bytes.Compare(secondary, it.searchKey) >= 0 {
			primary := nuk.encodedPrimary()
			if _, found := visited[string(primary)]; found {
				continue
			}
			visited[string(primary)] = struct{}{}

			if !yield(key, iobj) {
				return
			}
		}
	}
}

func (it *nonUniqueLowerBoundPartIterator) Next() ([]byte, object, bool) {
	if it.visited == nil {
		it.visited = map[string]struct{}{}
	}
	for {
		key, obj, ok := it.iter.Next()
		if !ok {
			return nil, object{}, false
		}

		// With a non-unique index we have a composite key <secondary><primary><secondary len>.
		// This means we need to check every key that it's larger or equal to the search key.
		// Just seeking to the first one isn't enough as the secondary key length may vary.
		nuk := nonUniqueKey(key)
		secondary := nuk.encodedSecondary()
		if bytes.Compare(secondary, it.searchKey) >= 0 {
			primary := nuk.encodedPrimary()
			if _, found := it.visited[string(primary)]; found {
				continue
			}
			it.visited[string(primary)] = struct{}{}

			return key, obj, true
		}
	}
}

func newNonUniqueLowerBoundPartIterator(iter part.Iterator[object], searchKey []byte) *nonUniqueLowerBoundPartIterator {
	return &nonUniqueLowerBoundPartIterator{
		iter:      iter,
		searchKey: searchKey,
	}
}

type singletonTableIndexIterator struct {
	key []byte
	obj object
}

func (s *singletonTableIndexIterator) All(yield func([]byte, object) bool) {
	if s.key != nil {
		yield(s.key, s.obj)
	}
}

var _ tableIndexIterator = &singletonTableIndexIterator{}
