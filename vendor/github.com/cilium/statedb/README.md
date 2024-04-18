# :memo: StateDB [![GoDoc](https://pkg.go.dev/badge/github.com/cilium/statedb)](https://pkg.go.dev/github.com/cilium/statedb) 

StateDB is an in-memory database for Go. The database is built on top of 
[Persistent](https://en.wikipedia.org/wiki/Persistent_data_structure) [Adaptive Radix Trees](https://db.in.tum.de/~leis/papers/ART.pdf).

StateDB is/supports:

* In-memory. Objects and indexes are stored in main memory and not on disk.
  This makes it easy to store and index any Go data type.

* Multi-Version Concurrency Control (MVCC). Both objects and indexes are immutable
  and objects are versioned. A read transaction has access to an immutable snapshot
  of the data.

* Cross-table write transactions. Write transactions lock the requested tables and
  allow modifying objects in multiple tables as a single atomic action. Transactions
  can be aborted to throw away the changes.

* Multiple indexes. A table may have one or more indexers for objects, with each
  indexer returning zero or more keys. Indexes can be unique or non-unique.
  A non-unique index is a concatenation of the primary and secondary keys.

* Watch channels. Changes to the database can be watched at fine-granularity via
  Go channels that close when a relevant part of the database changes. This is
  implemented by having a Go channel at each of the radix tree nodes. This enables
  watching an individual object for changes, a key prefix, or the whole table.

## Warning! Immutable data! Read this!

To support lockless readers and transactionality StateDB relies on both the indexes
and the objects themselves being immutable. Since in Go you cannot declare fields
`const` we cannot stop mutation of public fields in objects. This means that care
must be taken with objects stored in StateDB and not mutate objects that have been
inserted into it. This means both the fields directly in the object and everything
referenced from it, e.g. a map field must not be modified, but must be cloned first!

StateDB has a check in `Insert()` to validate that if an object is a pointer then it
cannot be replaced with the same pointer, but that at least a shallow clone has been
made. This of course doesn't extend to references within the object.

For "very important objects", please consider storing an interface type instead that
contains getter methods and a safe way of mutating the object, e.g. via the builder
pattern or a constructor function. 

Also prefer persistent/immutable data structures within the object to avoid expensive
copying on mutation. The `part` package comes with persistent `Map[K]V` and `Set[T]`.

## Example

Here's a quick example to show how using StateDB looks like.

```go
// Define an object to store in the database.
type MyObject struct {
  ID uint32
  Foo string
}

// Define how to index and query the object.
var IDIndex = statedb.Index[*MyObject, uint32]{
  Name: "id",
  FromObject: func(obj *MyObject) index.KeySet {
    return index.NewKeySet(index.Uint64(obj.ID))
  },
  FromKey: func(id uint32) index.Key {
    return index.Uint32(id)
  },
  Unique: true,
}

// Create the database and the table.
func example() {
  db := statedb.New()
  myObjects, err := statedb.NewTable(
    "my-objects",
    IDIndex,
  )
  if err != nil { ... }

  if err := db.RegisterTable(myObjects); err != nil {
    ...
  }

  wtxn := db.WriteTxn(myObjects)
  
  // Insert some objects
  myObjects.Insert(wtxn, &MyObject{1, "a"})
  myObjects.Insert(wtxn, &MyObject{2, "b"})
  myObjects.Insert(wtxn, &MyObject{3, "c"})

  // Modify an object
  if obj, _, found := myObjects.Get(wtxn, IDIndex.Query(1)); found {
    objCopy := *obj
    objCopy.Foo = "d"
    myObjects.Insert(wtxn, &objCopy)
  }

  // Delete an object
  if obj, _, found := myObjects.Get(wtxn, IDIndex.Query(2)); found {
    myObjects.Delete(wtxn, obj)
  }
  
  if feelingLucky {
    // Commit the changes.
    wtxn.Commit()
  } else {
    // Throw away the changes.
    wtxn.Abort()
  }

  // Query the objects with a snapshot of the database.
  txn := db.ReadTxn()

  if obj, _, found := myObjects.Get(wtxn, IDIndex.Query(1)); found {
    ...
  }

  iter, watch := myObjects.All()
  // Iterate all objects

  iter, watch = myObjects.LowerBound(IDIndex.Query(2))
  // Iterate objects with ID >= 2
  
  iter, watch = myObjects.Prefix(IDIndex.Query(0x1000_0000))
  // Iterate objects where ID is between 0x1000_0000 and 0x1fff_ffff

  for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() {
    ...
  }

  // Wait until the query results change.
  <-watch
}
```

Read on for a more detailed guide or check out the [Go package docs](https://pkg.go.dev/github.com/cilium/statedb).

## Guide to StateDB

StateDB can be used directly as a normal library, or as a [Hive](https://github.com/cilium/hive) Cell.
For example usage as part of Hive, see `reconciler/example`. Here we show a standalone example.

We start by defining the data type we want to store in the database. There are
no constraints on the type and it may be a primitive type like an `int` or a
struct type, or a pointer. Since each index stores a copy of the object one should
use a pointer if the object is large.

```go
import (
  "github.com/cilium/statedb"
  "github.com/cilium/statedb/index"
  "github.com/cilium/statedb/part"
)

type ID = uint64
type Tag = string
type MyObject struct {
  ID ID              // Identifier
  Tags part.Set[Tag] // Set of tags
}
```

### Indexes

With the object defined, we can describe how it should be indexed. Indexes are
constant values and can be defined as global variables alongside the object type.
Indexes take two type parameters, your object type and the key type: `Index[MyObject, ID]`.
Additionally you define two operations: `FromObject` that takes your object and returns
a set of StateDB keys (zero or many), and `FromKey` that takes the key type of your choosing and 
converts it to a StateDB key.

```go
// IDIndex is the primary index for MyObject indexing the 'ID' field.
var IDIndex = statedb.Index[*MyObject, ID]{
  Name: "id",

  FromObject: func(obj *MyObject) index.KeySet {
    return index.NewKeySet(index.Uint64(obj.ID))
  }

  FromKey: func(id ID) index.Key {
    return index.Uint64(id)
  }
  // Above is equal to just:
  // FromKey: index.Uint64,

  Unique: true, // IDs are unique.
}
```

The `index.Key` seen above is just a `[]byte`. The `index` package contains many functions
for converting into the `index.Key` type, for example `index.Uint64` and so on.

A single object can also map to multiple keys (multi-index). Let's construct an index
for tags.

```go
var TagsIndex = statedb.Index[*MyObject, Tag]{
  Name: "tags",

  FromObject: func(o *MyObject) index.KeySet {
    // index.Set turns the part.Set[string] into a set of keys
    // (set of byte slices)
    return index.Set(o.Tags)
  }

  FromKey: index.String,

  // Many objects may have the same tag, so we mark this as
  // non-unique.
  Unique: false,
}
```

With the indexes now defined, we can construct a table.

### Setting up a table

```go
func NewMyObjectTable() (statedb.RWTable[*MyObject], error) {
  return statedb.NewTable[*MyObject](
    "my-objects",

    IDIndex,   // IDIndex is the primary index
    TagsIndex, // TagsIndex is a secondary index
    // ... more secondary indexes can be passed in here
  )
}
```

The `NewTable` function takes the name of the table, a primary index and zero or
more secondary indexes. It returns a `RWTable`, which is an interface for both
reading and writing to a table. An `RWTable` is a superset of `Table`, an interface
that contains methods just for reading. This provides a simple form of type-level
access control to the table. `NewTable` may return an error if the indexers are
malformed, for example if `IDIndex` is not unique (primary index has to be), or if
the indexers have overlapping names.

### Inserting

With the table defined, we can now create the database and start writing and reading
to the table.

```go
db := statedb.New()

myObjects, err := NewMyObjectTable()
if err != nil { return err }

// Register the table with the database.
err := db.RegisterTable(myObjects)
if err != nil { 
  // May fail if the table with the same name is already registered.
  return err
}
```

To insert objects into a table, we'll need to create a `WriteTxn`. This locks
the target table(s) allowing for an atomic transaction change. 

```go
// Create a write transaction against the 'myObjects' table, locking
// it for writing.
// Note that the returned 'wtxn' holds internal state and it is not
// safe to use concurrently (e.g. you must not have multiple goroutines
// using the same WriteTxn in parallel).
wtxn := db.WriteTxn(myObjects)

// We can defer an Abort() of the transaction in case we encounter
// issues and want to forget our writes. This is a good practice
// to safe-guard against forgotten call to Commit(). Worry not though,
// StateDB has a finalizer on WriteTxn to catch forgotten Abort/Commit.
defer wtxn.Abort()

// Insert an object into the table. This will be visible to readers
// only when we commit.
obj := &MyObject{ID: 42, Tags: part.NewStringSet("hello")}
oldObj, hadOld, err := myObjects.Insert(wtxn, obj)
if err != nil {
  // Insert can fail only if 'wtxn' is not locking the table we're
  // writing to, or if 'wxtn' was already committed.
  return err
}
// hadOld is true and oldObj points to an old version of the object
// if it was replaced. Since the object type can be a non-pointer
// we need the separate 'hadOld' boolean and cannot just check for nil.

// Commit the changes to the database and notify readers by closing the
// relevant watch channels.
wtxn.Commit()
```


### Reading

Now that there's something in the table we can try out reading. We can
read either using a read-only `ReadTxn`, or we can read using a `WriteTxn`.
With a `ReadTxn` we'll be reading from a snapshot and nothing we do
will affect other readers or writers (unless you mutate the immutable object,
in which case bad things happen).

```go
txn := db.ReadTxn()
```

The `txn` is now a frozen snapshot of the database that we can use
to read the data. 

```go
// Let's break out the types so you know what is going on.
var (
  obj *MyObject
  revision statedb.Revision
  found bool
  watch <-chan struct{}
)
// Get returns the first matching object in the query.
obj, revision, found = myObjects.Get(txn, IDIndex.Query(42))
if found {
  // obj points to the object we inserted earlier.
  // revision is the "table revision" for the object. Revisions are
  // incremented for a table on every insertion or deletion.
}
// GetWatch is the same as Get, but also gives us a watch
// channel that we can use to wait on the object to appear or to
// change.
obj, revision, watch, found = myObjects.GetWatch(txn, IDIndex.Query(42))
<-watch // closes when object with ID '42' is inserted or deleted
```

### Iterating

`List` can be used to iterate over all objects that match the query.

```go
var iter statedb.Iterator[*MyObject]
// List returns all matching objects as an iterator. The iterator is lazy
// and one can stop reading at any time without worrying about the rest.
iter := myObjects.List(txn, TagsIndex.Query("hello"))
for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() {
  // ...
}

// ListWatch is like List, but also returns a watch channel.
iter, watch := myObjects.ListWatch(txn, TagsIndex.Query("hello"))
for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() { ... }

// closes when an object with tag "hello" is inserted or deleted
<-watch
```

`Prefix` can be used to iterate over objects that match a given prefix.

```go
// Prefix does a prefix search on an index. Here it returns an iterator
// for all objects that have a tag that starts with "h".
iter, watch = myObjects.Prefix(txn, TagsIndex.Query("h"))
for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() {
  // ...
}
// closes when an object with a tag starting with "h" is inserted or deleted
<-watch
```

`LowerBound` can be used to iterate over objects that have a key equal
to or higher than given key.

```go
// LowerBound can be used to find all objects with a key equal to or higher
// than specified key. The semantics of it depends on how the indexer works.
// For example index.Uint32 returns the big-endian or most significant byte
// first form of the integer, in other words the number 3 is the key
// []byte{0, 0, 0, 3}, which allows doing a meaningful LowerBound search on it.
iter, watch = myObjects.LowerBound(txn, IDIndex.Query(3))
for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() {
  // obj.ID >= 3
}

// closes when anything happens to the table. This is because there isn't a
// clear notion of what part of the index to watch for, e.g. if the index
// stores 0x01, 0x11, 0x20, and we do LowerBound(0x10), then none of these nodes
// in the tree are what we should watch for since "0x01" is in the wrong subtree
// and we may insert "0x10" above "0x11", so cannot watch that either. LowerBound
// could return the watch channel of the node that shares a prefix with the search
// term, but instead StateDB currently does the conservative thing and returns the
// watch channel of the "root node".
<-watch
```

All objects stored in StateDB have an associated revision. The revision is unique
to the table and increments on every insert or delete. Revisions can be queried
with `ByRevision`.

```go
// StateDB also has a built-in index for revisions and that can be used to
// iterate over the objects in the order they have been changed. Furthermore
// we can use this to wait for new changes!
lastRevision := statedb.Revision(0)
for {
  iter, watch = myObjects.LowerBound(txn, statedb.ByRevision(lastRevision+1))
  for obj, revision, ok := iter.Next(); ok; obj, revision, ok = iter.Next() {
    lastRevision = revision
  }

  // Wait until there are new changes. In real code we probably want to
  // do a 'select' here and check for 'ctx.Done()' etc.
  <-watch

  // We should rate limit so we can see a batch of changes in one go.
  // For sake of example just sleeping here, but you likely want to use the
  // 'rate' package.
  time.Sleep(100*time.Millisecond)

  // Take a new snapshot so we can see the changes.
  txn = db.ReadTxn()
}
```

As it's really useful to know when an object has been deleted, StateDB has
a facility for storing deleted objects in a separate index until they have
been observed. Using `Changes` one can iterate over insertions and deletions.

```go
// Let's iterate over both inserts and deletes. We need to use
// a write transaction to create the change iterator as this needs to
// register with the table to track the deleted objects.

wtxn := statedb.WriteTxn(myObjects)
changes, err := myObjects.Changes(wtxn)
wtxn.Commit()
if err != nil {
  // This can fail due to same reasons as e.g. Insert()
  // e.g. transaction not locking target table or it has
  // already been committed.
  return err
}

// We need to remember to Close() it so that StateDB does not hold onto
// deleted objects for us. No worries though, a finalizer will close it
// for us if we do not do this.
defer changes.Close()

// Now very similar to the LowerBound revision iteration above, we will
// iterate over the changes.
for {
  for change, revision, ok := iter.Next(); ok; change, revision, ok = iter.Next() {
    if change.Deleted {
      fmt.Printf("Object %#v was deleted!\n", change.Object)
    } else {
      fmt.Printf("Object %#v was inserted!\n", change.Object)
    }
  }
  // To observe more changes, we create a new ReadTxn and pass it to Watch() that
  // refreshes the iterator. Once the returned channel closes we can iterate again.
  <-changes.Watch(db.ReadTxn())
}
```

### Modifying objects

Modifying objects is basically just a query and an insert to override the object.
One must however take care to not modify the object returned by the query.

```go
// Let's make a write transaction to modify the table.
wtxn := db.WriteTxn(myObjects)

// Now that we have the table written we can retrieve an object and none will
// be able to modify it until we commit.
obj, revision, found := myObjects.Get(wtxn, IDIndex.Query(42))
if !found { panic("it should be there, I swear!") }

// We cannot just straight up modify 'obj' since someone might be reading it.
// It's supposed to be immutable after all. To make this easier, let's define
// a Clone() method.
func (obj *MyObject) Clone() *MyObject {
  obj2 := *obj
  return &obj2
}

// Now we can do a "shallow clone" of the object and we can modify the fields
// without the readers getting upset. Of course we still cannot modify anything
// referenced by those fields without cloning the fields themselves. But that's
// why we're using persistent data structures like 'part.Set' and 'part.Map'.
//
// Let's add a new tag. But first we clone.
obj = obj.Clone()
obj.Tags = obj.Tags.Set("foo")

// Now we have a new object that has "foo" set. We can now write it to the table.
oldObj, hadOld, err := myObjects.Insert(wtxn, obj)
// err should be nil, since we're using the WriteTxn correctly
// oldObj is the original object, without the "foo" tag
// hadOld is true since we replaced the object

// Commit the transaction so everyone sees it.
wtxn.Commit()

// We can also do a "compare-and-swap" to insert an object. This is useful when
// computing the change we want to make is expensive. Here's how you do it.

// Start with a ReadTxn that is cheap and doesn't block anyone.
txn := db.ReadTxn()

// Look up the object we want to update and perform some slow calculation
// to produce the desired new object.
obj, revision, found := myObjects.Get(txn, IDIndex.Query(42))
obj = veryExpensiveCalculation(obj)

// Now that we're ready to insert we can grab a WriteTxn.
wtxn := db.WriteTxn(myObjects)

// Let's try and update the object with the revision of the object we used
// for that expensive calculation.
oldObj, hadOld, err := myObjects.CompareAndSwap(wtxn, obj, revision)
if errors.Is(err, statedb.ErrRevisionNotEqual) {
  // Oh no, someone updated the object while we were calculating.
  // I guess I need to calculate again...
  wtxn.Abort()
  return err
}
wtxn.Commit()
```

### Performance considerations

Needless to say, one should keep the duration of the write transactions
as short as possible so that other writers are not starved (readers
are not affected as they're reading from a snapshot). Writing in
batches or doing first a `ReadTxn` to compute the changes and committing
with `CompareAndSwap` is a good way to accomplish this as shown above
(optimistic concurrency control).

One should also avoid keeping the `ReadTxn` around when for example waiting
on a watch channel to close. The `ReadTxn` holds a pointer to the database
root and thus holding it will prevent old objects from being garbage collected
by the Go runtime. Considering grabbing the `ReadTxn` in a function and returning
the watch channel to the function doing the for-select loop.

## Persistent Map and Set

The `part` package contains persistent `Map[K, V]` and `Set[T]` data structures.
These, like StateDB, are implemented with the Persistent Adaptive Radix Trees.
They are meant to be used as replacements for the built-in mutable Go hashmap
in StateDB objects as they're persistent (operations return a copy) and thus 
more efficient to copy and suitable to use in immutable objects.

Here's how to use `Map[K, V]`:

```go
import (
  "github.com/cilium/statedb/part"
)

// Create a new map with strings as keys
m := part.NewStringMap[int]()

// Set the key "one" to value 1. Returns a new map.
mNew := m.Set("one", 1)
v, ok := m.Get("one")
// ok == false since we didn't modify the original map.

v, ok = mNew.Get("one")
// v == 1, ok == true

// Let's reuse 'm' as our variable.
m = mNew
m = m.Set("two")

// All key-value pairs can be iterated over.
iter := m.All()
// Maps can be prefix and lowerbound searched, just like StateDB tables
iter = m.Prefix("a")  // Iterator for anything starting with 'a'
iter = m.LowerBound("b") // Iterator for anything equal to 'b' or larger, e.g. 'bb' or 'c'...

for k, v, ok := iter.Next(); ok; k, v, ok = iter.Next() {
  // ...
}

m.Len() == 2
m = m.Delete("two")
m.Len() == 1

// We can use arbitrary types as keys and values... provided
// we teach it how to create a byte slice key out of it.
type Obj struct {
  ID string
}
m2 := part.NewMap[*Obj, *Obj](
  func(o *Obj) []byte { return []byte(o.ID) },
  func(b []byte) string { return string(b) },
)
o := &Obj{ID: "foo"}
m2.Set(o, o)
```

And here's `Set[T]`:

```go
// 's' is now the empty string set
s := part.StringSet
s = s.Set("hello")
s.Has("hello") == true
s2 := s.Delete("hello")
s.Has("hello") == true
s2.Has("hello") == false

// we can initialize a set with NewStringSet
s3 := part.NewStringSet("world", "foo")

// Sets can be combined.
s3 = s3.Union(s)
// s3 now contains "hello", "foo", world"
s3.Len() == 3

// Print "hello", "foo", "world"
iter := s3.All()
for word, ok := iter.Next(); ok; word, ok = iter.Next() {
  fmt.Println(word)
}

// We can remove a set from another set
s4 := s3.Difference(part.NewStringSet("foo"))
s4.Has("foo") == false

// As with Map[K, V] we can define Set[T] for our own objects
type Obj struct {
  ID string
}
s5 := part.NewSet[*Obj](
  func(o *Obj) []byte { return []byte(o.ID) },
)
s5.Set(&Obj{"quux"})
s5.Has(&Obj{"quux"}) == true
```

## Reconciler

This repository comes with a generic reconciliation utility that watches a table
for changes and performs a configurable Update or Delete operation on the change.
The status of the operation is written back into the object, which allows inspecting
or waiting for an object to be reconciled. On failures the reconciler will retry
the operation at a later time. Reconciler supports health reporting and metrics.

See the example application in `reconciler/example` for more information.

