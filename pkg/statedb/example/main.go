// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-memdb"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/stream"
)

type Kind = string

var (
	QueenBee  = "queen"
	WorkerBee = "worker"
	DroneBee  = "drone"
)

type Bee struct {
	UUID statedb.UUID // Primary key
	Kind Kind
}

// DeepCopy is needed for objects that are stored in the database tables. Usually
// these would be generated with k8s deepcopy-gen with the following comment:
// +k8s:deepcopy-gen=true
//
// You'll need to remember to also edit Makefile to include the directory in
// which you define the structs as part of the generate-k8s-api target.
func (b *Bee) DeepCopy() *Bee {
	b2 := *b
	return &b2
}

// beeTableSchema is a table schema definition for storing the Bee objects. It defines the name
// for the table and how to index the objects inserted into that table.
var beeTableSchema = &memdb.TableSchema{
	Name: "bees",
	Indexes: map[string]*memdb.IndexSchema{
		// id is the primary index and must always be defined.
		// Here we're indexing our bees primarily by their UUID, so we
		// can use the predefined schema for it.
		"id": statedb.UUIDIndexSchema,
		"kind": {
			Name:         "kind", // Name of the index. Must match the map key one line above.
			AllowMissing: false,  // Whether this index can be unset, e.g. empty string or other zero value.
			Unique:       false,  // Whether this index is unique. Inserts where multiple unique indexes conflict will be rejected.

			// go-memdb provides generic indexers that use reflection to extract the indexing key. Here we're using
			// the string field indexer to extract the "Kind" field from the struct and convert that into the index key (a byte slice).
			// Indexers can also be defined manually for specific types (see the definition of StringFieldIndex for a starting point).
			Indexer: &memdb.StringFieldIndex{Field: "Kind"},
		},
	},
}

type BeeTable = statedb.Table[*Bee]

// ByKind queries the bees by their kind
func ByKind(Kind Kind) statedb.Query {
	return statedb.Query{
		// Index is the index we want to query. Here we use the indexing
		// on the Kind field which is defined above in the schema.
		Index: statedb.Index("kind"),

		// Args are the arguments for querying the index. Index may support
		// multiple arguments (memdb.CompoundIndex for example), but here
		// we only have one.
		Args: []any{Kind},
	}
}

// beeHive defines our application. It has a database with a table for bees.
var beeHive = hive.New(
	// StateDB takes our table definitions and provides the sequencing for accessing and modifying
	// the tables.
	statedb.Cell,

	// Register the bee table with the database. This will provide statedb.Table[*Bee] to the whole hive.
	// You can also use NewPrivateTableCell to keep the Table[T] private to your module.
	statedb.NewTableCell[*Bee](beeTableSchema),

	// Use a wait group and a context to do some synchronization in the little play below.
	cell.Provide(
		func() (wg *sync.WaitGroup, ctx context.Context, cancel context.CancelFunc) {
			wg = &sync.WaitGroup{}
			ctx, cancel = context.WithCancel(context.Background())
			return
		}),

	// Run these functions one by one to play with the database. Note that we're assuming here that
	// the database does not need to be Start()'ed, which may not be the case when there are e.g. commit
	// hooks and persistence involved. In general "real work" should only start happening from a Start hook.
	cell.Invoke(
		observeDatabase,
		createBees,
		listBees,
		observeAndModifyBees,

		// Finally stop the hive.
		func(wg *sync.WaitGroup, cancel context.CancelFunc, s hive.Shutdowner) {
			cancel()
			wg.Wait()
			s.Shutdown()
		},
	),
)

func main() {
	beeHive.Run()
}

func createBees(db statedb.DB, beeTable BeeTable) {
	fmt.Printf("[createBees]\n")

	// Start a write transaction against the database. This "write locks" the database and other calls
	// to WriteTxn() will wait until we're finished. Readers however are unaffected.
	txn := db.WriteTxn()

	// Now that we have a write transaction, we can use it to modify the bee table by
	// asking for a writer.
	bees := beeTable.Writer(txn)

	// Create the queen bee
	if err := bees.Insert(&Bee{UUID: statedb.NewUUID(), Kind: QueenBee}); err != nil {
		// Insert can fail if the table's indexing is malformed, e.g. it has a StringFieldIndex
		// but the field it's referencing isn't in the provided struct. This is why it makes usually
		// sense to not expose Table[Obj] directly, but rather wrap it into a safer interface which
		// handles these errors, usually by fataling as it's a mistake by the programmer in the schema
		// or the query functions.
		panic(err)
	}

	// Create some worker bees
	for i := 0; i < 10; i++ {
		if err := bees.Insert(&Bee{UUID: statedb.NewUUID(), Kind: WorkerBee}); err != nil {
			panic(err)
		}
	}

	// And some drone bees
	for i := 0; i < 10; i++ {
		if err := bees.Insert(&Bee{UUID: statedb.NewUUID(), Kind: DroneBee}); err != nil {
			panic(err)
		}
	}

	// Finally commit our changes to the database.
	if err := txn.Commit(); err != nil {
		// Commit can fail if a commit hook fails, e.g. due to invalid changes to the table or
		// due to failure to persist the changes. Note that currently the support for commit hooks
		// is not yet implemented.
		panic(err)
	}

	// We can also abort transactions to throw away any changes we have accumulated:
	txn = db.WriteTxn()
	beeTable.Writer(txn).Insert(&Bee{UUID: statedb.NewUUID(), Kind: QueenBee}) // Nobody will see this second queen.
	txn.Abort()
}

func listBees(db statedb.DB, beeTable BeeTable) {
	fmt.Printf("[listBees]\n")

	// Create a read transaction to read from the bees table. A read transaction will essentially
	// just do an atomic read of the root tree pointer, so anything we do here will be against
	// an immutable snapshot of the database and will not affect any other readers or writers.
	// We must be careful not to mutate any of the objects though!
	txn := db.ReadTxn()

	// Create a bee table reader with the transaction.
	bees := beeTable.Reader(txn)

	// List all the bees using the 'All' query (this uses the mandatory 'id' index, so the order
	// is the lexicographical ordering of the UUIDs).
	it, err := bees.Get(statedb.All)
	if err != nil {
		// Reader methods may fail if the query or the schema is malformed. As mentioned above
		// in the first Insert() call, it's preferable to wrap Table[] behind a safer interface
		// to not expose these errors.
		panic(err)
	}

	// The returned iterator is an interface with the method "Next() (obj Obj, ok bool)", so it's
	// easy to iterate with a for loop. Even easier once the iterator proposal lands!
	fmt.Printf("All bees:\n")
	for bee, ok := it.Next(); ok; bee, ok = it.Next() {
		fmt.Printf("  [%s] %s\n", bee.UUID, bee.Kind)
	}

	// We can also query other indexes. Let's get all the worker bees. We're
	// using our predefined ByKind helper that creates the Query for us.
	it, err = bees.Get(ByKind(WorkerBee))
	if err != nil {
		// This would only fail if ByKind has a bug or schema has bad indexer.
		panic(err)
	}

	// The state package has few utilities for making the iteration in some common cases a bit easier.
	// ProcessEach iterates using a function that can return an error and stop the iteration.
	fmt.Printf("First 5 worker bees:\n")
	count := 0
	var stopIterErr = fmt.Errorf("stop")
	err = statedb.ProcessEach(
		it,
		func(bee *Bee) error {
			fmt.Printf("  [%s] %s\n", bee.UUID, bee.Kind)

			count++
			if count >= 5 {
				return stopIterErr
			}
			return nil
		})
	if !errors.Is(err, stopIterErr) {
		panic("oops")
	}
}

func modifyBees(db statedb.DB, beeTable BeeTable) {
	// Oh no, one of the drone bees died :-(
	txn := db.WriteTxn()
	bees := beeTable.Writer(txn)
	aDroneBee, _ := bees.First(ByKind(DroneBee))
	if aDroneBee != nil {
		// Delete the first drone bee we found.
		err := beeTable.Writer(txn).Delete(aDroneBee)
		if err != nil {
			// As with other queries, deletion can also fail due the indexing bugs.
			panic(err)
		}
		fmt.Printf("[modifyDees] Deleted drone bee %s\n", aDroneBee.UUID)
	}
	txn.Commit()
}

func observeAndModifyBees(wg *sync.WaitGroup, db statedb.DB, beeTable BeeTable) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		bees := beeTable.Reader(db.ReadTxn())

		// Get all the drone bees
		it, err := bees.Get(ByKind(DroneBee))
		if err != nil {
			panic(err)
		}
		nDrones := 0
		for _, ok := it.Next(); ok; _, ok = it.Next() {
			nDrones++
		}
		fmt.Printf("[observeBees] There are %d drone bees\n", nDrones)

		// Go modify the bees in the background.
		go modifyBees(db, beeTable)

		// Some queries allow watching for changes. We can now
		// wait for the "kind" index to change in a way that
		// invalidates the iteration we just did above.
		<-it.Invalidated()

		// We now need a new read transaction in order to observe the new
		// state of the database.
		bees = beeTable.Reader(db.ReadTxn())

		it, err = bees.Get(ByKind(DroneBee))
		if err != nil {
			panic(err)
		}

		nDrones = 0
		for _, ok := it.Next(); ok; _, ok = it.Next() {
			nDrones++
		}
		fmt.Printf("[observeBees] Drone bees changed, there are now %d of them\n", nDrones)
	}()
}

func observeDatabase(wg *sync.WaitGroup, ctx context.Context, db statedb.DB) {
	// The whole database can also be observed. This is useful when multiple tables need to be watched for changes
	// in order to trigger reconciliation. Combining this with revision-based LowerBound queries provides fast
	// access to the new changes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for change := range stream.ToChannel[statedb.Event](ctx, db) {
			fmt.Printf("[observeDatabase] table %q changed!\n", change.Table)
		}
	}()
}
