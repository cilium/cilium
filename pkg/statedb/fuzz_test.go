// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb_test

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// Run test with "--debug" for log output.
var debug = flag.Bool("debug", false, "Enable debug logging")

type debugLogger struct {
	l *log.Logger
}

func (l *debugLogger) log(fmt string, args ...any) {
	if l == nil {
		return
	}
	l.l.Printf(fmt, args...)
}

func newDebugLogger(worker int) *debugLogger {
	if !*debug {
		return nil
	}
	logger := log.New(os.Stdout, fmt.Sprintf("worker[%03d] | ", worker), 0)
	return &debugLogger{logger}
}

const (
	numUniqueIDs  = 20
	numWorkers    = 10
	numIterations = 1000
)

type fuzzObj struct {
	id    uint64
	value uint64
}

func mkID() uint64 {
	return uint64(rand.Int63n(numUniqueIDs))
}

var idIndex = statedb.Index[fuzzObj, uint64]{
	Name: "id",
	FromObject: func(obj fuzzObj) index.KeySet {
		return index.NewKeySet(index.Uint64(obj.id))
	},
	FromKey: func(n uint64) []byte {
		return index.Uint64(n)
	},
	Unique: true,
}

var (
	tableFuzz1, _ = statedb.NewTable[fuzzObj]("fuzz1", idIndex)
	tableFuzz2, _ = statedb.NewTable[fuzzObj]("fuzz2", idIndex)
	tableFuzz3, _ = statedb.NewTable[fuzzObj]("fuzz3", idIndex)
	fuzzTables    = []statedb.TableMeta{tableFuzz1, tableFuzz2, tableFuzz3}
	fuzzDB, _     = statedb.NewDB(fuzzTables, statedb.NewMetrics())
)

func randomSubset[T any](xs []T) []T {
	xs = slices.Clone(xs)
	rand.Shuffle(len(xs), func(i, j int) {
		xs[i], xs[j] = xs[j], xs[i]
	})
	n := 1 + rand.Intn(len(xs)-1)
	return xs[:n]
}

type actionLog interface {
	append(actionLogEntry)
}

type realActionLog struct {
	lock.Mutex
	log []actionLogEntry
}

func (a *realActionLog) append(e actionLogEntry) {
	a.Lock()
	a.log = append(a.log, e)
	a.Unlock()
}

func (a *realActionLog) validate(db *statedb.DB, t *testing.T) {
	a.Lock()
	defer a.Unlock()

	// Collapse the log down to objects that are alive at the end.
	alive := map[statedb.Table[fuzzObj]]sets.Set[uint64]{}
	for _, e := range a.log {
		aliveThis, ok := alive[e.table]
		if !ok {
			aliveThis = sets.New[uint64]()
			alive[e.table] = aliveThis
		}
		switch e.act {
		case actInsert:
			aliveThis.Insert(e.id)
		case actDelete:
			aliveThis.Delete(e.id)
		case actDeleteAll:
			aliveThis.Clear()
		}
	}

	for table, expected := range alive {
		txn := db.ReadTxn()
		iter, _ := table.All(txn)
		actual := sets.New[uint64]()
		for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
			actual.Insert(obj.id)
		}
		require.True(t, expected.Equal(actual), "validate failed, mismatching ids: %v", actual.SymmetricDifference(expected))
	}
}

type nopActionLog struct {
}

func (nopActionLog) append(e actionLogEntry) {}

const (
	actInsert = iota
	actDelete
	actDeleteAll
)

type actionLogEntry struct {
	table statedb.Table[fuzzObj]
	act   int
	id    uint64
	value uint64
}

type action func(log *debugLogger, actLog actionLog, txn statedb.WriteTxn, target statedb.RWTable[fuzzObj])

func insertAction(log *debugLogger, actLog actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	value := rand.Uint64()
	log.log("%s: Insert %d", table.Name(), id)
	table.Insert(txn, fuzzObj{id, value})
	actLog.append(actionLogEntry{table, actInsert, id, value})
}

func deleteAction(log *debugLogger, actLog actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	log.log("%s: Delete %d", table.Name(), id)
	table.Delete(txn, fuzzObj{id, 0})
	actLog.append(actionLogEntry{table, actDelete, id, 0})
}

func deleteAllAction(log *debugLogger, actLog actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	log.log("%s: DeleteAll", table.Name())
	table.DeleteAll(txn)
	actLog.append(actionLogEntry{table, actDeleteAll, 0, 0})
}

func allAction(log *debugLogger, _ actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	iter, _ := table.All(txn)
	log.log("%s: All => %d found", table.Name(), len(statedb.Collect(iter)))
}

func getAction(log *debugLogger, _ actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	iter, _ := table.Get(txn, idIndex.Query(mkID()))
	log.log("%s: Get(%d) => %d found", table.Name(), id, len(statedb.Collect(iter)))
}

func firstAction(log *debugLogger, _ actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	_, rev, ok := table.First(txn, idIndex.Query(id))
	log.log("%s: First(%d) => rev=%d, ok=%v", table.Name(), id, rev, ok)
}

func lastAction(log *debugLogger, _ actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	_, rev, ok := table.First(txn, idIndex.Query(id))
	log.log("%s: First(%d) => rev=%d, ok=%v", table.Name(), id, rev, ok)
}

func lowerboundAction(log *debugLogger, _ actionLog, txn statedb.WriteTxn, table statedb.RWTable[fuzzObj]) {
	id := mkID()
	iter, _ := table.LowerBound(txn, idIndex.Query(id))
	log.log("%s: LowerBound(%d) => %d found", table.Name(), id, len(statedb.Collect(iter)))
}

var actions = []action{
	insertAction,
	insertAction,
	insertAction,
	insertAction,
	insertAction,
	insertAction,
	insertAction,

	deleteAction,
	deleteAction,
	deleteAllAction,

	allAction,
	getAction,
	firstAction,
	lastAction,
	lowerboundAction,

	allAction,
	getAction,
	firstAction,
	lastAction,
	lowerboundAction,
}

func randomAction() action {
	return actions[rand.Intn(len(actions))]
}

func fuzzWorker(realActionLog *realActionLog, worker int, iterations int) {
	log := newDebugLogger(worker)
	for iterations > 0 {
		targets := randomSubset(fuzzTables)
		txn := fuzzDB.WriteTxn(targets[0], targets[1:]...)

		// Try to run other goroutines with write lock held.
		runtime.Gosched()

		var actLog actionLog = realActionLog
		abort := false
		if rand.Intn(10) == 0 {
			abort = true
			actLog = nopActionLog{}
		}

		for _, target := range targets {
			act := randomAction()
			act(log, actLog, txn, target.(statedb.RWTable[fuzzObj]))
			runtime.Gosched()
		}
		runtime.Gosched()

		if abort {
			log.log("Abort")
			txn.Abort()
		} else {
			log.log("Commit")
			txn.Commit()
		}
		iterations--
	}
}

func TestDB_Fuzz(t *testing.T) {
	t.Parallel()

	fuzzDB.Start(context.TODO())
	defer fuzzDB.Stop(context.TODO())

	var actionLog realActionLog
	var wg sync.WaitGroup
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		i := i
		go func() {
			fuzzWorker(&actionLog, i, numIterations)
			wg.Done()
		}()
	}
	wg.Wait()
	actionLog.validate(fuzzDB, t)

}
