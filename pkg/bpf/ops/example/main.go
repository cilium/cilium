// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/cilium/cilium/pkg/time"
)

func main() {
	cmd := cobra.Command{
		Use: "example",
		Run: func(_ *cobra.Command, args []string) {
			if err := Hive.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Run: %s\n", err)
			}
		},
	}

	// Register command-line flags. Currently only
	// has --directory for specifying where to store
	// the examples.
	Hive.RegisterFlags(cmd.Flags())

	// Add the "hive" command for inspecting the object graph:
	//
	//  $ go run . hive
	//
	cmd.AddCommand(Hive.Command())

	cmd.Execute()
}

var Hive = hive.New(
	statedb.Cell,
	job.Cell,
	reconciler.Cell,

	cell.Module(
		"example",
		"BPF map reconciler example",

		cell.Provide(
			// Creates RWTable[*Example] and registers it with the database.
			NewExampleTable,

			// Creates the example BPF map. On start the BPF map is opened and pinned.
			newExampleMap,
		),

		// Construct the configuration and operations for the reconciler
		cell.ProvidePrivate(newReconcilerConfigAndOperations),

		// Construct the reconciler for *Example objects.
		cell.Provide(reconciler.New[*Example]),

		cell.Invoke(registerHTTPServer),
	),

	cell.Invoke(createSomeStuff),
)

func newReconcilerConfigAndOperations(m exampleMap) (reconciler.Config[*Example], reconciler.Operations[*Example]) {
	ops, batchOps := ops.NewMapOps[*Example](m.Map)

	// Reconcile at most every 5 milliseconds to allow for batch to build
	// up.
	limiter := rate.NewLimiter(5*time.Millisecond, 1)

	cfg := reconciler.Config[*Example]{
		FullReconcilationInterval: 5 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Minute,
		IncrementalRoundSize:      100000,
		GetObjectStatus:           (*Example).GetStatus,
		WithObjectStatus:          (*Example).WithStatus,
		RateLimiter:               limiter,
		Operations:                ops,
		BatchOperations:           batchOps,
	}
	return cfg, ops
}

func createSomeStuff(db *statedb.DB, t statedb.RWTable[*Example]) {
	txn := db.WriteTxn(t)
	defer txn.Commit()

	for i := 0; i < 1000; i++ {
		t.Insert(txn, &Example{
			ExKey:   ExampleKey{uint64(i)},
			ExValue: ExampleValue{uint64(i)},
			Status:  reconciler.StatusPending(),
		})
	}
}

func registerHTTPServer(
	lc hive.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB,
	examples statedb.RWTable[*Example],
	exampleReconciler reconciler.Reconciler[*Example]) {

	mux := http.NewServeMux()

	// For dumping the database:
	// curl -s http://localhost:8080/statedb | jq .
	mux.HandleFunc("/statedb", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		db.ReadTxn().WriteJSON(w)
	})

	// For creating and deleting:
	// curl -d 1234 http://localhost:8080/examples/20
	// curl -XDELETE http://localhost:8080/examples/20
	mux.HandleFunc("/examples/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		idString, ok := strings.CutPrefix(r.URL.Path, "/examples/")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		parts := strings.Split(idString, "-")
		from, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		to := from
		if len(parts) > 1 {
			to, err = strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		var commitTime time.Duration
		switch r.Method {
		case "POST":

			content, err := safeio.ReadAllLimit(r.Body, 8)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			value, err := strconv.ParseUint(string(content), 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			txn := db.WriteTxn(examples)
			for id := from; id <= to; id++ {
				examples.Insert(
					txn,
					&Example{
						ExKey:   ExampleKey{ID: id},
						ExValue: ExampleValue{X: value},
						Status:  reconciler.StatusPending(),
					})
			}
			txn.Commit()

			commitTime = time.Since(start)
			log.Infof("Inserted %d - %d with value %d in %s", from, to, value, commitTime)

		case "DELETE":
			txn := db.WriteTxn(examples)
			for id := from; id <= to; id++ {
				ex, _, ok := examples.First(txn, ExampleIDIndex.Query(id))
				if ok {
					examples.Insert(
						txn,
						ex.WithStatus(reconciler.StatusPendingDelete()))
				}
			}
			txn.Commit()
			commitTime = time.Since(start)
			log.Infof("Marked %d - %d for deletion", from, to)
		}

		// Wait for the last inserted object to be reconciled.
		for {
			obj, _, watch, ok := examples.FirstWatch(db.ReadTxn(), ExampleIDIndex.Query(to))
			if (r.Method == "DELETE" && !ok) || (ok && obj.Status.Kind == reconciler.StatusKindDone) {
				break
			}
			select {
			case <-r.Context().Done():
				return
			case <-watch:
			}
		}

		w.WriteHeader(http.StatusOK)
		duration := time.Since(start)
		opsPerSec := float64(to-from+1) / (float64(duration) / float64(time.Second))
		fmt.Fprintf(w, "OK in %s (%.2f ops/s) (commit took %s)\n", duration, opsPerSec, commitTime)

	})

	server := http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			log.Infof("Serving API at %s", server.Addr)
			go server.ListenAndServe()
			return nil
		},
		OnStop: func(ctx hive.HookContext) error {
			return server.Shutdown(ctx)
		},
	})

}
