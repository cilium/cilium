// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/cilium/cilium/pkg/time"
)

// This is a simple example of the statedb reconciler. It implements an
// HTTP API for creating and deleting "memos" that are stored on the
// disk.
//
// To run the application:
//
//   $ go run .
//   (ctrl-c to stop)
//
// To create a memo:
//
//   $ curl -d 'hello world' http://localhost:8080/memos/greeting
//   $ cat memos/greeting
//
// To delete a memo:
//
//   $ curl -XDELETE http://localhost:8080/memos/greeting
//
// The application builds on top of the reconciler which retries any failed
// operations and also does periodic "full reconciliation" to prune unknown
// memos and check that the stored memos are up-to-date. To test the resilence
// you can try out the following:
//
//   # Create 'memos/greeting'
//   $ curl -d 'hello world' http://localhost:8080/memos/greeting
//
//   # Make the file read-only and try changing it:
//   $ chmod a-w memos/greeting
//   $ curl -d 'hei maailma' http://localhost:8080/memos/greeting
//   # (You should now see the update operation hitting permission denied)
//
//   # The reconciliation state can be observed in the Table[*Memo]:
//   $ curl -q http://localhost:8080/statedb | jq .
//
//   # Let's give write permissions back:
//   $ chmod u+w memos/greeting
//   # (The update operation should now succeed)
//   $ cat memos/greeting
//   $ curl -s http://localhost:8080/statedb | jq .
//
//   # The full reconciliation runs every 10 seconds. We can see it in
//   # action by modifying the contents of our greeting or by creating
//   # a file directly:
//   $ echo bogus > memos/bogus
//   $ echo mangled > memos/greeting
//   # (wait up to 10 seconds)
//   $ cat memos/bogus
//   $ cat memos/greeting
//

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
	// the memos.
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
		"Reconciler example",

		cell.Config(Config{}),

		cell.Provide(
			// Create and register the RWTable[*Memo]
			NewMemoTable,

			// Provide the Operations[*Memo] for reconciling Memos.
			NewMemoOps,

			// Construct the configuration for the memo reconciler.
			NewReconcilerConfig,
		),

		// Create and register the reconciler for memos. This takes
		// in Operations[*Memo] and Config[*Memo] and constructs a
		// reconciler that will watch Table[*Memo] for changes and
		// using Operations[*Memo] updates the memo files on disk.
		cell.Invoke(reconciler.Register[*Memo]),

		cell.Invoke(registerHTTPServer),
	),
)

func NewReconcilerConfig(ops reconciler.Operations[*Memo]) reconciler.Config[*Memo] {
	return reconciler.Config[*Memo]{
		FullReconcilationInterval: 10 * time.Second,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   5 * time.Second,
		IncrementalRoundSize:      100,
		GetObjectStatus:           (*Memo).GetStatus,
		WithObjectStatus:          (*Memo).WithStatus,
		Operations:                ops,
	}
}

// maxMemoSize defines the maximum size for a memo.
const maxMemoSize = 1024

func registerHTTPServer(
	lc cell.Lifecycle,
	log logrus.FieldLogger,
	db *statedb.DB,
	memos statedb.RWTable[*Memo]) {

	mux := http.NewServeMux()

	// For dumping the database:
	// curl -s http://localhost:8080/statedb | jq .
	mux.HandleFunc("/statedb", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		db.ReadTxn().WriteJSON(w)
	})

	// For creating and deleting memos:
	// curl -d 'foo' http://localhost:8080/memos/bar
	// curl -XDELETE http://localhost:8080/memos/bar
	mux.HandleFunc("/memos/", func(w http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/memos/")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		txn := db.WriteTxn(memos)
		defer txn.Commit()

		switch r.Method {
		case "POST":
			content, err := safeio.ReadAllLimit(r.Body, maxMemoSize)
			if err != nil {
				return
			}
			memos.Insert(
				txn,
				&Memo{
					Name:    name,
					Content: string(content),
					Status:  reconciler.StatusPending(),
				})
			log.Infof("Inserted memo '%s'", name)
			w.WriteHeader(http.StatusOK)

		case "DELETE":
			memo, _, ok := memos.First(txn, MemoNameIndex.Query(name))
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			memos.Insert(
				txn,
				memo.WithStatus(reconciler.StatusPendingDelete()))
			log.Infof("Deleted memo '%s'", name)
			w.WriteHeader(http.StatusOK)
		}
	})

	server := http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			log.Infof("Serving API at %s", server.Addr)
			go server.ListenAndServe()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			return server.Shutdown(ctx)
		},
	})

}
