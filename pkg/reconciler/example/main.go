package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/statedb"
)

var fakeProcPath = "/tmp/fakeproc"

func main() {
	os.MkdirAll(fakeProcPath, 0755)
	h := hive.New(
		statedb.Cell,
		job.Cell,
		reconciler.Cell,

		cell.Group(
			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{}
			}),
			metrics.Cell,
		),

		SysctlCell,

		IPTablesCell,

		cell.Invoke(
			modify,
			modifyIPTables,
			healthReport,
			printPendingOrErrored,
		),
	)
	h.PrintObjects()
	h.Run()
}

func modify(s *Sysctl) {
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)

			n := rand.Intn(5)
			x := rand.Intn(5)
			key := fmt.Sprintf("foo%d", n)
			val := fmt.Sprintf("bar%d", x)

			s.Set(key, val)

			// Wait until the new values are reconciled.
			s.Wait(context.TODO())

		}
	}()
}

func modifyIPTables(db *statedb.DB, t statedb.RWTable[*Rule]) {
	go func() {
		txn := db.WriteTxn(t)
		t.Insert(txn, &Rule{
			TableChain: TableChainFilterInput,
			IPv6:       false,
			Comment:    "testing",
			Args: []ToArgs{
				Source{IP: netip.MustParseAddr("1.2.3.4"), Port: nil},
				OutDevice("eth0"),
			},
			Jump:   JumpAccept,
			Status: reconciler.StatusPending(),
		})
		txn.Commit()
	}()
}

func healthReport(health cell.Health) {
	go func() {
		for {
			time.Sleep(time.Second)

			for _, status := range health.All() {
				fmt.Println(status.String())
			}
		}

	}()

}

func printPendingOrErrored(db *statedb.DB, t statedb.Table[*SysctlSetting]) {
	go func() {
		for {
			fmt.Printf("Sysctl:\n")
			txn := db.ReadTxn()
			_, watch := t.All(txn)
			pending, _ := t.Get(txn, SysctlStatusIndex.Query(reconciler.StatusKindPending))
			errored, _ := t.Get(txn, SysctlStatusIndex.Query(reconciler.StatusKindError))
			iter := statedb.NewDualIterator(pending, errored)

			for obj, _, _, ok := iter.Next(); ok; obj, _, _, ok = iter.Next() {
				fmt.Printf("\t%s: %s\n", obj.Key, obj.Status)
			}

			<-watch
		}
	}()
}
