package main

import (
	"fmt"
	"math/rand"
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

		Cell,
		cell.Invoke(
			modify,
			healthReport,
		),
	)
	h.PrintObjects()
	h.Run()
}

func modify(db *statedb.DB, t statedb.RWTable[*SysctlSetting]) {
	go func() {
		for {
			time.Sleep(500 * time.Millisecond)

			n := rand.Intn(5)
			x := rand.Intn(5)
			key := fmt.Sprintf("foo%d", n)
			val := fmt.Sprintf("bar%d", x)

			txn := db.WriteTxn(t)
			if x == 0 {
				obj, _, ok := t.First(txn, SysctlKeyIndex.Query(key))
				if ok {
					obj = obj.WithStatus(reconciler.StatusPendingDelete())
					t.Insert(txn, obj)
				}
			} else {
				t.Insert(txn, &SysctlSetting{
					Key: key, Value: val, status: reconciler.StatusPending(),
				})
			}
			txn.Commit()
		}
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
