package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/reconciler"
	"github.com/cilium/cilium/pkg/reconciler/example/reconcilers"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var fakeProcPath = "/tmp/fakeproc"

func main() {
	os.MkdirAll(fakeProcPath, 0755)
	h := hive.New(
		cell.Provide(func() (*netns.NsHandle, error) {
			h, err := netns.New()
			// Using a pointer here so this works with the optional struct tag.
			// Likely better to make NsHandle mandatory for devices controller etc.
			return &h, err
		}),

		statedb.Cell,
		job.Cell,
		reconciler.Cell,

		cell.Group(
			cell.Provide(func() *option.DaemonConfig {
				return &option.DaemonConfig{}
			}),
			metrics.Cell,
		),

		cell.Group(
			cell.Provide(func() linux.DevicesConfig {
				return linux.DevicesConfig{}
			}),
			linux.DevicesControllerCell,
		),

		//SysctlCell,

		//IPTablesCell,

		reconcilers.RoutesCell,

		cell.Invoke(
			//modify,
			//modifyIPTables,
			modifyRoutes,
			healthReport,
			dumpActualRoutes,
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

func modifyRoutes(r reconcilers.Routes, ns *netns.NsHandle) {
	nlHandle, _ := netlink.NewHandleAt(*ns)
	loIndex := 0
	if l, err := nlHandle.LinkByName("lo"); err == nil {
		if err := nlHandle.LinkSetUp(l); err != nil {
			panic(err)
		}
		loIndex = l.Attrs().Index
	} else {
		panic(err)
	}

	h := r.NewHandle("test")
	dst := netip.PrefixFrom(
		netip.MustParseAddr("172.16.0.1"),
		32,
	)
	h.Insert(tables.Route{
		Table:     unix.RT_TABLE_MAIN,
		LinkIndex: loIndex,
		Scope:     unix.RT_SCOPE_LINK,
		Dst:       dst,
	})
}

func dumpActualRoutes(db *statedb.DB, routes statedb.Table[*tables.Route]) {
	go func() {
		for {
			iter, watch := routes.All(db.ReadTxn())
			for r, _, ok := iter.Next(); ok; r, _, ok = iter.Next() {
				fmt.Printf("ACTUAL ROUTE: %v\n", r)
			}
			<-watch
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

func printPendingOrErrored(db *statedb.DB, t statedb.Table[*reconcilers.DesiredRoute]) {
	go func() {
		for {
			fmt.Printf("Desired routes:\n")
			txn := db.ReadTxn()
			iter, watch := t.All(txn)
			for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
				fmt.Printf("\t%s: %s\n", obj.Route.Dst, obj.Status)
			}

			<-watch
		}
	}()
}
