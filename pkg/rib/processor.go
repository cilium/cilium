// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"context"
	"slices"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
)

type processorIn struct {
	cell.In

	DB  *statedb.DB
	RIB RIB
	FIB FIB

	LC    cell.Lifecycle
	JR    job.Registry
	Scope cell.Scope
}

// processor is responsible for calculating best paths from RIB and sync them
// to FIB.
type processor struct {
	db  *statedb.DB
	rib RIB
	fib FIB
}

func (p *processor) selectBest(rt Route) (Route, bool) {
	it, _ := p.rib.Get(p.db.ReadTxn(),
		RIBVRFPrefixIndex.Query(VRFPrefix{
			VRF:    rt.VRF,
			Prefix: rt.Prefix,
		}),
	)
	rts := statedb.Collect(it)
	if len(rts) == 0 {
		// There's no route anymore
		return Route{}, false
	} else {
		// Recalculate best path
		return slices.MinFunc(rts, func(rt1, rt2 Route) int {
			d1 := rt1.Proto.Distance
			d2 := rt2.Proto.Distance
			switch {
			case d1 < d2:
				return -1
			case d1 > d2:
				return 1
			default:
				return 0
			}
		}), true
	}
}

func (p *processor) bestPathSelection(ctx context.Context, health cell.HealthReporter) error {
	wtxn := p.db.WriteTxn(p.rib)
	dt, err := p.rib.DeleteTracker(wtxn, "best-path-selection")
	if err != nil {
		wtxn.Abort()
		health.Stopped("failed to register RIB delete tracker")
		return err
	}
	wtxn.Commit()

	rtxn := p.db.ReadTxn()

	for {
		watch := dt.Iterate(rtxn, func(rt Route, _ bool, _ statedb.Revision) {
			var err error

			best, found := p.selectBest(rt)

			wtxn := p.db.WriteTxn(p.fib)

			if found {
				// Promote next best path
				_, _, err = p.fib.Insert(wtxn, best)
			} else {
				// No route to promote. Just delete the existing one.
				_, _, err = p.fib.Delete(wtxn, best)
			}

			wtxn.Commit()

			if err != nil {
				health.Degraded("FIB update failed", err)
			} else {
				health.OK("FIB is up-to-date")
			}
		})

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
		}

		rtxn = p.db.ReadTxn()
	}
}

func registerProcessor(in processorIn) error {
	p := &processor{
		db:  in.DB,
		rib: in.RIB,
		fib: in.FIB,
	}

	jg := in.JR.NewGroup(in.Scope)
	jg.Add(job.OneShot("best-path-selection", p.bestPathSelection))
	in.LC.Append(jg)

	return nil
}
