package datapath

import (
	"time"

	"github.com/cilium/cilium/pkg/bpf/ops"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

var (
	Cell = cell.Module(
		"datapath",
		"Demo Datapath",

		// The frontend and backend tables
		tablesCell,

		// The frontend and backend BPF maps
		mapsCell,

		// Reconcilers for the BPF maps
		reconcilers,
	)

	reconcilers = cell.Group(
		cell.ProvidePrivate(
			// Provide read-write access to the Frontend and Backend tables
			// for the reconciler.
			func(fes Frontends) statedb.RWTable[*Frontend] {
				return fes.rw
			},
			func(bes Backends) statedb.RWTable[*Backend] {
				return bes.rw
			},

			newFrontendsReconcilerConfig,
			newBackendsReconcilerConfig,
		),

		// Create and register reconcilers for the BPF maps
		cell.Invoke(
			reconciler.Register[*Frontend],
			reconciler.Register[*Backend],
		),
	)
)

func newFrontendsReconcilerConfig(m frontendsMap) reconciler.Config[*Frontend] {
	ops, batchOps := ops.NewMapOps[*Frontend](m.Map)
	return reconciler.Config[*Frontend]{
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Second,
		IncrementalRoundSize:      1000,
		GetObjectStatus: func(fe *Frontend) reconciler.Status {
			return fe.Status
		},
		WithObjectStatus: func(fe *Frontend, newStatus reconciler.Status) *Frontend {
			fe = fe.Clone()
			fe.Status = newStatus
			return fe
		},
		RateLimiter:     nil,
		Operations:      ops,
		BatchOperations: batchOps,
	}
}

func newBackendsReconcilerConfig(m backendsMap) reconciler.Config[*Backend] {
	ops, batchOps := ops.NewMapOps[*Backend](m.Map)
	return reconciler.Config[*Backend]{
		FullReconcilationInterval: 10 * time.Minute,
		RetryBackoffMinDuration:   100 * time.Millisecond,
		RetryBackoffMaxDuration:   time.Second,
		IncrementalRoundSize:      1000,
		GetObjectStatus: func(be *Backend) reconciler.Status {
			return be.Status
		},
		WithObjectStatus: func(be *Backend, newStatus reconciler.Status) *Backend {
			be = be.Clone()
			be.Status = newStatus
			return be
		},
		RateLimiter:     nil,
		Operations:      ops,
		BatchOperations: batchOps,
	}

}
