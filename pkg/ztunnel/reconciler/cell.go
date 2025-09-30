// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"enrollment-reconciler",
	"Reconciler for namespace enrollment for ztunnel mTLS",
	cell.Provide(reconciler.NewExpVarMetrics),
	cell.Provide(
		NewEnrolledNamespacesTable,
		NewEnrollmentReconciler,
	),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*Namespace],
	tbl statedb.RWTable[*Namespace],
	m *reconciler.ExpVarMetrics,
) error {
	_, err := reconciler.Register(
		params,
		tbl,
		(*Namespace).Clone,
		(*Namespace).SetStatus,
		(*Namespace).GetStatus,
		ops,
		nil, // no batch operations support

		reconciler.WithMetrics(m),
		reconciler.WithPruning(time.Minute),
		reconciler.WithRefreshing(time.Minute, nil),
	)
	if err != nil {
		return err
	}
	return nil
}
