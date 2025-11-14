// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/ztunnel/table"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"enrollment-reconciler",
	"Reconciler for namespace enrollment for ztunnel mTLS",
	cell.Provide(
		table.NewEnrolledNamespacesTable,
		NewEnrollmentReconciler,
	),
	cell.Invoke(statedb.Derive("derive-desired-mtls-namespace-enrollments", table.K8sNamespaceToEnrolledNamespace)),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*table.EnrolledNamespace],
	tbl statedb.RWTable[*table.EnrolledNamespace],
) error {
	_, err := reconciler.Register(
		params,
		tbl,
		(*table.EnrolledNamespace).Clone,
		(*table.EnrolledNamespace).SetStatus,
		(*table.EnrolledNamespace).GetStatus,
		ops,
		nil, // no batch operations support
		reconciler.WithoutPruning(),
	)
	if err != nil {
		return err
	}
	return nil
}
