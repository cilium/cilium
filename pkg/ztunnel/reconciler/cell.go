// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/daemon/k8s"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

var Cell = cell.Module(
	"enrollment-reconciler",
	"Reconciler for namespace enrollment for ztunnel mTLS",
	cell.Provide(
		NewEnrolledNamespacesTable,
		NewEnrollmentReconciler,
	),
	cell.Invoke(statedb.Derive("derive-desired-mtls-namespace-enrollments", defaultNamespaceToEnrolledNamespace)),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*EnrolledNamespace],
	tbl statedb.RWTable[*EnrolledNamespace],
) error {
	_, err := reconciler.Register(
		params,
		tbl,
		(*EnrolledNamespace).Clone,
		(*EnrolledNamespace).SetStatus,
		(*EnrolledNamespace).GetStatus,
		ops,
		nil, // no batch operations support
		reconciler.WithoutPruning(),
	)
	if err != nil {
		return err
	}
	return nil
}

func defaultNamespaceToEnrolledNamespace(ns k8s.Namespace, deleted bool) (*EnrolledNamespace, statedb.DeriveResult) {
	enrolled := true
	if mtlsValue, exists := ns.Labels["mtls-enabled"]; !exists || mtlsValue != "true" {
		enrolled = false
	}
	if deleted || !enrolled {
		return &EnrolledNamespace{
			Name:   ns.Name,
			Status: reconciler.StatusPending(),
		}, statedb.DeriveDelete
	}
	return &EnrolledNamespace{
		Name:   ns.Name,
		Status: reconciler.StatusPending(),
	}, statedb.DeriveInsert
}
