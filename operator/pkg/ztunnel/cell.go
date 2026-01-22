// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/operator/pkg/ztunnel/config"
	ztunnelReconciler "github.com/cilium/cilium/operator/pkg/ztunnel/reconciler"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

// Cell manages SPIRE enrollment for namespaces when ztunnel encryption is enabled.
var Cell = cell.Module(
	"ztunnel",
	"ZTunnel SPIRE Enrollment",

	cell.Config(config.DefaultConfig),
	cell.Provide(
		k8s.NewNamespaceTableAndReflector,
		table.NewEnrolledNamespacesTable,
		ztunnelReconciler.NewServiceAccountTable,
		ztunnelReconciler.NewEnrollmentReconciler,
	),
	cell.Invoke(statedb.Derive("derive-desired-mtls-namespace-enrollments", table.K8sNamespaceToEnrolledNamespace)),
	cell.Invoke(registerEnrollmentReconciler),
)

func registerEnrollmentReconciler(
	cfg config.Config,
	params reconciler.Params,
	ops reconciler.Operations[*table.EnrolledNamespace],
	tbl statedb.RWTable[*table.EnrolledNamespace],
) error {
	if !cfg.EnableZTunnel {
		return nil
	}
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
