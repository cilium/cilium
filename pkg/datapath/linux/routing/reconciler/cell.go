// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/time"
)

// Cell maintains desired endpoint policy-routing rules for supported cloud IPAM modes.
var Cell = cell.Module(
	"cloud-routing-rule-reconciler",
	"Reconciles endpoint routing rules for cloud IPAM",

	cell.ProvidePrivate(
		newEndpointRulesTable,
		newEndpointRulesManager,
		newEndpointRulesOperations,
	),
	cell.Provide(
		statedb.RWTable[*EndpointRules].ToTable,
	),
	cell.Invoke(
		registerEndpointRulesReconciler,
	),
)

type endpointRulesReconcilerParams struct {
	cell.In

	ReconcilerParams statedbReconciler.Params
	Table            statedb.RWTable[*EndpointRules]
	Manager          *endpointRulesManager
	Operations       *endpointRulesOperations
}

func registerEndpointRulesReconciler(p endpointRulesReconcilerParams) error {
	if !p.Manager.enabled {
		return nil
	}

	if _, err := statedbReconciler.Register(
		p.ReconcilerParams,
		p.Table,
		(*EndpointRules).Clone,
		(*EndpointRules).SetStatus,
		(*EndpointRules).GetStatus,
		p.Operations,
		nil,
		statedbReconciler.WithPruning(30*time.Minute),
		statedbReconciler.WithRefreshing(30*time.Minute, nil),
	); err != nil {
		return err
	}

	return nil
}
