// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Cell maintains desired endpoint policy-routing rules for supported cloud IPAM modes.
var Cell = cell.Module(
	"cloud-routing-rule-reconciler",
	"Reconciles endpoint routing rules for cloud IPAM",

	cell.ProvidePrivate(newEndpointRulesTable),
	cell.Provide(statedb.RWTable[*EndpointRules].ToTable),
	cell.Invoke(registerEndpointRulesReconciler),
)

type params struct {
	cell.In

	Logger           *slog.Logger
	Lifecycle        cell.Lifecycle
	JobGroup         job.Group
	ReconcilerParams statedbReconciler.Params
	DB               *statedb.DB
	Table            statedb.RWTable[*EndpointRules]
	DaemonConfig     *option.DaemonConfig
	IPAM             *ipam.IPAM
	EndpointManager  endpointmanager.EndpointManager
	Restorer         promise.Promise[endpointstate.Restorer]
	LocalNodeStore   *node.LocalNodeStore
}

func registerEndpointRulesReconciler(p params) error {
	if p.DaemonConfig.DryMode {
		return nil
	}

	ipamMode := p.DaemonConfig.IPAMMode()
	if !isCloudIPAMMode(ipamMode) {
		return nil
	}

	manager := newEndpointRulesManager(
		p.Logger,
		p.DB,
		p.Table,
		p.IPAM,
		p.EndpointManager,
		p.Restorer,
	)
	// Subscribe during cell registration so no restored endpoint event is lost.
	p.EndpointManager.Subscribe(manager)
	p.Lifecycle.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			p.EndpointManager.Unsubscribe(manager)
			return nil
		},
	})

	p.JobGroup.Add(job.OneShot(
		"initialize-cloud-endpoint-routing-rules",
		manager.initialize,
		job.WithRetry(-1, &job.ExponentialBackoff{
			Min: time.Second,
			Max: time.Minute,
		}),
	))

	ops := &endpointRulesOperations{
		logger:          p.Logger,
		ipam:            p.IPAM,
		ipamMode:        ipamMode,
		endpointManager: p.EndpointManager,
		localNodeStore:  p.LocalNodeStore,
	}
	if _, err := statedbReconciler.Register(
		p.ReconcilerParams,
		p.Table,
		(*EndpointRules).Clone,
		(*EndpointRules).SetStatus,
		(*EndpointRules).GetStatus,
		ops,
		nil,
		statedbReconciler.WithPruning(30*time.Minute),
		statedbReconciler.WithRefreshing(30*time.Minute, nil),
	); err != nil {
		return err
	}

	return nil
}

func isCloudIPAMMode(ipamMode string) bool {
	return ipamMode == ipamOption.IPAMENI || ipamMode == ipamOption.IPAMAzure
}
