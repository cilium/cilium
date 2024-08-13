// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamicconfig

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type controllerParams struct {
	cell.In

	Logger           *slog.Logger
	JobGroup         job.Group
	Config           config
	StateDB          *statedb.DB
	DynamicConfigMap k8s.DynamicConfigMapResource
}

type Controller struct {
	logger *slog.Logger

	jobGroup         job.Group
	db               *statedb.DB
	configTable      statedb.RWTable[*ConfigEntry]
	dynamicConfigMap k8s.DynamicConfigMapResource
}

func registerController(table statedb.RWTable[*ConfigEntry], params controllerParams) {
	if !params.Config.EnableDynamicConfig {
		return
	}

	c := &Controller{
		logger:           params.Logger,
		jobGroup:         params.JobGroup,
		db:               params.StateDB,
		configTable:      table,
		dynamicConfigMap: params.DynamicConfigMap,
	}

	c.jobGroup.Add(job.OneShot("cilium-config-cm-watcher", c.processConfigChanges))
}

func (c Controller) processConfigChanges(ctx context.Context, _ cell.Health) error {
	for event := range c.dynamicConfigMap.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.computeChanges(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c Controller) computeChanges(newConfigMap *v1.ConfigMap) {
	var entries []ConfigEntry
	for k, v := range newConfigMap.Data {
		entries = append(entries, NewConfigEntry(k, v))
	}
	c.upsertEntry(entries)
}
