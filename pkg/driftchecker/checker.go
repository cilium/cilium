// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package driftchecker

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/cast"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/dynamicconfig"
)

type checkerParams struct {
	cell.In

	Lifecycle               cell.Lifecycle
	CellAllSettings         cell.AllSettings
	Health                  cell.Health
	DB                      *statedb.DB
	JobGroup                job.Group
	DynamicConfigTable      statedb.Table[dynamicconfig.DynamicConfig]
	Logger                  *slog.Logger
	CheckerConfig           config
	DynamicConfigCellConfig dynamicconfig.Config
	Metrics                 Metrics
}

type checker struct {
	cla          cell.AllSettings
	db           *statedb.DB
	dct          statedb.Table[dynamicconfig.DynamicConfig]
	l            *slog.Logger
	m            Metrics
	ignoredFlags sets.Set[string]
}

func Register(params checkerParams) {
	if !params.CheckerConfig.EnableDriftChecker || !params.DynamicConfigCellConfig.EnableDynamicConfig {
		return
	}

	c := checker{
		cla:          params.CellAllSettings,
		db:           params.DB,
		dct:          params.DynamicConfigTable,
		l:            params.Logger,
		m:            params.Metrics,
		ignoredFlags: sets.New[string](params.CheckerConfig.IgnoreFlagsDriftChecker...),
	}

	params.JobGroup.Add(job.OneShot("drift-checker", func(ctx context.Context, health cell.Health) error {
		return c.watchTableChanges(ctx)
	}))
}

func (c checker) watchTableChanges(ctx context.Context) error {
	for {
		tableKeys, channel := dynamicconfig.WatchAllKeys(c.db.ReadTxn(), c.dct)
		// Wait for table initialization
		if len(tableKeys) == 0 {
			<-channel
			continue
		}

		deltas := c.computeDelta(tableKeys, c.cla)
		c.publishMetrics(deltas)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-channel:
			continue
		}
	}
}

func (c checker) computeDelta(desired map[string]dynamicconfig.DynamicConfig, actual cell.AllSettings) []string {
	var deltas []string

	for key, value := range desired {
		if c.ignoredFlags.Has(key) {
			continue
		}

		if actualValue, ok := actual[key]; ok {
			actualValueString := cast.ToString(actualValue)
			if value.Value != actualValueString {
				deltas = append(deltas, fmt.Sprintf("Mismatch for key [%s]: expecting %q but got %q", key, value.Value, actualValueString))
				c.l.Warn("Mismatch found", "key", key, "actual", actualValueString, "expectedValue", value.Value, "expectedSource", value.Key.String())
			}
		} else {
			deltas = append(deltas, fmt.Sprintf("No entry found for key: [%s]", key))
			c.l.Warn("No local entry found", "key", key, "expectedValue", value.Value, "expectedSource", value.Key.String())
		}
	}
	slices.Sort(deltas)
	return deltas
}

func (c checker) publishMetrics(deltas []string) {
	c.m.DriftCheckerConfigDelta.Set(float64(len(deltas)))
}
