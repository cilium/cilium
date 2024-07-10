// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"log/slog"
	"reflect"
	"runtime/pprof"
	"time"

	upstream "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type (
	Hive       = upstream.Hive
	Options    = upstream.Options
	Shutdowner = upstream.Shutdowner
)

var (
	ShutdownWithError = upstream.ShutdownWithError
)

// New wraps the hive.New to create a hive with defaults used by cilium-agent.
// pkg/hive should eventually go away and this code should live in e.g. daemon/cmd
// or operator/cmd.
func New(cells ...cell.Cell) *Hive {
	cells = append(
		slices.Clone(cells),

		health.Cell,
		job.Cell,
		statedb.Cell,

		cell.Provide(
			NewStateDBMetrics,
			NewStateDBReconcilerMetrics,
			func() logrus.FieldLogger { return logging.DefaultLogger },
			func(provider types.Provider) cell.Health {
				return provider.ForModule(nil)
			},
		))
	// Scope logging and health by module ID.
	moduleDecorators := []cell.ModuleDecorator{
		func(log logrus.FieldLogger, mid cell.ModuleID) logrus.FieldLogger {
			return log.WithField(logfields.LogSubsys, string(mid))
		},
		func(hp types.Provider, fmid cell.FullModuleID) cell.Health {
			return hp.ForModule(fmid)
		},
	}
	modulePrivateProviders := []cell.ModulePrivateProvider{
		jobGroupProvider,
		func(db *statedb.DB, mid cell.ModuleID) statedb.Handle {
			return db.NewHandle(string(mid))
		},
	}
	return upstream.NewWithOptions(
		upstream.Options{
			EnvPrefix:              "CILIUM_",
			ModulePrivateProviders: modulePrivateProviders,
			ModuleDecorators:       moduleDecorators,
			DecodeHooks:            decodeHooks,
			StartTimeout:           5 * time.Minute,
			StopTimeout:            1 * time.Minute,
			LogThreshold:           100 * time.Millisecond,
		},
		cells...,
	)
}

var decodeHooks = cell.DecodeHooks{
	// Decode *cidr.CIDR fields
	func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		s := data.(string)
		if to != reflect.TypeOf((*cidr.CIDR)(nil)) {
			return data, nil
		}
		return cidr.ParseCIDR(s)
	},
}

func AddConfigOverride[Cfg cell.Flagger](h *Hive, override func(*Cfg)) {
	upstream.AddConfigOverride[Cfg](h, override)
}

// jobGroupProvider provides a (private) job group to modules, with scoped health reporting, logging and metrics.
func jobGroupProvider(reg job.Registry, h cell.Health, l *slog.Logger, lc cell.Lifecycle, mid cell.ModuleID) job.Group {
	g := reg.NewGroup(h,
		job.WithLogger(l),
		job.WithPprofLabels(pprof.Labels("cell", string(mid))))
	lc.Append(g)
	return g
}
