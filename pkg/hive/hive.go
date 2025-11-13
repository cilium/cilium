// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"log/slog"
	"net/netip"
	"reflect"
	"runtime/pprof"
	"slices"

	upstream "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	watcherMetrics "github.com/cilium/cilium/pkg/k8s/watchers/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

type (
	Hive       = upstream.Hive
	Options    = upstream.Options
	Shutdowner = upstream.Shutdowner
)

var ShutdownWithError = upstream.ShutdownWithError

// New wraps the hive.New to create a hive with defaults used by cilium-agent.
func New(cells ...cell.Cell) *Hive {
	cells = append(
		slices.Clone(cells),

		cell.Group(
			job.Cell,
			metrics.Metric(newHiveJobsCiliumMetrics),
		),

		// Module health
		cell.Group(
			health.Cell,
			cell.Provide(
				func(provider types.Provider) cell.Health {
					return provider.ForModule(nil)
				},
			),
		),

		// StateDB and its metrics
		cell.Group(
			statedb.Cell,

			metrics.Metric(NewStateDBMetrics),
			metrics.Metric(NewStateDBReconcilerMetrics),
			cell.Provide(
				NewStateDBMetricsImpl,
				NewStateDBReconcilerMetricsImpl,
			),
		),

		// The root slog FieldLogger.
		cell.Provide(
			func() logging.FieldLogger {
				// slogloggercheck: its setup has been done before hive is Ran.
				return logging.DefaultSlogLogger
			},

			// Root job group. This is mostly provided for tests so that we don't need a cell.Module
			// wrapper to get a job.Group.
			func(reg job.Registry, h cell.Health, l *slog.Logger, lc cell.Lifecycle) job.Group {
				return reg.NewGroup(h, lc, job.WithLogger(l))
			},
		),

		// Provides workqueue metrics provider, used by all k8s resource constructors. This will
		// also be needed by a very large number of tests so we choose to include it by default.
		watcherMetrics.Cell,
	)

	// Scope logging and health by module ID.
	moduleDecorators := []cell.ModuleDecorator{
		func(mid cell.ModuleID) logging.FieldLogger {
			// slogloggercheck: its setup has been done before hive is Ran.
			return logging.DefaultSlogLogger.With(logfields.LogSubsys, string(mid))
		},
		func(hp types.Provider, fmid cell.FullModuleID) cell.Health {
			return hp.ForModule(fmid)
		},
		func(db *statedb.DB, mid cell.ModuleID) *statedb.DB {
			return db.NewHandle(string(mid))
		},
	}
	modulePrivateProviders := []cell.ModulePrivateProvider{
		jobGroupProvider,
	}
	return upstream.NewWithOptions(
		upstream.Options{
			EnvPrefix:              "CILIUM_",
			ModulePrivateProviders: modulePrivateProviders,
			ModuleDecorators:       moduleDecorators,
			DecodeHooks:            decodeHooks,
			StartTimeout:           defaults.HiveStartTimeout,
			StopTimeout:            defaults.HiveStopTimeout,
			LogThreshold:           defaults.HiveLogThreshold,
		},
		cells...,
	)
}

func RegisterFlags(vp *viper.Viper, flags *pflag.FlagSet) {
	flags.Duration(option.HiveStartTimeout, defaults.HiveStartTimeout, "Maximum time to wait for startup hooks to complete before timing out")
	option.BindEnv(vp, option.HiveStartTimeout)

	flags.Duration(option.HiveStopTimeout, defaults.HiveStopTimeout, "Maximum time to wait for stop hooks to complete before timing out")
	option.BindEnv(vp, option.HiveStopTimeout)

	flags.Duration(option.HiveLogThreshold, defaults.HiveLogThreshold, "Time limit after which a slow hook is logged at Info level")
	option.BindEnv(vp, option.HiveLogThreshold)
}

func GetOptions(cfg option.HiveConfig) []upstream.RunOptionFunc {
	return []upstream.RunOptionFunc{
		upstream.WithStartTimeout(cfg.StartTimeout),
		upstream.WithStopTimeout(cfg.StopTimeout),
		upstream.WithLogThreshold(cfg.LogThreshold),
	}
}

var decodeHooks = cell.DecodeHooks{
	// Decode netip.Prefix fields
	// TODO: move to github.com/cilium/hive/cell.decoderConfig default decode hooks once
	// https://github.com/go-viper/mapstructure/pull/85 is merged.
	func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		if to != reflect.TypeFor[netip.Prefix]() {
			return data, nil
		}
		return netip.ParsePrefix(data.(string))
	},
}

func AddConfigOverride[Cfg cell.Flagger](h *Hive, override func(*Cfg)) {
	upstream.AddConfigOverride[Cfg](h, override)
}

// jobGroupProvider provides a (private) job group to modules, with scoped health reporting, logging and metrics.
func jobGroupProvider(reg job.Registry, h cell.Health, l *slog.Logger, lc cell.Lifecycle, jobsMetrics *hiveJobsCiliumMetrics, mid cell.ModuleID) job.Group {
	return reg.NewGroup(h, lc,
		job.WithLogger(l),
		job.WithPprofLabels(pprof.Labels("cell", string(mid))),
		job.WithMetrics(jobMetricsFor(jobsMetrics, mid)),
	)
}
