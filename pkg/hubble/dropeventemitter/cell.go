// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/endpointmanager"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// FlowProcessor is a wrapper for dropEventEmitter used by Hubble
// to hook into the flow processing pipeline.
type FlowProcessor interface {
	ProcessFlow(ctx context.Context, flow *flowpb.Flow) error
}

var Cell = cell.Module(
	"hubble-dropeventemitter",
	"Emits k8s events on packet drop",

	cell.Provide(newDropEventEmitter),
	cell.Config(defaultConfig),
)

type config struct {
	// EnableK8sDropEvents controls whether Hubble should create v1.Events for
	// packet drops related to pods.
	EnableK8sDropEvents bool `mapstructure:"hubble-drop-events"`
	// K8sDropEventsInterval controls the minimum time between emitting events
	// with the same source and destination IP.
	K8sDropEventsInterval time.Duration `mapstructure:"hubble-drop-events-interval"`
	// K8sDropEventsReasons controls which drop reasons to emit events for.
	K8sDropEventsReasons []string `mapstructure:"hubble-drop-events-reasons"`
	// EnableK8sDropEventsExtended controls if L4 network policies are included in event message
	EnableK8sDropEventsExtended bool `mapstructure:"hubble-drop-events-extended"`
	// K8sDropEventsRateLimit controls the rate limit for the drop event emitter in events per second
	// If 0, no rate limit is applied
	K8sDropEventsRateLimit int64 `mapstructure:"hubble-drop-events-rate-limit"`
}

var defaultConfig = config{
	EnableK8sDropEvents:   false,
	K8sDropEventsInterval: 2 * time.Minute,
	K8sDropEventsReasons: []string{
		strings.ToLower(flowpb.DropReason_AUTH_REQUIRED.String()),
		strings.ToLower(flowpb.DropReason_POLICY_DENIED.String()),
	},
	EnableK8sDropEventsExtended: false,
	K8sDropEventsRateLimit:      1,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Bool("hubble-drop-events", def.EnableK8sDropEvents, "Emit packet drop Events related to pods (alpha)")
	flags.Duration("hubble-drop-events-interval", def.K8sDropEventsInterval, "Minimum time between emitting same events")
	flags.StringSlice("hubble-drop-events-reasons", def.K8sDropEventsReasons, "Drop reasons to emit events for")
	flags.Bool("hubble-drop-events-extended", def.EnableK8sDropEventsExtended, "Include L4 network policies in drop event message")
	flags.Int64("hubble-drop-events-rate-limit", def.K8sDropEventsRateLimit, "Rate limit for the drop event emitter in events per second (0 for no rate limit)")
}

func (cfg *config) normalize() {
	// Before moving the --hubble-drop-events-reasons flag to Config, it was
	// registered as flags.String() and parsed through viper.GetStringSlice()
	// in Cilium's DaemonConfig. In that case, viper is handling the split of
	// the single string value into slice and it uses white spaces as
	// separators. See also https://github.com/cilium/cilium/pull/33699 for
	// more context.
	//
	// Since it moved to Config, the --hubble-drop-events-reasons flag is
	// registered as flags.StringSlice() allowing multiple flag invocations,
	// and splitting values using comma as separator (see
	// https://pkg.go.dev/github.com/spf13/pflag#StringSlice). Since the
	// reasons themselves have no commas nor white spaces, starting to split on
	// commas should not introduce issues but we still need to handle white
	// spaces splitting to maintain backward compatibility.
	if len(cfg.K8sDropEventsReasons) == 1 {
		cfg.K8sDropEventsReasons = strings.Fields(cfg.K8sDropEventsReasons[0])
	}
}

type params struct {
	cell.In

	Logger *slog.Logger

	Lifecycle cell.Lifecycle

	Clientset  k8sClient.Clientset
	K8sWatcher *watchers.K8sWatcher

	Config config

	EndpointsLookup endpointmanager.EndpointsLookup
}

func newDropEventEmitter(p params) FlowProcessor {
	if !p.Config.EnableK8sDropEvents {
		p.Logger.Info("The Hubble packet drop events emitter is disabled")
		return nil
	}

	p.Config.normalize()

	p.Logger.Info(
		"Building the Hubble packet drop events emitter",
		logfields.Interval, p.Config.K8sDropEventsInterval,
		logfields.Reasons, p.Config.K8sDropEventsReasons,
		logfields.ExtendedMessage, p.Config.EnableK8sDropEventsExtended,
		logfields.RateLimit, p.Config.K8sDropEventsRateLimit,
	)

	flowProcessor := new(p.Logger, p.Config.K8sDropEventsInterval, p.Config.K8sDropEventsReasons, p.Config.EnableK8sDropEventsExtended, p.Config.K8sDropEventsRateLimit, p.Clientset, p.K8sWatcher, p.EndpointsLookup)
	p.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			flowProcessor.Shutdown()
			return nil
		},
	})
	return flowProcessor
}
