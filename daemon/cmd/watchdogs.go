// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

const epBPFProgWatchdog = "ep-bpf-prog-watchdog"

type epBPFProgWatchdogConfig struct {
	EndpointBPFProgWatchdogInterval time.Duration
}

func (c epBPFProgWatchdogConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("endpoint-bpf-prog-watchdog-interval", c.EndpointBPFProgWatchdogInterval,
		"Interval to trigger endpoint BPF programs load check watchdog")
}

type epBPFProgWatchdogParams struct {
	cell.In

	Config        epBPFProgWatchdogConfig
	Logger        logrus.FieldLogger
	Lifecycle     hive.Lifecycle
	DaemonPromise promise.Promise[*Daemon]
	Scope         cell.Scope
}

var (
	// endpointBPFrogWatchdogCell triggers a job to ensure device tc programs remain loaded.
	endpointBPFrogWatchdogCell = cell.Module(
		epBPFProgWatchdog,
		"Periodically checks that endpoint BPF programs remain loaded",

		cell.Config(epBPFProgWatchdogConfigDefault),
		cell.Invoke(registerEndpointBPFProgWatchdog),
	)

	epBPFProgWatchdogConfigDefault = epBPFProgWatchdogConfig{
		EndpointBPFProgWatchdogInterval: 30 * time.Second,
	}
)

func registerEndpointBPFProgWatchdog(p epBPFProgWatchdogParams) {
	if p.Config.EndpointBPFProgWatchdogInterval == 0 {
		return
	}

	var (
		ctx, cancel = context.WithCancel(context.Background())
		mgr         = controller.NewManager()
	)
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			mgr.UpdateController(
				epBPFProgWatchdog,
				controller.ControllerParams{
					Group:          controller.NewGroup(epBPFProgWatchdog),
					HealthReporter: cell.GetHealthReporter(p.Scope, epBPFProgWatchdog),
					DoFunc: func(ctx context.Context) error {
						d, err := p.DaemonPromise.Await(ctx)
						if err != nil {
							return err
						}
						return d.checkEndpointBPFPrograms(ctx, p)
					},
					RunInterval: p.Config.EndpointBPFProgWatchdogInterval,
					Context:     ctx,
				},
			)

			return nil
		},
		OnStop: func(hive.HookContext) error {
			cancel()
			mgr.RemoveAllAndWait()
			return nil
		},
	},
	)
}

func (d *Daemon) checkEndpointBPFPrograms(ctx context.Context, p epBPFProgWatchdogParams) error {
	var (
		loaded = true
		err    error
		eps    = d.endpointManager.GetEndpoints()
	)
	for _, ep := range eps {
		if ep.GetState() != endpoint.StateReady {
			continue
		}
		if !ep.HasBPFPolicyMap() {
			// Skip Endpoints without BPF datapath
			continue
		}
		loaded, err = loader.DeviceHasTCProgramLoaded(ep.HostInterface(), ep.RequireEgressProg())
		if err != nil {
			log.WithField(logfields.Endpoint, ep.HostInterface()).
				WithField(logfields.EndpointID, ep.ID).
				WithError(err).
				Error("Unable to assert if endpoint BPF programs need to be reloaded")
			return err
		}
		// We've detected missing bpf progs for this endpoint.
		// Break and trigger bpf progs reload.
		if !loaded {
			break
		}
	}
	if loaded {
		return nil
	}

	log.WithField(logfields.Count, len(eps)).
		Warn(
			"Detected unexpected endpoint BPF program removal. " +
				"Consider investigating whether other software running on this machine is removing Cilium's endpoint BPF programs. " +
				"If endpoint BPF programs are removed, the associated pods will lose connectivity and only reinstating the programs will restore connectivity.",
		)
	wg, err := d.TriggerReloadWithoutCompile(epBPFProgWatchdog)
	if err != nil {
		log.WithError(err).Error("Failed to reload Cilium endpoints BPF programs")
	} else {
		wg.Wait()
	}

	return err
}
