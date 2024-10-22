// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
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
	Lifecycle     cell.Lifecycle
	DaemonPromise promise.Promise[*Daemon]
	Health        cell.Health
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
	// The watchdog works only for tc BPF, but not when the L4LB has
	// XDP acceleration enabled. While we could enable it for tc BPF
	// mode, lets keep same behavior on both settings.
	if option.Config.DatapathMode == datapathOption.DatapathModeLBOnly {
		return
	}
	var (
		ctx, cancel = context.WithCancel(context.Background())
		mgr         = controller.NewManager()
	)
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			mgr.UpdateController(
				epBPFProgWatchdog,
				controller.ControllerParams{
					Group:  controller.NewGroup(epBPFProgWatchdog),
					Health: p.Health.NewScope(epBPFProgWatchdog),
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
		OnStop: func(cell.HookContext) error {
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
		if ep.IsProperty(endpoint.PropertyWithouteBPFDatapath) {
			// Skip Endpoints without BPF datapath
			continue
		}
		loaded, err = loader.DeviceHasSKBProgramLoaded(ep.HostInterface(), ep.RequireEgressProg())
		if err != nil {
			log.WithField(logfields.Endpoint, ep.HostInterface()).
				WithField(logfields.EndpointID, ep.ID).
				WithField(logfields.CEPName, ep.GetK8sNamespaceAndCEPName()).
				WithError(err).
				Warn("Unable to assert if endpoint BPF programs need to be reloaded")
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
	err = d.orchestrator.Reinitialize(d.ctx)
	if err != nil {
		log.WithError(err).Error("Failed to reload Cilium endpoints BPF programs")
	}

	return err
}
