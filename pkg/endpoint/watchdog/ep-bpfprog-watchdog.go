// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchdog

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/loader"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
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

	Config   epBPFProgWatchdogConfig
	Logger   *slog.Logger
	JobGroup job.Group

	RestorerPromise promise.Promise[endpointstate.Restorer]

	EndpointManager endpointmanager.EndpointManager
	Orchestrator    datapath.Orchestrator
}

// Cell triggers a job to ensure device tc programs remain loaded.
var Cell = cell.Module(
	epBPFProgWatchdog,
	"Periodically checks that endpoint BPF programs remain loaded",

	cell.Config(epBPFProgWatchdogConfig{
		EndpointBPFProgWatchdogInterval: 30 * time.Second,
	}),
	cell.Invoke(registerEndpointBPFProgWatchdog),
)

func registerEndpointBPFProgWatchdog(p epBPFProgWatchdogParams) {
	if p.Config.EndpointBPFProgWatchdogInterval == 0 {
		return
	}

	watchdog := &endpointBPFProgWatchdog{
		logger:          p.Logger,
		endpointManager: p.EndpointManager,
		orchestrator:    p.Orchestrator,
	}

	p.JobGroup.Add(job.Timer(epBPFProgWatchdog, func(ctx context.Context) error {
		_, err := p.RestorerPromise.Await(ctx)
		if err != nil {
			return err
		}

		return watchdog.checkEndpointBPFPrograms(ctx, p)
	}, p.Config.EndpointBPFProgWatchdogInterval))
}

type endpointBPFProgWatchdog struct {
	logger *slog.Logger

	endpointManager endpointmanager.EndpointManager
	orchestrator    datapath.Orchestrator
}

func (r *endpointBPFProgWatchdog) checkEndpointBPFPrograms(ctx context.Context, p epBPFProgWatchdogParams) error {
	eps := r.endpointManager.GetEndpoints()
	for _, ep := range eps {
		if ep.GetState() != endpoint.StateReady {
			continue
		}

		if ep.IsProperty(endpoint.PropertyWithouteBPFDatapath) {
			// Skip Endpoints without BPF datapath
			continue
		}

		loaded, err := loader.DeviceHasSKBProgramLoaded(ep.HostInterface(), ep.RequireEgressProg())
		if err != nil {
			r.logger.Warn("Unable to assert if endpoint BPF programs need to be reloaded",
				logfields.Endpoint, ep.HostInterface(),
				logfields.EndpointID, ep.ID,
				logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
				logfields.Error, err,
			)

			return fmt.Errorf("failed to assert if endpoint BPF programs need to be reloaded: %w", err)
		}

		// We've detected missing bpf progs for this endpoint.
		// Trigger bpf progs reload.
		if !loaded {
			return r.reloadBPFPrograms(ctx, len(eps))
		}
	}

	return nil
}

func (r *endpointBPFProgWatchdog) reloadBPFPrograms(ctx context.Context, endpointCount int) error {
	r.logger.Warn(
		"Detected unexpected endpoint BPF program removal. "+
			"Consider investigating whether other software running on this machine is removing Cilium's endpoint BPF programs. "+
			"If endpoint BPF programs are removed, the associated pods will lose connectivity and only reinstating the programs will restore connectivity.",
		logfields.Count, endpointCount,
	)

	if err := r.orchestrator.Reinitialize(ctx); err != nil {
		r.logger.Error("Failed to reload Cilium endpoints BPF programs", logfields.Error, err)
		return fmt.Errorf("failed to reload Cilium endpoints BPF programs: %w", err)
	}

	return nil
}
