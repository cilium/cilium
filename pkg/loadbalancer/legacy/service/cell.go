// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/datapath/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides access to the Service Manager.
var Cell = cell.Module(
	"service-manager",
	"Service Manager",

	cell.ProvidePrivate(newServiceInternal),
	cell.Provide(func(svc *Service) ServiceManager { return svc }),
	cell.Provide(func(svc *Service) ServiceHealthCheckManager { return svc }),
	cell.Provide(newServiceRestApiHandler),

	cell.ProvidePrivate(func(sm ServiceManager) syncNodePort { return sm }),
	cell.Invoke(registerServiceReconciler),
	cell.Provide(func(l *slog.Logger) (sockets.SocketDestroyer, error) {
		bpfSD := &sockets.BPFSocketDestroyer{
			Logger: l,
		}

		if supported, err := bpfSD.IsSupported(); err != nil {
			return nil, fmt.Errorf("probing BPF socket destroyer support: %w", err)
		} else if supported {
			l.Info("Using BPF socket destroyer")
			return bpfSD, nil
		}

		l.Info("bpf_sock_destroy is not supported on the current kernel. Falling back to netlink-based socket destroyer")
		return &sockets.NetlinkSocketDestroyer{
			Logger: l,
		}, nil
	}),
)

type serviceManagerParams struct {
	cell.In

	Logger *slog.Logger

	JG    job.Group
	LBMap types.LBMap

	HealthCheckers  []HealthChecker `group:"healthCheckers"`
	Clientset       k8sClient.Clientset
	NodeNeighbors   types.NodeNeighbors
	MetricsRegistry *metrics.Registry

	Config                   *option.DaemonConfig
	LBConfig                 loadbalancer.Config
	BackendConnectionHandler sockets.SocketDestroyer
}

func newServiceInternal(params serviceManagerParams) *Service {
	enabledHealthCheckers := []HealthChecker{}
	for _, hc := range params.HealthCheckers {
		if hc != nil {
			enabledHealthCheckers = append(enabledHealthCheckers, hc)
		}
	}

	svc := newService(
		params.Logger,
		params.MetricsRegistry,
		params.LBConfig,
		params.LBMap,
		params.NodeNeighbors,
		enabledHealthCheckers,
		params.Clientset.IsEnabled(),
		params.Config,
		params.BackendConnectionHandler,
	)

	params.JG.Add(job.OneShot("health-check-event-watcher", svc.handleHealthCheckEvent))

	return svc
}
