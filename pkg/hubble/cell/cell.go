// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/service"
)

// The top-level Hubble cell, implements several Hubble subsystems: reports pod
// network drops to k8s, Hubble flows based prometheus metrics, flows logging
// and export, and a couple of local and tcp gRPC servers.
var Cell = cell.Module(
	"hubble",
	"Exposes the Observer gRPC API and Hubble metrics",

	cell.Provide(newHubbleIntegration),
	cell.Config(defaultConfig),

	// Provide Hubble flow log exporters
	cell.ProvidePrivate(exportercell.NewValidatedConfig),
	cell.ProvidePrivate(exportercell.NewHubbleStaticExporter),
	cell.ProvidePrivate(exportercell.NewHubbleDynamicExporter),
	cell.Config(exportercell.DefaultConfig),
)

type hubbleParams struct {
	cell.In

	JobGroup job.Group

	IdentityAllocator identitycell.CachingIdentityAllocator
	EndpointManager   endpointmanager.EndpointManager
	IPCache           *ipcache.IPCache
	ServiceManager    service.ServiceManager
	CGroupManager     manager.CGroupManager
	Clientset         k8sClient.Clientset
	K8sWatcher        *watchers.K8sWatcher
	NodeManager       nodeManager.NodeManager
	NodeLocalStore    *node.LocalNodeStore
	MonitorAgent      monitorAgent.Agent
	Recorder          *recorder.Recorder

	// NOTE: ordering is not guaranteed, do not rely on it.
	ObserverOptions []observeroption.Option    `group:"hubble-observer-options"`
	Exporters       []exporter.FlowLogExporter `group:"hubble-flow-log-exporters"`

	// NOTE: we still need DaemonConfig for the shared EnableRecorder flag.
	AgentConfig *option.DaemonConfig
	Config      config

	// TODO: replace by slog
	Logger logrus.FieldLogger
}

type HubbleIntegration interface {
	Launch(ctx context.Context) error
	Status(ctx context.Context) *models.HubbleStatus
}

func newHubbleIntegration(params hubbleParams) (HubbleIntegration, error) {
	h, err := new(
		params.IdentityAllocator,
		params.EndpointManager,
		params.IPCache,
		params.ServiceManager,
		params.CGroupManager,
		params.Clientset,
		params.K8sWatcher,
		params.NodeManager,
		params.NodeLocalStore,
		params.MonitorAgent,
		params.Recorder,
		params.ObserverOptions,
		params.Exporters,
		params.AgentConfig,
		params.Config,
		params.Logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create hubble integration: %w", err)
	}

	params.JobGroup.Add(job.OneShot("hubble", func(ctx context.Context, _ cell.Health) error {
		return h.Launch(ctx)
	}))

	return h, nil
}
