// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/dropeventemitter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	metricscell "github.com/cilium/cilium/pkg/hubble/metrics/cell"
	"github.com/cilium/cilium/pkg/hubble/observer/namespace"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parsercell "github.com/cilium/cilium/pkg/hubble/parser/cell"
	"github.com/cilium/cilium/pkg/hubble/peer"
	peercell "github.com/cilium/cilium/pkg/hubble/peer/cell"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
)

// The top-level Hubble cell, implements several Hubble subsystems: reports pod
// network drops to k8s, Hubble flows based prometheus metrics, flows logging
// and export, and a couple of local and tcp gRPC servers.
var Cell = cell.Module(
	"hubble",
	"Exposes the Observer gRPC API and Hubble metrics",

	Core,

	// Configuration providers group creates config objects for other components
	ConfigProviders,

	// Hubble TLS certificates
	certloaderGroup,

	// Hubble flow log exporters
	exportercell.Cell,

	// Metrics server and flow processor
	metricscell.Cell,

	// Drop event emitter flow processor
	dropeventemitter.Cell,

	// Parser for Hubble flows
	parsercell.Cell,

	// Hubble flows k8s namespaces monitor
	namespace.Cell,

	// Peer service for handling peer discovery and notifications
	peercell.Cell,
)

// The core cell group, which contains the Hubble integration and the
// Hubble integration configuration isolated from the dependency graph
// will enable us to run hubble with a different dataplane
var Core = cell.Group(
	cell.Provide(newHubbleIntegration),
	cell.Config(defaultConfig),
)

type hubbleParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup job.Group

	IdentityAllocator identitycell.CachingIdentityAllocator
	EndpointManager   endpointmanager.EndpointManager
	IPCache           *ipcache.IPCache
	CGroupManager     manager.CGroupManager
	NodeManager       nodeManager.NodeManager
	NodeLocalStore    *node.LocalNodeStore
	MonitorAgent      monitorAgent.Agent

	TLSConfigPromise tlsConfigPromise

	// NOTE: ordering is not guaranteed, do not rely on it.
	ObserverOptions  []observeroption.Option                `group:"hubble-observer-options"`
	ExporterBuilders []*exportercell.FlowLogExporterBuilder `group:"hubble-exporter-builders"`

	DropEventEmitter dropeventemitter.FlowProcessor

	PayloadParser    parser.Decoder
	NamespaceManager namespace.Manager

	GRPCMetrics          *grpc_prometheus.ServerMetrics
	MetricsFlowProcessor metrics.FlowProcessor

	PeerService *peer.Service

	Config config
}

type HubbleIntegration interface {
	Launch(ctx context.Context) error
	Status(ctx context.Context) *models.HubbleStatus
}

func newHubbleIntegration(params hubbleParams) (HubbleIntegration, error) {
	h, err := createHubbleIntegration(
		params.IdentityAllocator,
		params.EndpointManager,
		params.IPCache,
		params.CGroupManager,
		params.NodeManager,
		params.NodeLocalStore,
		params.MonitorAgent,
		params.TLSConfigPromise,
		params.ObserverOptions,
		params.ExporterBuilders,
		params.DropEventEmitter,
		params.PayloadParser,
		params.NamespaceManager,
		params.GRPCMetrics,
		params.MetricsFlowProcessor,
		params.PeerService,
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
