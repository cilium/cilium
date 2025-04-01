// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/go-openapi/strfmt"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/endpointmanager"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/dropeventemitter"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	exportercell "github.com/cilium/cilium/pkg/hubble/exporter/cell"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/hubble/monitor"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	hubbleRecorder "github.com/cilium/cilium/pkg/hubble/recorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/recorderoption"
	"github.com/cilium/cilium/pkg/hubble/recorder/sink"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/time"
)

// hubbleIntegration is responsible for configuration, initialization, and
// shutdown of every Hubble components including the Hubble observer servers
// (TCP, UNIX domain socket), the Hubble metrics server, etc.
type hubbleIntegration struct {
	log *slog.Logger

	// Observer will be set once the Hubble Observer has been started.
	observer        atomic.Pointer[observer.LocalObserverServer]
	observerOptions []observeroption.Option

	// launchError is set when an error occurs as part of launch.
	// It is used to report the cell status to the daemon when probed using Status().
	launchError atomic.Pointer[string]

	identityAllocator identitycell.CachingIdentityAllocator
	endpointManager   endpointmanager.EndpointManager
	ipcache           *ipcache.IPCache
	serviceManager    service.ServiceManager
	cgroupManager     manager.CGroupManager
	clientset         k8sClient.Clientset
	k8sWatcher        *watchers.K8sWatcher
	nodeManager       nodeManager.NodeManager
	nodeLocalStore    *node.LocalNodeStore
	monitorAgent      monitorAgent.Agent
	recorder          *recorder.Recorder
	exporters         []exporter.FlowLogExporter

	// payloadParser is used to decode monitor events into Hubble events.
	payloadParser parser.Decoder

	// NOTE: we still need DaemonConfig for the shared EnableRecorder flag.
	agentConfig *option.DaemonConfig
	config      config
}

// new creates and return a new hubbleIntegration.
func new(
	identityAllocator identitycell.CachingIdentityAllocator,
	endpointManager endpointmanager.EndpointManager,
	ipcache *ipcache.IPCache,
	serviceManager service.ServiceManager,
	cgroupManager manager.CGroupManager,
	clientset k8sClient.Clientset,
	k8sWatcher *watchers.K8sWatcher,
	nodeManager nodeManager.NodeManager,
	nodeLocalStore *node.LocalNodeStore,
	monitorAgent monitorAgent.Agent,
	recorder *recorder.Recorder,
	observerOptions []observeroption.Option,
	exporterBuilders []*exportercell.FlowLogExporterBuilder,
	payloadParser parser.Decoder,
	agentConfig *option.DaemonConfig,
	config config,
	log *slog.Logger,
) (*hubbleIntegration, error) {
	config.normalize()

	// NOTE: exporter builders MUST always be resolved early and outside of a
	// Hive job.Group or cell.Lifecycle hook. This is because their Build()
	// function may have captured pointers to these and append new jobs/hooks,
	// which we don't want to see happening after the hive startup.
	exporters, err := exportercell.ResolveExporters(exporterBuilders)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Hubble exporters: %w", err)
	}

	hi := &hubbleIntegration{
		identityAllocator: identityAllocator,
		endpointManager:   endpointManager,
		ipcache:           ipcache,
		serviceManager:    serviceManager,
		cgroupManager:     cgroupManager,
		clientset:         clientset,
		k8sWatcher:        k8sWatcher,
		nodeManager:       nodeManager,
		nodeLocalStore:    nodeLocalStore,
		monitorAgent:      monitorAgent,
		recorder:          recorder,
		observerOptions:   observerOptions,
		exporters:         exporters,
		payloadParser:     payloadParser,
		agentConfig:       agentConfig,
		config:            config,
		log:               log,
	}

	return hi, nil
}

// Launch initializes and starts all sub-systems of Hubble.
func (h *hubbleIntegration) Launch(ctx context.Context) error {
	if !h.config.EnableHubble {
		h.log.Info("Hubble server is disabled")
		return nil
	}

	observer, err := h.launch(ctx)
	if err != nil {
		h.log.Error("Failed to launch hubble", logfields.Error, err)
		errStr := err.Error()
		h.launchError.Store(&errStr)
		return err
	}

	h.observer.Store(observer)
	return nil
}

// Status report the Hubble status for the Cilium Daemon status collector
// probe.
func (h *hubbleIntegration) Status(ctx context.Context) *models.HubbleStatus {
	if !h.config.EnableHubble {
		return &models.HubbleStatus{State: models.HubbleStatusStateDisabled}
	}

	// verify if an error occurred during launch() and report it
	launchError := h.launchError.Load()
	if launchError != nil {
		return &models.HubbleStatus{
			State: models.HubbleStatusStateWarning,
			Msg:   *launchError,
		}
	}

	// otherwise try to get a pointer to observer
	// If not set, we are still running launch(), report hubble as still starting
	obs := h.observer.Load()
	if obs == nil {
		return &models.HubbleStatus{
			State: models.HubbleStatusStateWarning,
			Msg:   "Hubble starting",
		}
	}

	req := &observerpb.ServerStatusRequest{}
	status, err := obs.ServerStatus(ctx, req)
	if err != nil {
		return &models.HubbleStatus{State: models.HubbleStatusStateFailure, Msg: err.Error()}
	}

	metricsState := models.HubbleStatusMetricsStateDisabled
	if h.config.MetricsServer != "" {
		// TODO: The metrics package should be refactored to be able report its actual state
		metricsState = models.HubbleStatusMetricsStateOk
	}

	hubbleStatus := &models.HubbleStatus{
		State: models.StatusStateOk,
		Observer: &models.HubbleStatusObserver{
			CurrentFlows: int64(status.NumFlows),
			MaxFlows:     int64(status.MaxFlows),
			SeenFlows:    int64(status.SeenFlows),
			Uptime:       strfmt.Duration(time.Duration(status.UptimeNs)),
		},
		Metrics: &models.HubbleStatusMetrics{
			State: metricsState,
		},
	}

	return hubbleStatus
}

func (h *hubbleIntegration) launch(ctx context.Context) (*observer.LocalObserverServer, error) {
	var (
		observerOpts []observeroption.Option
		localSrvOpts []serveroption.Option
	)

	if len(h.config.MonitorEvents) > 0 {
		monitorFilter, err := monitor.NewMonitorFilter(h.log, h.config.MonitorEvents)
		if err != nil {
			// TODO: bubble up the error and/or set cell health as degraded
			h.log.Warn("Failed to initialize Hubble monitor event filter", logfields.Error, err)
		} else {
			observerOpts = append(observerOpts, observeroption.WithOnMonitorEvent(monitorFilter))
		}
	}

	if h.config.EnableK8sDropEvents {
		h.log.Info(
			"Starting packet drop events emitter",
			logfields.Interval, h.config.K8sDropEventsInterval,
			logfields.Reasons, h.config.K8sDropEventsReasons,
		)

		dropEventEmitter := dropeventemitter.NewDropEventEmitter(
			h.config.K8sDropEventsInterval,
			h.config.K8sDropEventsReasons,
			h.clientset,
			h.k8sWatcher,
		)

		observerOpts = append(observerOpts,
			observeroption.WithOnDecodedFlowFunc(func(ctx context.Context, flow *flowpb.Flow) (bool, error) {
				err := dropEventEmitter.ProcessFlow(ctx, flow)
				if err != nil {
					h.log.Error("Failed to ProcessFlow in drop events handler", logfields.Error, err)
				}
				return false, nil
			}),
		)
	}

	// fill in the local node information after the dropEventEmitter logique,
	// but before anything else (e.g. metrics).
	localNodeWatcher, err := observer.NewLocalNodeWatcher(ctx, h.nodeLocalStore)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve local node information: %w", err)
	}
	observerOpts = append(observerOpts, observeroption.WithOnDecodedFlow(localNodeWatcher))

	grpcMetrics := grpc_prometheus.NewServerMetrics()
	var metricsTLSConfig *certloader.WatchedServerConfig
	if h.config.EnableMetricsServerTLS {
		metricsTLSConfigChan, err := certloader.FutureWatchedServerConfig(
			h.log.With(logfields.Config, "hubble-metrics-server-tls"),
			h.config.MetricsServerTLSClientCAFiles,
			h.config.MetricsServerTLSCertFile,
			h.config.MetricsServerTLSKeyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Hubble metrics server TLS configuration: %w", err)
		}
		waitingMsgTimeout := time.After(30 * time.Second)
		for metricsTLSConfig == nil {
			select {
			case metricsTLSConfig = <-metricsTLSConfigChan:
			case <-waitingMsgTimeout:
				h.log.Info("Waiting for Hubble metrics server TLS certificate and key files to be created")
			case <-ctx.Done():
				return nil, fmt.Errorf("timeout while waiting for Hubble metrics server TLS certificate and key files to be created: %w", ctx.Err())
			}
		}
		go func() {
			<-ctx.Done()
			metricsTLSConfig.Stop()
		}()
	}

	var srv *http.Server
	if h.config.MetricsServer != "" {
		switch {
		case h.config.DynamicMetricConfigFilePath != "" && len(h.config.Metrics) > 0:
			return nil, errors.New("Cannot configure both static and dynamic Hubble metrics")
		case h.config.DynamicMetricConfigFilePath != "":
			h.log.Info(
				"Starting Hubble server with dynamically configurable metrics",
				logfields.Address, h.config.MetricsServer,
				logfields.MetricConfig, h.config.DynamicMetricConfigFilePath,
				logfields.TLS, h.config.EnableMetricsServerTLS,
			)

			metrics.InitHubbleInternalMetrics(metrics.Registry, grpcMetrics)
			dynamicFp := metrics.NewDynamicFlowProcessor(metrics.Registry, h.log, h.config.DynamicMetricConfigFilePath)
			observerOpts = append(observerOpts, observeroption.WithOnDecodedFlow(dynamicFp))
		case len(h.config.Metrics) > 0:
			h.log.Info(
				"Starting Hubble Metrics server",
				logfields.Address, h.config.MetricsServer,
				logfields.MetricConfig, h.config.DynamicMetricConfigFilePath,
				logfields.TLS, h.config.EnableMetricsServerTLS,
			)

			metricConfigs := api.ParseStaticMetricsConfig(strings.Fields(h.config.Metrics))
			err := metrics.InitMetrics(h.log, metrics.Registry, metricConfigs, grpcMetrics)
			if err != nil {
				return nil, fmt.Errorf("failed to setup metrics: %w", err)
			}

			observerOpts = append(observerOpts,
				observeroption.WithOnDecodedFlowFunc(func(ctx context.Context, flow *flowpb.Flow) (bool, error) {
					if metrics.EnabledMetrics != nil {
						var errs error
						for _, nh := range metrics.EnabledMetrics {
							// Continue running the remaining metrics handlers, since one failing
							// shouldn't impact the other metrics handlers.
							errs = errors.Join(errs, nh.Handler.ProcessFlow(ctx, flow))
						}
						if errs != nil {
							h.log.Error("Failed to ProcessFlow in metrics handler", logfields.Error, err)
						}
					}
					return false, nil
				}),
			)
		}

		srv = &http.Server{
			Addr:    h.config.MetricsServer,
			Handler: nil,
		}
		metrics.InitMetricsServerHandler(srv, metrics.Registry, h.config.EnableOpenMetrics)

		go func() {
			if err := metrics.StartMetricsServer(srv, h.log, metricsTLSConfig, grpcMetrics); err != nil && !errors.Is(err, http.ErrServerClosed) {
				h.log.Error("Hubble metrics server encountered an error", logfields.Error, err)
				return
			}
		}()

		localSrvOpts = append(localSrvOpts,
			serveroption.WithGRPCMetrics(grpcMetrics),
			serveroption.WithGRPCStreamInterceptor(grpcMetrics.StreamServerInterceptor()),
			serveroption.WithGRPCUnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
		)
	}

	maxFlows, err := container.NewCapacity(h.config.EventBufferCapacity)
	if err != nil {
		return nil, fmt.Errorf("failed to compute event buffer capacity: %w", err)
	}
	observerOpts = append(observerOpts,
		observeroption.WithMaxFlows(maxFlows),
		observeroption.WithMonitorBuffer(h.config.EventQueueSize),
	)

	// register exporters
	for _, exporter := range h.exporters {
		observerOpts = append(observerOpts, observeroption.WithOnDecodedEventFunc(func(ctx context.Context, e *v1.Event) (bool, error) {
			return false, exporter.Export(ctx, e)
		}))
	}

	// register injected observer options last to allow
	// for explicit ordering of known dependencies
	observerOpts = append(observerOpts, h.observerOptions...)

	namespaceManager := observer.NewNamespaceManager()
	go namespaceManager.Run(ctx)

	hubbleObserver, err := observer.NewLocalServer(
		h.payloadParser,
		namespaceManager,
		h.log,
		observerOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize observer server: %w", err)
	}
	go hubbleObserver.Start()
	h.monitorAgent.RegisterNewConsumer(monitor.NewConsumer(hubbleObserver))

	// configure a local hubble server listening on a local UNIX domain socket.
	// This server can be used by the Hubble CLI when invoked from within the
	// cilium Pod, typically in troubleshooting scenario.
	sockPath := "unix://" + h.config.SocketPath
	var peerServiceOptions []serviceoption.Option
	if h.config.DisableServerTLS {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithoutTLSInfo())
	}
	if h.config.PreferIpv6 {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithAddressFamilyPreference(serviceoption.AddressPreferIPv6))
	}
	if addr := h.config.ListenAddress; addr != "" {
		port, err := getPort(h.config.ListenAddress)
		if err != nil {
			// TODO: bubble up the error and/or set cell health as degraded
			h.log.Warn(
				"Hubble server will not pass port information in change notifications on exposed Hubble peer service",
				logfields.Error, err,
				logfields.Address, addr,
			)
		} else {
			peerServiceOptions = append(peerServiceOptions, serviceoption.WithHubblePort(port))
		}
	}
	peerSvc := peer.NewService(h.nodeManager, peerServiceOptions...)
	localSrvOpts = append(localSrvOpts,
		serveroption.WithUnixSocketListener(logging.DefaultSlogLogger, sockPath),
		serveroption.WithHealthService(),
		serveroption.WithObserverService(hubbleObserver),
		serveroption.WithPeerService(peerSvc),
		serveroption.WithInsecure(),
		serveroption.WithGRPCUnaryInterceptor(serverVersionUnaryInterceptor()),
		serveroption.WithGRPCStreamInterceptor(serverVersionStreamInterceptor()),
	)

	if h.agentConfig.EnableRecorder && h.config.EnableRecorderAPI {
		dispatch, err := sink.NewDispatch(h.log, h.config.RecorderSinkQueueSize)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize recorder sink dispatch: %w", err)
		}
		h.monitorAgent.RegisterNewConsumer(dispatch)
		svc, err := hubbleRecorder.NewService(h.log, h.recorder, dispatch,
			recorderoption.WithStoragePath(h.config.RecorderStoragePath))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize recorder service: %w", err)
		}
		localSrvOpts = append(localSrvOpts, serveroption.WithRecorderService(svc))
	}

	localSrv, err := server.NewServer(h.log, localSrvOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize local hubble server: %w", err)
	}
	h.log.Info("Starting local Hubble server", logfields.Address, sockPath)
	go func() {
		if err := localSrv.Serve(); err != nil {
			h.log.Error("Error while serving from local Hubble server",
				logfields.Error, err,
				logfields.Address, sockPath,
			)
		}
	}()
	go func() {
		<-ctx.Done()
		localSrv.Stop()
		peerSvc.Close()
		if srv != nil {
			srv.Close()
		}
	}()

	// configure another hubble server listening on TCP. This server is
	// typically queried by Hubble Relay.
	address := h.config.ListenAddress
	if address != "" {
		if h.config.DisableServerTLS {
			h.log.Warn("Hubble server will be exposing its API insecurely on this address",
				logfields.Address, sockPath,
			)
		}
		options := []serveroption.Option{
			serveroption.WithTCPListener(address),
			serveroption.WithHealthService(),
			serveroption.WithPeerService(peerSvc),
			serveroption.WithObserverService(hubbleObserver),
			serveroption.WithGRPCUnaryInterceptor(serverVersionUnaryInterceptor()),
			serveroption.WithGRPCStreamInterceptor(serverVersionStreamInterceptor()),
		}

		// Hubble TLS/mTLS setup.
		var tlsServerConfig *certloader.WatchedServerConfig
		if h.config.DisableServerTLS {
			options = append(options, serveroption.WithInsecure())
		} else {
			tlsServerConfigChan, err := certloader.FutureWatchedServerConfig(
				h.log.With(logfields.Config, "tls-server"),
				h.config.ServerTLSClientCAFiles,
				h.config.ServerTLSCertFile,
				h.config.ServerTLSKeyFile,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize hubble server TLS configuration: %w", err)
			}
			waitingMsgTimeout := time.After(30 * time.Second)
			for tlsServerConfig == nil {
				select {
				case tlsServerConfig = <-tlsServerConfigChan:
				case <-waitingMsgTimeout:
					h.log.Info("Waiting for Hubble server TLS certificate and key files to be created")
				case <-ctx.Done():
					return nil, fmt.Errorf("timeout while waiting for hubble server TLS certificate and key files to be created: %w", ctx.Err())
				}
			}
			options = append(options, serveroption.WithServerTLS(tlsServerConfig))
		}

		srv, err := server.NewServer(h.log, options...)
		if err != nil {
			if tlsServerConfig != nil {
				tlsServerConfig.Stop()
			}
			return nil, fmt.Errorf("failed to initialize hubble server: %w", err)
		}

		h.log.Info(
			"Starting Hubble server",
			logfields.Address, address,
			logfields.TLS, !h.config.DisableServerTLS,
		)
		go func() {
			if err := srv.Serve(); err != nil {
				h.log.Error(
					"Error while serving from Hubble server",
					logfields.Error, err,
					logfields.Address, address,
				)
				if tlsServerConfig != nil {
					tlsServerConfig.Stop()
				}
			}
		}()

		go func() {
			<-ctx.Done()
			srv.Stop()
			if tlsServerConfig != nil {
				tlsServerConfig.Stop()
			}
		}()
	}

	return hubbleObserver, nil
}

func getPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("parse host address and port: %w", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port number: %w", err)
	}
	return portNum, nil
}

var serverVersionHeader = metadata.Pairs(defaults.GRPCMetadataServerVersionKey, build.ServerVersion.SemVer())

func serverVersionUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		grpc.SetHeader(ctx, serverVersionHeader)
		return resp, err
	}
}

func serverVersionStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ss.SetHeader(serverVersionHeader)
		return handler(srv, ss)
	}
}
