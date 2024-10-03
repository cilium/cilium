// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/go-openapi/strfmt"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/dropeventemitter"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/hubble/monitor"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser"
	hubbleGetters "github.com/cilium/cilium/pkg/hubble/parser/getters"
	parserOptions "github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	hubbleRecorder "github.com/cilium/cilium/pkg/hubble/recorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/recorderoption"
	"github.com/cilium/cilium/pkg/hubble/recorder/sink"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
)

// Hubble is responsible for configuration, initialization, and shutdown of
// every Hubble components including the Hubble observer servers (TCP, UNIX
// domain socket), the Hubble metrics server, etc.
type Hubble struct {
	// Observer will be set once the Hubble Observer has been started.
	Observer atomic.Pointer[observer.LocalObserverServer]

	identityAllocator identitycell.CachingIdentityAllocator
	endpointManager   endpointmanager.EndpointManager
	IPCache           *ipcache.IPCache // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	serviceManager    service.ServiceManager
	CGroupManager     manager.CGroupManager   // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	Clientset         k8sClient.Clientset     // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	K8sWatcher        *watchers.K8sWatcher    // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	NodeManager       nodeManager.NodeManager // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	NodeLocalStore    *node.LocalNodeStore    // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	MonitorAgent      monitorAgent.Agent      // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	Recorder          *recorder.Recorder      // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.

	// NOTE: we still need DaemonConfig for the shared EnableRecorder flag.
	agentConfig *option.DaemonConfig
	config      config
}

// new creates and return a new Hubble.
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
	agentConfig *option.DaemonConfig,
	config config,
) (*Hubble, error) {
	config.normalize()
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Hubble configuration error: %w", err)
	}

	return &Hubble{
		Observer:          atomic.Pointer[observer.LocalObserverServer]{},
		identityAllocator: identityAllocator,
		endpointManager:   endpointManager,
		IPCache:           ipcache,
		serviceManager:    serviceManager,
		CGroupManager:     cgroupManager,
		Clientset:         clientset,
		K8sWatcher:        k8sWatcher,
		NodeManager:       nodeManager,
		NodeLocalStore:    nodeLocalStore,
		MonitorAgent:      monitorAgent,
		Recorder:          recorder,
		agentConfig:       agentConfig,
		config:            config,
	}, nil
}

// Status report the Hubble status for the Cilium Daemon status collector
// probe.
func (h *Hubble) Status(ctx context.Context) *models.HubbleStatus {
	if !h.config.EnableHubble {
		return &models.HubbleStatus{State: models.HubbleStatusStateDisabled}
	}

	obs := h.Observer.Load()
	if obs == nil {
		return &models.HubbleStatus{
			State: models.HubbleStatusStateWarning,
			Msg:   "Server not initialized",
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

// GetIdentity implements IdentityGetter. It looks up identity by ID from
// Cilium's identity cache. Hubble uses the identity info to populate flow
// source and destination labels.
func (h *Hubble) GetIdentity(securityIdentity uint32) (*identity.Identity, error) {
	ident := h.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident, nil
}

// GetEndpointInfo implements EndpointGetter. It returns endpoint info for a
// given IP address. Hubble uses this function to populate fields like
// namespace and pod name for local endpoints.
func (h *Hubble) GetEndpointInfo(ip netip.Addr) (endpoint hubbleGetters.EndpointInfo, ok bool) {
	if !ip.IsValid() {
		return nil, false
	}
	ep := h.endpointManager.LookupIP(ip)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

// GetEndpointInfoByID implements EndpointGetter. It returns endpoint info for
// a given Cilium endpoint id. Used by Hubble.
func (h *Hubble) GetEndpointInfoByID(id uint16) (endpoint hubbleGetters.EndpointInfo, ok bool) {
	ep := h.endpointManager.LookupCiliumID(id)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

// GetNamesOf implements DNSGetter.GetNamesOf. It looks up DNS names of a given
// IP from the FQDN cache of an endpoint specified by sourceEpID.
func (h *Hubble) GetNamesOf(sourceEpID uint32, ip netip.Addr) []string {
	ep := h.endpointManager.LookupCiliumID(uint16(sourceEpID))
	if ep == nil {
		return nil
	}

	if !ip.IsValid() {
		return nil
	}
	names := ep.DNSHistory.LookupIP(ip)

	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}

	return names
}

// GetServiceByAddr implements ServiceGetter. It looks up service by IP/port.
// Hubble uses this function to annotate flows with service information.
func (h *Hubble) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
	if !ip.IsValid() {
		return nil
	}
	addrCluster := cmtypes.AddrClusterFrom(ip, 0)
	addr := loadbalancer.L3n4Addr{
		AddrCluster: addrCluster,
		L4Addr: loadbalancer.L4Addr{
			Port: port,
		},
	}
	namespace, name, ok := h.serviceManager.GetServiceNameByAddr(addr)
	if !ok {
		return nil
	}
	return &flowpb.Service{
		Namespace: namespace,
		Name:      name,
	}
}

func (h *Hubble) Launch(ctx context.Context) {
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble")
	if !h.config.EnableHubble {
		logger.Info("Hubble server is disabled")
		return
	}

	var (
		observerOpts []observeroption.Option
		localSrvOpts []serveroption.Option
		parserOpts   []parserOptions.Option
	)

	if len(h.config.MonitorEvents) > 0 {
		monitorFilter, err := monitor.NewMonitorFilter(logger, h.config.MonitorEvents)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize Hubble monitor event filter")
		} else {
			observerOpts = append(observerOpts, observeroption.WithOnMonitorEvent(monitorFilter))
		}
	}

	if h.config.EnableK8sDropEvents {
		logger.
			WithField("interval", h.config.K8sDropEventsInterval).
			WithField("reasons", h.config.K8sDropEventsReasons).
			Info("Starting packet drop events emitter")

		dropEventEmitter := dropeventemitter.NewDropEventEmitter(
			h.config.K8sDropEventsInterval,
			h.config.K8sDropEventsReasons,
			h.Clientset,
			h.K8sWatcher,
		)

		observerOpts = append(observerOpts,
			observeroption.WithOnDecodedFlowFunc(func(ctx context.Context, flow *flowpb.Flow) (bool, error) {
				err := dropEventEmitter.ProcessFlow(ctx, flow)
				if err != nil {
					logger.WithError(err).Error("Failed to ProcessFlow in drop events handler")
				}
				return false, nil
			}),
		)
	}

	// fill in the local node information after the dropEventEmitter logique,
	// but before anything else (e.g. metrics).
	localNodeWatcher, err := observer.NewLocalNodeWatcher(ctx, h.NodeLocalStore)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve local node information")
		return
	}
	observerOpts = append(observerOpts, observeroption.WithOnDecodedFlow(localNodeWatcher))

	grpcMetrics := grpc_prometheus.NewServerMetrics()
	var metricsTLSConfig *certloader.WatchedServerConfig
	if h.config.EnableMetricsServerTLS {
		metricsTLSConfigChan, err := certloader.FutureWatchedServerConfig(
			logger.WithField("config", "hubble-metrics-server-tls"),
			h.config.MetricsServerTLSClientCAFiles,
			h.config.MetricsServerTLSCertFile,
			h.config.MetricsServerTLSKeyFile,
		)
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble metrics server TLS configuration")
			return
		}
		waitingMsgTimeout := time.After(30 * time.Second)
		for metricsTLSConfig == nil {
			select {
			case metricsTLSConfig = <-metricsTLSConfigChan:
			case <-waitingMsgTimeout:
				logger.Info("Waiting for Hubble metrics server TLS certificate and key files to be created")
			case <-ctx.Done():
				logger.WithError(ctx.Err()).Error("Timeout while waiting for Hubble metrics server TLS certificate and key files to be created")
				return
			}
		}
		go func() {
			<-ctx.Done()
			metricsTLSConfig.Stop()
		}()
	}

	var srv *http.Server
	if h.config.MetricsServer != "" {
		logger.WithFields(logrus.Fields{
			"address": h.config.MetricsServer,
			"metrics": h.config.Metrics,
			"tls":     h.config.EnableMetricsServerTLS,
		}).Info("Starting Hubble Metrics server")

		err := metrics.InitMetrics(metrics.Registry, api.ParseStaticMetricsConfig(h.config.Metrics), grpcMetrics)
		if err != nil {
			logger.WithError(err).Error("Unable to setup metrics: %w", err)
			return
		}

		srv = &http.Server{
			Addr:    h.config.MetricsServer,
			Handler: nil,
		}
		metrics.InitMetricsServerHandler(srv, metrics.Registry, h.config.EnableOpenMetrics)

		go func() {
			if err := metrics.StartMetricsServer(srv, logger, metricsTLSConfig, grpcMetrics); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Error("Hubble metrics server encountered an error")
				return
			}
		}()

		observerOpts = append(observerOpts,
			observeroption.WithOnDecodedFlowFunc(func(ctx context.Context, flow *flowpb.Flow) (bool, error) {
				err := metrics.ProcessFlow(ctx, flow)
				if err != nil {
					logger.WithError(err).Error("Failed to ProcessFlow in metrics handler")
				}
				return false, nil
			}),
		)

		localSrvOpts = append(localSrvOpts,
			serveroption.WithGRPCMetrics(grpcMetrics),
			serveroption.WithGRPCStreamInterceptor(grpcMetrics.StreamServerInterceptor()),
			serveroption.WithGRPCUnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
		)
	}

	if h.config.EnableRedact {
		parserOpts = append(
			parserOpts,
			parserOptions.Redact(
				logger,
				h.config.RedactHttpURLQuery,
				h.config.RedactHttpUserInfo,
				h.config.RedactKafkaAPIKey,
				h.config.RedactHttpHeadersAllow,
				h.config.RedactHttpHeadersDeny,
			),
		)
	}

	payloadParser, err := parser.New(logger, h, h, h, h.IPCache, h, link.NewLinkCache(), h.CGroupManager, h.config.SkipUnknownCGroupIDs, parserOpts...)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}

	maxFlows, err := container.NewCapacity(h.config.EventBufferCapacity)
	if err != nil {
		logger.WithError(err).Error("Specified capacity for Hubble events buffer is invalid")
		return
	}
	observerOpts = append(observerOpts,
		observeroption.WithMaxFlows(maxFlows),
		observeroption.WithMonitorBuffer(h.config.EventQueueSize),
	)
	if h.config.ExportFilePath != "" {
		exporterOpts := []exporteroption.Option{
			exporteroption.WithPath(h.config.ExportFilePath),
			exporteroption.WithMaxSizeMB(h.config.ExportFileMaxSizeMB),
			exporteroption.WithMaxBackups(h.config.ExportFileMaxBackups),
			exporteroption.WithAllowList(logger, h.config.ExportAllowlist),
			exporteroption.WithDenyList(logger, h.config.ExportDenylist),
			exporteroption.WithFieldMask(h.config.ExportFieldmask),
		}
		if h.config.ExportFileCompress {
			exporterOpts = append(exporterOpts, exporteroption.WithCompress())
		}
		hubbleExporter, err := exporter.NewExporter(ctx, logger, exporterOpts...)
		if err != nil {
			logger.WithError(err).Error("Failed to configure Hubble export")
		} else {
			opt := observeroption.WithOnDecodedEvent(hubbleExporter)
			observerOpts = append(observerOpts, opt)
		}
	}
	if h.config.FlowlogsConfigFilePath != "" {
		dynamicHubbleExporter := exporter.NewDynamicExporter(logger, h.config.FlowlogsConfigFilePath, h.config.ExportFileMaxSizeMB, h.config.ExportFileMaxBackups)
		opt := observeroption.WithOnDecodedEvent(dynamicHubbleExporter)
		observerOpts = append(observerOpts, opt)
	}
	namespaceManager := observer.NewNamespaceManager()
	go namespaceManager.Run(ctx)

	hubbleObserver, err := observer.NewLocalServer(
		payloadParser,
		namespaceManager,
		logger,
		observerOpts...,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}
	go hubbleObserver.Start()
	h.MonitorAgent.RegisterNewConsumer(monitor.NewConsumer(hubbleObserver))

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
			logger.WithError(err).WithField("address", addr).Warn("Hubble server will not pass port information in change notificantions on exposed Hubble peer service")
		} else {
			peerServiceOptions = append(peerServiceOptions, serviceoption.WithHubblePort(port))
		}
	}
	peerSvc := peer.NewService(h.NodeManager, peerServiceOptions...)
	localSrvOpts = append(localSrvOpts,
		serveroption.WithUnixSocketListener(sockPath),
		serveroption.WithHealthService(),
		serveroption.WithObserverService(hubbleObserver),
		serveroption.WithPeerService(peerSvc),
		serveroption.WithInsecure(),
	)

	if h.agentConfig.EnableRecorder && h.config.EnableRecorderAPI {
		dispatch, err := sink.NewDispatch(h.config.RecorderSinkQueueSize)
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble recorder sink dispatch")
			return
		}
		h.MonitorAgent.RegisterNewConsumer(dispatch)
		svc, err := hubbleRecorder.NewService(h.Recorder, dispatch,
			recorderoption.WithStoragePath(h.config.RecorderStoragePath))
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble recorder service")
			return
		}
		localSrvOpts = append(localSrvOpts, serveroption.WithRecorderService(svc))
	}

	localSrv, err := server.NewServer(logger, localSrvOpts...)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize local Hubble server")
		return
	}
	logger.WithField("address", sockPath).Info("Starting local Hubble server")
	go func() {
		if err := localSrv.Serve(); err != nil {
			logger.WithError(err).WithField("address", sockPath).Error("Error while serving from local Hubble server")
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
			logger.WithField("address", address).Warn("Hubble server will be exposing its API insecurely on this address")
		}
		options := []serveroption.Option{
			serveroption.WithTCPListener(address),
			serveroption.WithHealthService(),
			serveroption.WithPeerService(peerSvc),
			serveroption.WithObserverService(hubbleObserver),
		}

		// Hubble TLS/mTLS setup.
		var tlsServerConfig *certloader.WatchedServerConfig
		if h.config.DisableServerTLS {
			options = append(options, serveroption.WithInsecure())
		} else {
			tlsServerConfigChan, err := certloader.FutureWatchedServerConfig(
				logger.WithField("config", "tls-server"),
				h.config.ServerTLSClientCAFiles,
				h.config.ServerTLSCertFile,
				h.config.ServerTLSKeyFile,
			)
			if err != nil {
				logger.WithError(err).Error("Failed to initialize Hubble server TLS configuration")
				return
			}
			waitingMsgTimeout := time.After(30 * time.Second)
			for tlsServerConfig == nil {
				select {
				case tlsServerConfig = <-tlsServerConfigChan:
				case <-waitingMsgTimeout:
					logger.Info("Waiting for Hubble server TLS certificate and key files to be created")
				case <-ctx.Done():
					logger.WithError(ctx.Err()).Error("Timeout while waiting for Hubble server TLS certificate and key files to be created")
					return
				}
			}
			options = append(options, serveroption.WithServerTLS(tlsServerConfig))
		}

		srv, err := server.NewServer(logger, options...)
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble server")
			if tlsServerConfig != nil {
				tlsServerConfig.Stop()
			}
			return
		}

		logger.WithFields(logrus.Fields{
			"address": address,
			"tls":     !h.config.DisableServerTLS,
		}).Info("Starting Hubble server")
		go func() {
			if err := srv.Serve(); err != nil {
				logger.WithError(err).WithField("address", address).Error("Error while serving from Hubble server")
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

	h.Observer.Store(hubbleObserver)
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
