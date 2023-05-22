// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/go-openapi/strfmt"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/sirupsen/logrus"
	k8scache "k8s.io/client-go/tools/cache"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/datapath/link"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/exporter"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/monitor"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/hubble/recorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/recorderoption"
	"github.com/cilium/cilium/pkg/hubble/recorder/sink"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

func (d *Daemon) getHubbleStatus(ctx context.Context) *models.HubbleStatus {
	if !option.Config.EnableHubble {
		return &models.HubbleStatus{State: models.HubbleStatusStateDisabled}
	}

	if d.hubbleObserver == nil {
		return &models.HubbleStatus{
			State: models.HubbleStatusStateWarning,
			Msg:   "Server not initialized",
		}
	}

	req := &observerpb.ServerStatusRequest{}
	status, err := d.hubbleObserver.ServerStatus(ctx, req)
	if err != nil {
		return &models.HubbleStatus{State: models.HubbleStatusStateFailure, Msg: err.Error()}
	}

	metricsState := models.HubbleStatusMetricsStateDisabled
	if option.Config.HubbleMetricsServer != "" {
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

func (d *Daemon) launchHubble() {
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble")
	if !option.Config.EnableHubble {
		logger.Info("Hubble server is disabled")
		return
	}

	var (
		observerOpts []observeroption.Option
		localSrvOpts []serveroption.Option
	)

	if len(option.Config.HubbleMonitorEvents) > 0 {
		monitorFilter, err := monitor.NewMonitorFilter(logger, option.Config.HubbleMonitorEvents)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize Hubble monitor event filter")
		} else {
			observerOpts = append(observerOpts, observeroption.WithOnMonitorEvent(monitorFilter))
		}
	}

	if option.Config.HubbleMetricsServer != "" {
		logger.WithFields(logrus.Fields{
			"address": option.Config.HubbleMetricsServer,
			"metrics": option.Config.HubbleMetrics,
		}).Info("Starting Hubble Metrics server")
		grpcMetrics := grpc_prometheus.NewServerMetrics()

		if err := metrics.EnableMetrics(log, option.Config.HubbleMetricsServer, option.Config.HubbleMetrics, grpcMetrics, option.Config.EnableHubbleOpenMetrics); err != nil {
			logger.WithError(err).Warn("Failed to initialize Hubble metrics server")
			return
		}

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

	d.linkCache = link.NewLinkCache()
	payloadParser, err := parser.New(logger, d, d, d, d, d, d.linkCache, d.cgroupManager)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}

	maxFlows, err := getHubbleEventBufferCapacity(logger)
	if err != nil {
		logger.WithError(err).Error("Specified capacity for Hubble events buffer is invalid")
		return
	}
	observerOpts = append(observerOpts,
		observeroption.WithMaxFlows(maxFlows),
		observeroption.WithMonitorBuffer(option.Config.HubbleEventQueueSize),
		observeroption.WithCiliumDaemon(d),
	)
	if option.Config.HubbleExportFilePath != "" {
		exporterOpts := []exporteroption.Option{
			exporteroption.WithPath(option.Config.HubbleExportFilePath),
			exporteroption.WithMaxSizeMB(option.Config.HubbleExportFileMaxSizeMB),
			exporteroption.WithMaxBackups(option.Config.HubbleExportFileMaxBackups),
		}
		if option.Config.HubbleExportFileCompress {
			exporterOpts = append(exporterOpts, exporteroption.WithCompress())
		}
		hubbleExporter, err := exporter.NewExporter(logger, exporterOpts...)
		if err != nil {
			logger.WithError(err).Error("Failed to configure Hubble export")
		} else {
			opt := observeroption.WithOnDecodedEvent(hubbleExporter)
			observerOpts = append(observerOpts, opt)
		}
	}

	d.hubbleObserver, err = observer.NewLocalServer(payloadParser, logger,
		observerOpts...,
	)
	if err != nil {
		logger.WithError(err).Error("Failed to initialize Hubble")
		return
	}
	go d.hubbleObserver.Start()
	d.monitorAgent.RegisterNewConsumer(monitor.NewConsumer(d.hubbleObserver))

	// configure a local hubble instance that serves more gRPC services
	sockPath := "unix://" + option.Config.HubbleSocketPath
	var peerServiceOptions []serviceoption.Option
	if option.Config.HubbleTLSDisabled {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithoutTLSInfo())
	}
	if option.Config.HubblePreferIpv6 {
		peerServiceOptions = append(peerServiceOptions, serviceoption.WithAddressFamilyPreference(serviceoption.AddressPreferIPv6))
	}
	peerSvc := peer.NewService(d.nodeDiscovery.Manager, peerServiceOptions...)
	localSrvOpts = append(localSrvOpts,
		serveroption.WithUnixSocketListener(sockPath),
		serveroption.WithHealthService(),
		serveroption.WithObserverService(d.hubbleObserver),
		serveroption.WithPeerService(peerSvc),
		serveroption.WithInsecure(),
	)

	if option.Config.EnableRecorder && option.Config.EnableHubbleRecorderAPI {
		dispatch, err := sink.NewDispatch(option.Config.HubbleRecorderSinkQueueSize)
		if err != nil {
			logger.WithError(err).Error("Failed to initialize Hubble recorder sink dispatch")
			return
		}
		d.monitorAgent.RegisterNewConsumer(dispatch)
		svc, err := recorder.NewService(d.rec, dispatch,
			recorderoption.WithStoragePath(option.Config.HubbleRecorderStoragePath))
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
		<-d.ctx.Done()
		localSrv.Stop()
		peerSvc.Close()
	}()

	// configure another hubble instance that serve fewer gRPC services
	address := option.Config.HubbleListenAddress
	if address != "" {
		if option.Config.HubbleTLSDisabled {
			logger.WithField("address", address).Warn("Hubble server will be exposing its API insecurely on this address")
		}
		options := []serveroption.Option{
			serveroption.WithTCPListener(address),
			serveroption.WithHealthService(),
			serveroption.WithPeerService(peerSvc),
			serveroption.WithObserverService(d.hubbleObserver),
		}

		// Hubble TLS/mTLS setup.
		var tlsServerConfig *certloader.WatchedServerConfig
		if option.Config.HubbleTLSDisabled {
			options = append(options, serveroption.WithInsecure())
		} else {
			tlsServerConfigChan, err := certloader.FutureWatchedServerConfig(
				logger.WithField("config", "tls-server"),
				option.Config.HubbleTLSClientCAFiles,
				option.Config.HubbleTLSCertFile,
				option.Config.HubbleTLSKeyFile,
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
				case <-d.ctx.Done():
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

		logger.WithField("address", address).Info("Starting Hubble server")
		go func() {
			if err := srv.Serve(); err != nil {
				logger.WithError(err).WithField("address", address).Error("Error while serving from Hubble server")
				if tlsServerConfig != nil {
					tlsServerConfig.Stop()
				}
			}
		}()

		go func() {
			<-d.ctx.Done()
			srv.Stop()
			if tlsServerConfig != nil {
				tlsServerConfig.Stop()
			}
		}()
	}
}

// GetIdentity looks up identity by ID from Cilium's identity cache. Hubble uses the identity info
// to populate source and destination labels of flows.
func (d *Daemon) GetIdentity(securityIdentity uint32) (*identity.Identity, error) {
	ident := d.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident, nil
}

// GetEndpointInfo returns endpoint info for a given IP address. Hubble uses this function to populate
// fields like namespace and pod name for local endpoints.
func (d *Daemon) GetEndpointInfo(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
	if !ip.IsValid() {
		return nil, false
	}
	ep := d.endpointManager.LookupIP(ip)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

// GetEndpointInfoByID returns endpoint info for a given Cilium endpoint id. Used by Hubble.
func (d *Daemon) GetEndpointInfoByID(id uint16) (endpoint v1.EndpointInfo, ok bool) {
	ep := d.endpointManager.LookupCiliumID(id)
	if ep == nil {
		return nil, false
	}
	return ep, true
}

func (d *Daemon) GetEndpoints() map[policy.Endpoint]struct{} {
	return d.endpointManager.GetPolicyEndpoints()
}

// GetNamesOf implements DNSGetter.GetNamesOf. It looks up DNS names of a given IP from the
// FQDN cache of an endpoint specified by sourceEpID.
func (d *Daemon) GetNamesOf(sourceEpID uint32, ip netip.Addr) []string {
	ep := d.endpointManager.LookupCiliumID(uint16(sourceEpID))
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

// GetServiceByAddr looks up service by IP/port. Hubble uses this function to annotate flows
// with service information.
func (d *Daemon) GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service {
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
	namespace, name, ok := d.svc.GetServiceNameByAddr(addr)
	if !ok {
		return nil
	}
	return &flowpb.Service{
		Namespace: namespace,
		Name:      name,
	}
}

// GetK8sMetadata returns the Kubernetes metadata for the given IP address.
// It implements hubble parser's IPGetter.GetK8sMetadata.
func (d *Daemon) GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata {
	if !ip.IsValid() {
		return nil
	}
	return d.ipcache.GetK8sMetadata(ip.String())
}

// LookupSecIDByIP returns the security ID for the given IP. If the security ID
// cannot be found, ok is false.
// It implements hubble parser's IPGetter.LookupSecIDByIP.
func (d *Daemon) LookupSecIDByIP(ip netip.Addr) (id ipcache.Identity, ok bool) {
	if !ip.IsValid() {
		return ipcache.Identity{}, false
	}

	if id, ok = d.ipcache.LookupByIP(ip.String()); ok {
		return id, ok
	}

	ipv6Prefixes, ipv4Prefixes := d.GetCIDRPrefixLengths()
	prefixes := ipv4Prefixes
	if ip.Is6() {
		prefixes = ipv6Prefixes
	}
	for _, prefixLen := range prefixes {
		// note: we perform a lookup even when `prefixLen == bits`, as some
		// entries derived by a single address cidr-range will not have been
		// found by the above lookup
		cidr, _ := ip.Prefix(prefixLen)
		if id, ok = d.ipcache.LookupByPrefix(cidr.String()); ok {
			return id, ok
		}
	}
	return id, false
}

// GetK8sStore returns the k8s watcher cache store for the given resource name.
// It implements hubble parser's StoreGetter.GetK8sStore
// WARNING: the objects returned by these stores can't be used to create
// update objects into k8s as well as the objects returned by these stores
// should only be used for reading.
func (d *Daemon) GetK8sStore(name string) k8scache.Store {
	return d.k8sWatcher.GetStore(name)
}

// getHubbleEventBufferCapacity returns the user configured capacity for
// Hubble's events buffer.
func getHubbleEventBufferCapacity(logger logrus.FieldLogger) (container.Capacity, error) {
	return container.NewCapacity(option.Config.HubbleEventBufferCapacity)
}

func (d *Daemon) GetParentPodMetadata(cgroupId uint64) *cgroupManager.PodMetadata {
	return d.cgroupManager.GetPodMetadataForContainer(cgroupId)
}
