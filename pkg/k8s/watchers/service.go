// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgp/speaker"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/time"
)

type k8sServiceWatcherParams struct {
	cell.In

	K8sEventReporter *K8sEventReporter

	Resources         agentK8s.Resources
	K8sResourceSynced *k8sSynced.Resources
	K8sAPIGroups      *k8sSynced.APIGroups

	ServiceCache      *k8s.ServiceCache
	ServiceManager    service.ServiceManager
	LRPManager        *redirectpolicy.Manager
	MetalLBBgpSpeaker speaker.MetalLBBgpSpeaker
	LocalNodeStore    *node.LocalNodeStore
}

func newK8sServiceWatcher(params k8sServiceWatcherParams) *K8sServiceWatcher {
	return &K8sServiceWatcher{
		k8sEventReporter:      params.K8sEventReporter,
		k8sResourceSynced:     params.K8sResourceSynced,
		k8sAPIGroups:          params.K8sAPIGroups,
		resources:             params.Resources,
		k8sSvcCache:           params.ServiceCache,
		svcManager:            params.ServiceManager,
		redirectPolicyManager: params.LRPManager,
		bgpSpeakerManager:     params.MetalLBBgpSpeaker,
		localNodeStore:        params.LocalNodeStore,
		stop:                  make(chan struct{}),
	}
}

type K8sServiceWatcher struct {
	k8sEventReporter *K8sEventReporter
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources
	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups
	resources    agentK8s.Resources

	k8sSvcCache           *k8s.ServiceCache
	svcManager            svcManager
	redirectPolicyManager redirectPolicyManager
	bgpSpeakerManager     bgpSpeakerManager
	localNodeStore        *node.LocalNodeStore

	stop chan struct{}
}

func (k *K8sServiceWatcher) servicesInit() {
	var synced atomic.Bool
	swgSvcs := lock.NewStoppableWaitGroup()

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		k.stop,
		swgSvcs,
		func() bool { return synced.Load() },
		resources.K8sAPIGroupServiceV1Core,
	)
	go k.serviceEventLoop(&synced, swgSvcs)

	k.k8sAPIGroups.AddAPI(resources.K8sAPIGroupServiceV1Core)
}

func (k *K8sServiceWatcher) stopWatcher() {
	close(k.stop)
}

func (k *K8sServiceWatcher) serviceEventLoop(synced *atomic.Bool, swg *lock.StoppableWaitGroup) {
	apiGroup := resources.K8sAPIGroupServiceV1Core
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := k.resources.Services.Events(ctx)
	for {
		select {
		case <-k.stop:
			cancel()
		case event, ok := <-events:
			if !ok {
				return
			}
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				svc := event.Object
				k.k8sResourceSynced.SetEventTimestamp(apiGroup)
				k.upsertK8sServiceV1(svc, swg)
			case resource.Delete:
				svc := event.Object
				k.k8sResourceSynced.SetEventTimestamp(apiGroup)
				k.deleteK8sServiceV1(svc, swg)
			}
			event.Done(nil)
		}
	}
}

func (k *K8sServiceWatcher) upsertK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	svcID := k.k8sSvcCache.UpdateService(svc, swg)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			// The local redirect policies currently support services of type
			// clusterIP only.
			k.redirectPolicyManager.OnAddService(svcID)
		}
	}
	k.bgpSpeakerManager.OnUpdateService(svc)
}

func (k *K8sServiceWatcher) deleteK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	k.k8sSvcCache.DeleteService(svc, swg)
	svcID := k8s.ParseServiceID(svc)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			k.redirectPolicyManager.OnDeleteService(svcID)
		}
	}
	k.bgpSpeakerManager.OnDeleteService(svc)
}

func (k *K8sServiceWatcher) k8sServiceHandler() {
	eventHandler := func(event k8s.ServiceEvent) {
		defer func(startTime time.Time) {
			event.SWG.Done()
			k.k8sServiceEventProcessed(event.Action.String(), startTime)
		}(time.Now())

		svc := event.Service

		scopedLog := log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
		})

		if logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel) {
			scopedLog.WithFields(logrus.Fields{
				"action":        event.Action.String(),
				"service":       event.Service.String(),
				"old-service":   event.OldService.String(),
				"endpoints":     event.Endpoints.String(),
				"old-endpoints": event.OldEndpoints.String(),
			}).Debug("Kubernetes service definition changed")
		}

		switch event.Action {
		case k8s.UpdateService:
			k.addK8sSVCs(event.ID, event.OldService, svc, event.Endpoints)
		case k8s.DeleteService:
			k.delK8sSVCs(event.ID, event.Service)
		}
	}
	for {
		select {
		case <-k.stop:
			return
		case event, ok := <-k.k8sSvcCache.Events:
			if !ok {
				return
			}
			eventHandler(event)
		}
	}
}

func (k *K8sServiceWatcher) RunK8sServiceHandler() {
	go k.k8sServiceHandler()
}

func (k *K8sServiceWatcher) delK8sSVCs(svc k8s.ServiceID, svcInfo *k8s.Service) {
	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	})

	repPorts := svcInfo.UniquePorts()

	frontends := []*loadbalancer.L3n4Addr{}

	for portName, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		for _, feIP := range svcInfo.FrontendIPs {
			fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(feIP), svcPort.Port, loadbalancer.ScopeExternal)
			frontends = append(frontends, fe)
		}

		for _, nodePortFE := range svcInfo.NodePorts[portName] {
			frontends = append(frontends, &nodePortFE.L3n4Addr)
			if svcInfo.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal || svcInfo.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				cpFE := nodePortFE.L3n4Addr.DeepCopy()
				cpFE.Scope = loadbalancer.ScopeInternal
				frontends = append(frontends, cpFE)
			}
		}

		for _, k8sExternalIP := range svcInfo.K8sExternalIPs {
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(k8sExternalIP), svcPort.Port, loadbalancer.ScopeExternal))
		}

		for _, ip := range svcInfo.LoadBalancerIPs {
			addrCluster := cmtypes.MustAddrClusterFromIP(ip)
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeExternal))
			if svcInfo.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal || svcInfo.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeInternal))
			}
		}
	}

	for _, fe := range frontends {
		if found, err := k.svcManager.DeleteService(*fe); err != nil {
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(fe)).
				Warn("Error deleting service by frontend")
		} else if !found {
			scopedLog.WithField(logfields.Object, logfields.Repr(fe)).Warn("service not found")
		} else {
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", fe.AddrCluster.String(), fe.Port)
		}
	}
}

func genCartesianProduct(
	fe net.IP,
	twoScopes bool,
	svcType loadbalancer.SVCType,
	ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr,
	bes *k8s.Endpoints,
) []loadbalancer.SVC {
	var svcSize int

	// For externalTrafficPolicy=Local xor internalTrafficPolicy=Local we
	// add both external and internal scoped frontends, hence twice the size
	// for only this case.
	if twoScopes &&
		(svcType == loadbalancer.SVCTypeLoadBalancer || svcType == loadbalancer.SVCTypeNodePort) {
		svcSize = len(ports) * 2
	} else {
		svcSize = len(ports)
	}

	svcs := make([]loadbalancer.SVC, 0, svcSize)
	feFamilyIPv6 := ip.IsIPv6(fe)

	for fePortName, fePort := range ports {
		var besValues []*loadbalancer.Backend
		for addrCluster, backend := range bes.Backends {
			if backendPort := backend.Ports[string(fePortName)]; backendPort != nil && feFamilyIPv6 == addrCluster.Is6() {
				backendState := loadbalancer.BackendStateActive
				if backend.Terminating {
					backendState = loadbalancer.BackendStateTerminating
				}
				besValues = append(besValues, &loadbalancer.Backend{
					FEPortName: string(fePortName),
					NodeName:   backend.NodeName,
					ZoneID:     option.Config.GetZoneID(backend.Zone),
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *backendPort,
					},
					State:     backendState,
					Preferred: loadbalancer.Preferred(backend.Preferred),
					Weight:    loadbalancer.DefaultBackendWeight,
				})
			}
		}

		addrCluster := cmtypes.MustAddrClusterFromIP(fe)

		// External scoped entry - when external and internal policies are the same.
		svcs = append(svcs,
			loadbalancer.SVC{
				Frontend: loadbalancer.L3n4AddrID{
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr: loadbalancer.L4Addr{
							Protocol: fePort.Protocol,
							Port:     fePort.Port,
						},
						Scope: loadbalancer.ScopeExternal,
					},
					ID: loadbalancer.ID(0),
				},
				Backends: besValues,
				Type:     svcType,
			})

		// Internal scoped entry - when only one of traffic policies is Local.
		if svcSize > len(ports) {
			svcs = append(svcs,
				loadbalancer.SVC{
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							AddrCluster: addrCluster,
							L4Addr: loadbalancer.L4Addr{
								Protocol: fePort.Protocol,
								Port:     fePort.Port,
							},
							Scope: loadbalancer.ScopeInternal,
						},
						ID: loadbalancer.ID(0),
					},
					Backends: besValues,
					Type:     svcType,
				})
		}
	}
	return svcs
}

// datapathSVCs returns all services that should be set in the datapath.
func (k *K8sServiceWatcher) datapathSVCs(svc *k8s.Service, endpoints *k8s.Endpoints) ([]loadbalancer.SVC, error) {
	svcs := []loadbalancer.SVC{}

	if nodeMatches, err := k.checkServiceNodeExposure(svc); err != nil || !nodeMatches {
		return svcs, err
	}
	uniqPorts := svc.UniquePorts()

	clusterIPPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
	for fePortName, fePort := range svc.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}
		uniqPorts[fePort.Port] = false
		clusterIPPorts[fePortName] = fePort
	}

	twoScopes := (svc.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal) != (svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal)

	for _, frontendIP := range svc.FrontendIPs {
		dpSVC := genCartesianProduct(frontendIP, twoScopes, loadbalancer.SVCTypeClusterIP, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, ip := range svc.LoadBalancerIPs {
		dpSVC := genCartesianProduct(ip, twoScopes, loadbalancer.SVCTypeLoadBalancer, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, k8sExternalIP := range svc.K8sExternalIPs {
		dpSVC := genCartesianProduct(k8sExternalIP, twoScopes, loadbalancer.SVCTypeExternalIPs, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for fePortName := range clusterIPPorts {
		for _, nodePortFE := range svc.NodePorts[fePortName] {
			nodePortPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				fePortName: &nodePortFE.L4Addr,
			}
			dpSVC := genCartesianProduct(nodePortFE.AddrCluster.Addr().AsSlice(), twoScopes, loadbalancer.SVCTypeNodePort, nodePortPorts, endpoints)
			svcs = append(svcs, dpSVC...)
		}
	}

	lbSrcRanges := make([]*cidr.CIDR, 0, len(svc.LoadBalancerSourceRanges))
	for _, cidr := range svc.LoadBalancerSourceRanges {
		lbSrcRanges = append(lbSrcRanges, cidr)
	}

	// apply common service properties
	for i := range svcs {
		svcs[i].ExtTrafficPolicy = svc.ExtTrafficPolicy
		svcs[i].IntTrafficPolicy = svc.IntTrafficPolicy
		svcs[i].HealthCheckNodePort = svc.HealthCheckNodePort
		svcs[i].SessionAffinity = svc.SessionAffinity
		svcs[i].SessionAffinityTimeoutSec = svc.SessionAffinityTimeoutSec
		if svcs[i].Type == loadbalancer.SVCTypeLoadBalancer {
			svcs[i].LoadBalancerSourceRanges = lbSrcRanges
		}
		svcs[i].Annotations = svc.Annotations
	}

	return svcs, nil
}

// checkServiceNodeExposure returns true if the service should be installed onto the
// local node, and false if the node should ignore and not install the service.
func (k *K8sServiceWatcher) checkServiceNodeExposure(svc *k8s.Service) (bool, error) {
	if serviceLabelValue, serviceLabelExists := svc.Labels[annotation.ServiceNodeExposure]; serviceLabelExists {
		ln, err := k.localNodeStore.Get(context.Background())
		if err != nil {
			return false, fmt.Errorf("failed to retrieve local node: %w", err)
		}

		nodeLabelValue, nodeLabelExists := ln.Labels[annotation.ServiceNodeExposure]
		if !nodeLabelExists || nodeLabelValue != serviceLabelValue {
			return false, nil
		}
	}

	return true, nil
}

// hashSVCMap returns a mapping of all frontend's hash to the its corresponded
// value.
func hashSVCMap(svcs []loadbalancer.SVC) map[string]loadbalancer.L3n4Addr {
	m := map[string]loadbalancer.L3n4Addr{}
	for _, svc := range svcs {
		m[svc.Frontend.L3n4Addr.Hash()] = svc.Frontend.L3n4Addr
	}
	return m
}

func (k *K8sServiceWatcher) addK8sSVCs(svcID k8s.ServiceID, oldSvc, svc *k8s.Service, endpoints *k8s.Endpoints) {
	// Headless services do not need any datapath implementation
	if svc.IsHeadless {
		return
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})
	svcs, err := k.datapathSVCs(svc, endpoints)
	if err != nil {
		scopedLog.WithError(err).Error("Error while evaluating datapath services")
		return
	}
	svcMap := hashSVCMap(svcs)

	if oldSvc != nil {
		// If we have oldService then we need to detect which frontends
		// are no longer in the updated service and delete them in the datapath.
		oldSVCs, err := k.datapathSVCs(oldSvc, endpoints)
		if err != nil {
			scopedLog.WithError(err).Error("Error while evaluating datapath services for old service")
			return
		}
		oldSVCMap := hashSVCMap(oldSVCs)

		for svcHash, oldSvc := range oldSVCMap {
			if _, ok := svcMap[svcHash]; !ok {
				if found, err := k.svcManager.DeleteService(oldSvc); err != nil {
					scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(oldSvc)).
						Warn("Error deleting service by frontend")
				} else if !found {
					scopedLog.WithField(logfields.Object, logfields.Repr(oldSvc)).Warn("service not found")
				} else {
					scopedLog.Debugf("# cilium lb delete-service %s %d 0", oldSvc.AddrCluster.String(), oldSvc.Port)
				}
			}
		}
	}

	for _, dpSvc := range svcs {
		p := &loadbalancer.SVC{
			Frontend:                  dpSvc.Frontend,
			Backends:                  dpSvc.Backends,
			Type:                      dpSvc.Type,
			ExtTrafficPolicy:          dpSvc.ExtTrafficPolicy,
			IntTrafficPolicy:          dpSvc.IntTrafficPolicy,
			SessionAffinity:           dpSvc.SessionAffinity,
			SessionAffinityTimeoutSec: dpSvc.SessionAffinityTimeoutSec,
			HealthCheckNodePort:       dpSvc.HealthCheckNodePort,
			Annotations:               dpSvc.Annotations,
			LoadBalancerSourceRanges:  dpSvc.LoadBalancerSourceRanges,
			Name: loadbalancer.ServiceName{
				Name:      svcID.Name,
				Namespace: svcID.Namespace,
				Cluster:   svcID.Cluster,
			},
		}
		if _, _, err := k.svcManager.UpsertService(p); err != nil {
			if errors.Is(err, service.NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
				scopedLog.WithError(err).Debug("Error while inserting service in LB map")
			} else {
				scopedLog.WithError(err).Error("Error while inserting service in LB map")
			}
		}
	}
}

// k8sServiceEventProcessed is called to do metrics accounting the duration to program the service.
func (k *K8sServiceWatcher) k8sServiceEventProcessed(action string, startTime time.Time) {
	duration, _ := safetime.TimeSinceSafe(startTime, log)
	metrics.ServiceImplementationDelay.WithLabelValues(action).Observe(duration.Seconds())
}
