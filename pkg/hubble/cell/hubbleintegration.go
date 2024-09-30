// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-openapi/strfmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/observer"
	hubbleGetters "github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/loadbalancer"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
)

// Hubble is responsible for configuration, initialization, and shutdown of
// every Hubble components including the Hubble observer servers (TCP, UNIX
// domain socket), the Hubble metrics server, etc.
type Hubble struct {
	agentConfig *option.DaemonConfig
	// Observer will be set by the Cilium daemon once the Hubble Observer has
	// been started.
	Observer atomic.Pointer[observer.LocalObserverServer]

	identityAllocator identitycell.CachingIdentityAllocator
	endpointManager   endpointmanager.EndpointManager
	IPCache           *ipcache.IPCache // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	serviceManager    service.ServiceManager
	CGroupManager     manager.CGroupManager // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	Clientset         k8sClient.Clientset   // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	K8sWatcher        *watchers.K8sWatcher  // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	NodeLocalStore    *node.LocalNodeStore  // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
	MonitorAgent      monitorAgent.Agent    // FIXME: unexport once launchHubble() has moved away from the Cilium daemon.
}

// new creates and return a new Hubble.
func new(
	agentConfig *option.DaemonConfig,
	identityAllocator identitycell.CachingIdentityAllocator,
	endpointManager endpointmanager.EndpointManager,
	ipcache *ipcache.IPCache,
	serviceManager service.ServiceManager,
	cgroupManager manager.CGroupManager,
	clientset k8sClient.Clientset,
	k8sWatcher *watchers.K8sWatcher,
	nodeLocalStore *node.LocalNodeStore,
	monitorAgent monitorAgent.Agent,
) *Hubble {
	return &Hubble{
		agentConfig:       agentConfig,
		Observer:          atomic.Pointer[observer.LocalObserverServer]{},
		identityAllocator: identityAllocator,
		endpointManager:   endpointManager,
		IPCache:           ipcache,
		serviceManager:    serviceManager,
		CGroupManager:     cgroupManager,
		Clientset:         clientset,
		K8sWatcher:        k8sWatcher,
		NodeLocalStore:    nodeLocalStore,
		MonitorAgent:      monitorAgent,
	}
}

// Status report the Hubble status for the Cilium Daemon status collector
// probe.
func (h *Hubble) Status(ctx context.Context) *models.HubbleStatus {
	if !h.agentConfig.EnableHubble {
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
