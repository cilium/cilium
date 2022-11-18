package cache

import (
	"net"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

func (sc *serviceCache) GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints {
	<-sc.syncChan

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	epSlice, ok := sc.endpoints[svcID]
	if !ok {
		return nil
	}
	eps := epSlice.GetEndpoints()
	eps.EndpointSliceID.ServiceID = svcID
	return eps
}

func (sc *serviceCache) GetServiceFrontendIP(svcID k8s.ServiceID, svcType loadbalancer.SVCType) net.IP {
	<-sc.syncChan

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	svc := sc.services[svcID]
	if svc == nil || svc.Type != svcType || len(svc.FrontendIPs) == 0 {
		return nil
	}

	return ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
}

// GetServiceIP returns a random L3n4Addr that is backing the given Service ID.
// The returned IP is with external scope since its string representation might
// be used for net Dialer.
func (sc *serviceCache) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	<-sc.syncChan

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	svc := sc.services[svcID]
	if svc == nil || len(svc.FrontendIPs) == 0 || len(svc.Ports) == 0 {
		return nil
	}

	feIP := ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
	if feIP == nil {
		return nil
	}

	for _, port := range svc.Ports {
		return loadbalancer.NewL3n4Addr(port.Protocol, cmtypes.MustAddrClusterFromIP(feIP), port.Port,
			loadbalancer.ScopeExternal)
	}
	return nil
}

// TODO: Is EnsureService really needed? Why does it emit an event? Look at git history
// of EnsureService and figure out a way to get rid of it.
func (sc *serviceCache) EnsureService(svcID k8s.ServiceID) bool {
	<-sc.syncChan

	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if svc, found := sc.services[svcID]; found {
		if endpoints, serviceReady := sc.correlateEndpoints(svcID); serviceReady {
			sc.mcast.emit(&ServiceEvent{
				Action:     UpdateService,
				ID:         svcID,
				Service:    svc,
				OldService: svc,
				Endpoints:  endpoints,
			})
			return true
		}
	}
	return false
}

func (sc *serviceCache) GetServiceAddrsWithType(svcID k8s.ServiceID, svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	<-sc.syncChan

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	svc := sc.services[svcID]
	if svc == nil || svc.Type != svcType || len(svc.FrontendIPs) == 0 {
		return nil, 0
	}

	addrsByPort := make(map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr)
	for pName, l4Addr := range svc.Ports {
		addrs := make([]*loadbalancer.L3n4Addr, 0, len(svc.FrontendIPs))
		for _, feIP := range svc.FrontendIPs {
			if isValidServiceFrontendIP(feIP) {
				addrs = append(addrs, loadbalancer.NewL3n4Addr(l4Addr.Protocol, cmtypes.MustAddrClusterFromIP(feIP), l4Addr.Port, loadbalancer.ScopeExternal))
			}
		}

		addrsByPort[pName] = addrs
	}

	return addrsByPort, len(svc.FrontendIPs)
}

// isValidServiceFrontendIP returns true if the provided service frontend IP address type
// is supported in cilium configuration.
func isValidServiceFrontendIP(netIP net.IP) bool {
	if (option.Config.EnableIPv4 && ip.IsIPv4(netIP)) || (option.Config.EnableIPv6 && ip.IsIPv6(netIP)) {
		return true
	}

	return false
}
