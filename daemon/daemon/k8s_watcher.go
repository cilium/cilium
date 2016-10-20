//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package daemon

import (
	"net"
	"time"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/types"

	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/fields"
	"k8s.io/client-go/1.5/pkg/util/wait"
	"k8s.io/client-go/1.5/tools/cache"
)

func (d *Daemon) EnableK8sWatcher(resyncPeriod time.Duration) error {
	if !d.conf.IsK8sEnabled() {
		return nil
	}

	_, policyController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Extensions().GetRESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&v1beta1.NetworkPolicy{},
		resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.policyAddFn,
			UpdateFunc: d.policyModFn,
			DeleteFunc: d.policyDelFn,
		},
	)
	go policyController.Run(wait.NeverStop)

	_, svcController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Core().GetRESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.serviceAddFn,
			UpdateFunc: d.serviceModFn,
			DeleteFunc: d.serviceDelFn,
		},
	)
	go svcController.Run(wait.NeverStop)

	_, endpointController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Core().GetRESTClient(),
			"endpoints", v1.NamespaceAll, fields.Everything()),
		&v1.Endpoints{},
		resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.endpointAddFn,
			UpdateFunc: d.endpointModFn,
			DeleteFunc: d.endpointDelFn,
		},
	)
	go endpointController.Run(wait.NeverStop)

	return nil
}

func (d *Daemon) policyAddFn(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		return
	}
	nodePath, pn, err := types.K8sNP2CP(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}
	if err := d.PolicyAdd(nodePath, pn); err != nil {
		log.Errorf("Error while adding kubernetes network policy %+v: %s", pn, err)
		return
	}
	log.Infof("Kubernetes network policy successfully add %+v", obj)
}

func (d *Daemon) policyModFn(oldObj interface{}, newObj interface{}) {
	log.Debugf("Modified policy %+v->%+v", oldObj, newObj)
	d.policyAddFn(newObj)
}

func (d *Daemon) policyDelFn(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		return
	}
	nodePath, pn, err := types.K8sNP2CP(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}
	if err := d.PolicyDelete(nodePath); err != nil {
		log.Errorf("Error while deleting kubernetes network policy %+v: %s", pn, err)
		return
	}
	log.Infof("Kubernetes network policy successfully removed %+v", obj)
}

func (d *Daemon) serviceAddFn(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}
	log.Debugf("Service %+v", svc)

	d.loadBalancer.ServicesMU.Lock()
	defer d.loadBalancer.ServicesMU.Unlock()

	if svc.Spec.Type != v1.ServiceTypeClusterIP {
		log.Infof("Ignoring service %s/%s since its type is %s", svc.Namespace, svc.Name, svc.Spec.Type)
		return
	}

	svcns := types.ServiceNamespace{
		Service:   svc.Name,
		Namespace: svc.Namespace,
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	newSI := types.NewServiceInfo(clusterIP)

	for _, port := range svc.Spec.Ports {
		p, err := types.NewLBSvcPort(types.L4Type(port.Protocol), uint16(port.Port))
		if err != nil {
			log.Errorf("Unable to add service port %v: %s", port, err)
		}
		if _, ok := newSI.Ports[types.LBPortName(port.Name)]; !ok {
			newSI.Ports[types.LBPortName(port.Name)] = p
		}
	}

	log.Debugf("Got new service %+v", newSI)
	d.loadBalancer.Services[svcns] = newSI

	d.syncLB(&svcns, nil, nil)
}

func (d *Daemon) serviceModFn(_ interface{}, newObj interface{}) {
	newSvc, ok := newObj.(*v1.Service)
	if !ok {
		return
	}
	log.Debugf("Service %+v", newSvc)

	d.serviceAddFn(newObj)
}

func (d *Daemon) serviceDelFn(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}
	log.Debugf("Service %+v", svc)

	svcns := &types.ServiceNamespace{
		Service:   svc.Name,
		Namespace: svc.Namespace,
	}

	d.syncLB(nil, nil, svcns)
}

func (d *Daemon) endpointAddFn(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return
	}
	log.Debugf("Endpoint %+v", ep)

	d.loadBalancer.ServicesMU.Lock()
	defer d.loadBalancer.ServicesMU.Unlock()

	svcns := types.ServiceNamespace{
		Service:   ep.Name,
		Namespace: ep.Namespace,
	}

	newSvcEP := types.NewServiceEndpoint()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			newSvcEP.IPs[addr.IP] = true
		}
		for _, port := range sub.Ports {
			lbPort, err := types.NewLBPort(types.L4Type(port.Protocol), uint16(port.Port))
			if err != nil {
				log.Errorf("Error while creating a new LB Port: %s", err)
				continue
			}
			newSvcEP.Ports[types.LBPortName(port.Name)] = lbPort
		}
	}
	d.loadBalancer.Endpoints[svcns] = newSvcEP

	d.syncLB(&svcns, nil, nil)
}

func (d *Daemon) endpointModFn(_ interface{}, newObj interface{}) {
	newEp, ok := newObj.(*v1.Endpoints)
	if !ok {
		return
	}
	log.Debugf("Endpoint %+v", newEp)

	d.endpointAddFn(newObj)
}

func (d *Daemon) endpointDelFn(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return
	}
	log.Debugf("Endpoint %+v", ep)

	svcns := &types.ServiceNamespace{
		Service:   ep.Name,
		Namespace: ep.Namespace,
	}

	d.syncLB(nil, nil, svcns)
}

func (d *Daemon) syncLB(newSN, modSN, delSN *types.ServiceNamespace) {
	log.Debugf("newns %+v, modns %+v, delns %+v", newSN, modSN, delSN)

	deleteSN := func(delSN types.ServiceNamespace) {
		svc, ok := d.loadBalancer.Services[delSN]
		if !ok {
			delete(d.loadBalancer.Endpoints, delSN)
			return
		}
		se, ok := d.loadBalancer.Endpoints[delSN]
		if !ok {
			delete(d.loadBalancer.Services, delSN)
			return
		}
		d.delLBServices(delSN, svc, se)

		delete(d.loadBalancer.Services, delSN)
		delete(d.loadBalancer.Endpoints, delSN)
	}

	addSN := func(addSN types.ServiceNamespace) {
		svcInfo, ok := d.loadBalancer.Services[addSN]
		if !ok {
			return
		}

		se, ok := d.loadBalancer.Endpoints[addSN]
		if !ok {
			return
		}

		d.addLBServices(addSN, svcInfo, se)
	}

	if delSN != nil {
		// Clean old services
		deleteSN(*delSN)
	}
	if modSN != nil {
		// Re-add modified services
		addSN(*modSN)
	}
	if newSN != nil {
		// Add new services
		addSN(*newSN)
	}
}

func areIPsConsistent(ipv4Enabled, isSvcIPv4 bool, svc types.ServiceNamespace, se *types.ServiceEndpoint) bool {

	if isSvcIPv4 {
		if !ipv4Enabled {
			log.Warningf("Received an IPv4 kubernetes service but IPv4 is"+
				"disabled in the cilium daemon. Ignoring service %+v", svc)
			return false
		}

		isEPsIPv6 := false
		for epIP := range se.IPs {
			//is IPv6?
			if net.ParseIP(epIP).To4() == nil {
				isEPsIPv6 = true
				break
			}
		}
		if isEPsIPv6 {
			log.Errorf("Not all endpoints IPs are IPv4. Ignoring IPv4 service %+v", svc)
			return false
		}
	} else {
		isEPsIPv4 := false
		for epIP := range se.IPs {
			//is IPv4?
			if net.ParseIP(epIP).To4() != nil {
				isEPsIPv4 = true
				break
			}
		}
		if isEPsIPv4 {
			log.Errorf("Not all endpoints IPs are IPv6. Ignoring IPv6 service %+v", svc)
			return false
		}
	}
	return true
}

func getUniqPorts(svcPorts map[types.LBPortName]*types.LBSvcPort) map[uint16]bool {
	// We are not discriminating the different L4 protocols on the same L4
	// port so we create the number of unique sets of service IP + service
	// port.
	uniqPorts := map[uint16]bool{}
	for _, svcPort := range svcPorts {
		uniqPorts[svcPort.Port] = true
	}
	return uniqPorts
}

func (d *Daemon) delLBServices(svc types.ServiceNamespace, svcInfo *types.ServiceInfo, se *types.ServiceEndpoint) {
	isSvcIPv4 := svcInfo.IP.To4() != nil
	if !areIPsConsistent(d.conf.IPv4Enabled, isSvcIPv4, svc, se) {
		return
	}

	repPorts := getUniqPorts(svcInfo.Ports)

	for _, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		if svcPort.ServiceID != 0 {
			if err := d.DeleteServiceL4IDByUUID(uint32(svcPort.ServiceID)); err != nil {
				log.Warningf("Error while cleaning service ID: %s", err)
			}
		}

		if isSvcIPv4 {
			d.deleteSvc4(se.IPs, svcInfo, svcPort)
		} else {
			d.deleteSvc6(se.IPs, svcInfo, svcPort)
		}
	}
}

func (d *Daemon) deleteSvc4(epIPs map[string]bool, svcInfo *types.ServiceInfo, svcPort *types.LBSvcPort) {

	serverIndex := uint16(0)

	svc4k := lbmap.NewService4Key(svcInfo.IP, svcPort.Port, serverIndex)
	if err := lbmap.Service4Map.Delete(svc4k); err != nil {
		log.Warningf("Error deleting service %+v, %s", svc4k, err)
	} else {
		log.Debugf("# cilium lb -4 delete-service %s %d %d",
			svcInfo.IP, svcPort.Port, serverIndex)
	}

	for range epIPs {
		serverIndex++
		svc4k.Slave = serverIndex

		if err := lbmap.Service4Map.Delete(svc4k); err != nil {
			log.Warningf("Error deleting service %+v, %s", svc4k, err)
		} else {
			log.Debugf("# cilium lb -4 delete-service %s %d %d",
				svcInfo.IP, svcPort.Port, serverIndex)
		}
	}

	revNATk := lbmap.NewRevNat4Key(uint16(svcPort.ServiceID))
	if err := lbmap.RevNat4Map.Delete(revNATk); err != nil {
		log.Warningf("Error updating reverser NAT %+v, %s", revNATk, err)
	} else {
		log.Debugf("# cilium lb -4 delete-rev-nat %d", svcPort.ServiceID)
	}
}

func (d *Daemon) deleteSvc6(epIPs map[string]bool, svcInfo *types.ServiceInfo, svcPort *types.LBSvcPort) {

	serverIndex := uint16(0)

	svc6k := lbmap.NewService6Key(svcInfo.IP, svcPort.Port, serverIndex)
	if err := lbmap.Service6Map.Delete(svc6k); err != nil {
		log.Warningf("Error deleting service %+v, %s", svc6k, err)
	} else {
		log.Debugf("# cilium lb delete-service %s %d %d",
			svcInfo.IP, svcPort.Port, serverIndex)
	}

	for range epIPs {
		serverIndex++
		svc6k.Slave = serverIndex

		if err := lbmap.Service6Map.Delete(svc6k); err != nil {
			log.Warningf("Error deleting service %+v, %s", svc6k, err)
		} else {
			log.Debugf("# cilium lb delete-service %s %d %d",
				svcInfo.IP, svcPort.Port, serverIndex)
		}
	}

	revNATk := lbmap.NewRevNat6Key(uint16(svcPort.ServiceID))
	if err := lbmap.RevNat6Map.Delete(revNATk); err != nil {
		log.Warningf("Error updating reverser NAT %+v, %s", revNATk, err)
	} else {
		log.Debugf("# cilium lb delete-rev-nat %d", svcPort.ServiceID)
	}
}

func (d *Daemon) addLBServices(svc types.ServiceNamespace, svcInfo *types.ServiceInfo, se *types.ServiceEndpoint) {
	isSvcIPv4 := svcInfo.IP.To4() != nil
	if !areIPsConsistent(d.conf.IPv4Enabled, isSvcIPv4, svc, se) {
		return
	}

	uniqPorts := getUniqPorts(svcInfo.Ports)

	for svcPortName, svcPort := range svcInfo.Ports {
		if !uniqPorts[svcPort.Port] {
			continue
		}
		epPort, ok := se.Ports[svcPortName]
		if !ok {
			continue
		}
		uniqPorts[svcPort.Port] = false

		if svcPort.ServiceID == 0 {
			svcl4 := types.ServiceL4{
				IP:   svcInfo.IP,
				Port: svcPort.Port,
			}
			svcl4ID, err := d.PutServiceL4(svcl4)
			if err != nil {
				log.Errorf("Error while getting a new service ID: %s. Ignoring service %v...", err, svcl4)
				continue
			}
			log.Debugf("Got service ID %d for service %+v", svcl4ID.ServiceID, svc)
			svcPort.ServiceID = svcl4ID.ServiceID
		}

		if isSvcIPv4 {
			d.insertSvc4(se.IPs, svcInfo, svcPort, epPort)
		} else {
			d.insertSvc6(se.IPs, svcInfo, svcPort, epPort)
		}
	}
}

func (d *Daemon) insertSvc4(epIPs map[string]bool, svcInfo *types.ServiceInfo,
	svcPort *types.LBSvcPort, epPort *types.LBPort) {

	isServerPresent := false
	serverIndex := uint16(0)
	nSvcs := uint16(len(epIPs))

	svc4k := lbmap.NewService4Key(svcInfo.IP, svcPort.Port, serverIndex)
	svc4v := lbmap.NewService4Value(nSvcs, svcInfo.IP, svcPort.Port, uint16(svcPort.ServiceID))
	if err := lbmap.UpdateService(svc4k, svc4v); err != nil {
		log.Errorf("Error updating service %+v, %s", svc4k, err)
	} else {
		log.Debugf("# cilium lb -4 update-service %s %d %d %d %d %s %d",
			svcInfo.IP, svcPort.Port, serverIndex, nSvcs, svcPort.ServiceID,
			"127.0.0.1", 0)
	}

	for epIP := range epIPs {
		serverIndex++
		svc4k.Slave = serverIndex
		epIPParsed := net.ParseIP(epIP)

		svc4v := lbmap.NewService4Value(nSvcs, epIPParsed, epPort.Port, uint16(svcPort.ServiceID))
		if err := lbmap.UpdateService(svc4k, svc4v); err != nil {
			log.Errorf("Error updating service %+v, %s", svc4k, err)
		} else {
			log.Debugf("# cilium lb -4 update-service %s %d %d %d %d %s %d",
				svcInfo.IP, svcPort.Port, serverIndex, nSvcs, svcPort.ServiceID,
				epIP, epPort.Port)
		}

		if !isServerPresent {
			d.conf.OptsMU.RLock()
			d.ipamConf.AllocatorMutex.RLock()
			isServerPresent = d.conf.NodeAddress.IPv4Address.IP().Equal(epIPParsed) ||
				d.ipamConf.IPv4Allocator.Has(epIPParsed)
			d.ipamConf.AllocatorMutex.RUnlock()
			d.conf.OptsMU.RUnlock()
		}
	}
	if isServerPresent {
		revNATk := lbmap.NewRevNat4Key(uint16(svcPort.ServiceID))
		revNATv := lbmap.NewRevNat4Value(svcInfo.IP, svcPort.Port)
		if err := lbmap.UpdateRevNat(revNATk, revNATv); err != nil {
			log.Errorf("Error updating reverser NAT %+v, %s", revNATk, err)
		} else {
			log.Debugf("# cilium lb -4 update-rev-nat %d %s %d",
				svcPort.ServiceID, svcInfo.IP, svcPort.Port)
		}
	}
}

func (d *Daemon) insertSvc6(epIPs map[string]bool, svcInfo *types.ServiceInfo,
	svcPort *types.LBSvcPort, epPort *types.LBPort) {

	isServerPresent := false
	serverIndex := uint16(0)
	nSvcs := uint16(len(epIPs))

	svc6k := lbmap.NewService6Key(svcInfo.IP, svcPort.Port, serverIndex)
	svc6v := lbmap.NewService6Value(nSvcs, svcInfo.IP, svcPort.Port, uint16(svcPort.ServiceID))
	if err := lbmap.UpdateService(svc6k, svc6v); err != nil {
		log.Errorf("Error updating service %+v, %s", svc6k, err)
	} else {
		log.Debugf("# cilium lb update-service %s %d %d %d %d %s %d",
			svcInfo.IP, svcPort.Port, serverIndex, nSvcs, svcPort.ServiceID,
			"::", 0)
	}

	for epIP := range epIPs {
		serverIndex++
		svc6k.Slave = serverIndex
		epIPParsed := net.ParseIP(epIP)

		svc6v := lbmap.NewService6Value(nSvcs, epIPParsed, epPort.Port, uint16(svcPort.ServiceID))
		if err := lbmap.UpdateService(svc6k, svc6v); err != nil {
			log.Errorf("Error updating service %+v, %s", svc6k, err)
		} else {
			log.Debugf("# cilium lb update-service %s %d %d %d %d %s %d",
				svcInfo.IP, svcPort.Port, serverIndex, nSvcs, svcPort.ServiceID,
				epIP, epPort.Port)
		}

		if !isServerPresent {
			d.conf.OptsMU.RLock()
			d.ipamConf.AllocatorMutex.RLock()
			isServerPresent = d.conf.NodeAddress.IPv6Address.HostIP().Equal(epIPParsed) ||
				d.ipamConf.IPv6Allocator.Has(epIPParsed)
			d.ipamConf.AllocatorMutex.RUnlock()
			d.conf.OptsMU.RUnlock()
		}
	}
	if isServerPresent {
		revNATk := lbmap.NewRevNat6Key(uint16(svcPort.ServiceID))
		revNATv := lbmap.NewRevNat6Value(svcInfo.IP, svcPort.Port)
		if err := lbmap.UpdateRevNat(revNATk, revNATv); err != nil {
			log.Errorf("Error updating reverser NAT %+v, %s", revNATk, err)
		} else {
			log.Debugf("# cilium lb update-rev-nat %d %s %d",
				svcPort.ServiceID, svcInfo.IP, svcPort.Port)
		}
	}
}
