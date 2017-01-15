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

	"github.com/cilium/cilium/common/types"

	"k8s.io/client-go/1.5/pkg/api/v1"
	"k8s.io/client-go/1.5/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/1.5/pkg/fields"
	"k8s.io/client-go/1.5/pkg/util/wait"
	"k8s.io/client-go/1.5/tools/cache"
)

// EnableK8sWatcher watches for policy, services and endpoint changes on the kurbenetes
// api server defined in the receiver's daemon k8sClient. Re-syncs all state from the
// kubernetes api server at the given reSyncPeriod duration.
func (d *Daemon) EnableK8sWatcher(reSyncPeriod time.Duration) error {
	if !d.conf.IsK8sEnabled() {
		return nil
	}

	_, policyController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Extensions().GetRESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&v1beta1.NetworkPolicy{},
		reSyncPeriod,
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
		reSyncPeriod,
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
		reSyncPeriod,
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
	parentsPath, pn, err := types.K8sNP2CP(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}
	if err := d.PolicyAdd(parentsPath, pn); err != nil {
		log.Errorf("Error while adding kubernetes network policy %+v: %s", pn, err)
		return
	}
	log.Infof("Kubernetes network policy '%s' successfully add", k8sNP.Name)
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
	parentsPath, pn, err := types.K8sNP2CP(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}
	if pn != nil {
		parentsPath += "." + pn.Name
	}

	gotErrors := false
	for _, rule := range pn.Rules {
		coverageSHA256Sum, err := rule.CoverageSHA256Sum()
		if err != nil {
			log.Errorf("Error while deleting kubernetes network policy %+v: %s", pn, err)
			gotErrors = true
			continue
		}
		if err := d.PolicyDelete(parentsPath, coverageSHA256Sum); err != nil {
			log.Errorf("Error while deleting kubernetes network policy %+v rule %+v: %s with ", pn, rule, err)
			gotErrors = true
		}
	}
	if !gotErrors {
		log.Infof("Kubernetes network policy '%s' successfully removed", k8sNP.Name)
	}
}

func (d *Daemon) serviceAddFn(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	if svc.Spec.Type != v1.ServiceTypeClusterIP {
		log.Infof("Ignoring service %s/%s since its type is %s", svc.Namespace, svc.Name, svc.Spec.Type)
		return
	}

	svcns := types.K8sServiceNamespace{
		Service:   svc.Name,
		Namespace: svc.Namespace,
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	newSI := types.NewK8sServiceInfo(clusterIP)

	for _, port := range svc.Spec.Ports {
		p, err := types.NewFEPort(types.L4Type(port.Protocol), uint16(port.Port))
		if err != nil {
			log.Errorf("Unable to add service port %v: %s", port, err)
			continue
		}
		if _, ok := newSI.Ports[types.FEPortName(port.Name)]; !ok {
			newSI.Ports[types.FEPortName(port.Name)] = p
		}
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	d.loadBalancer.K8sServices[svcns] = newSI

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

	svcns := &types.K8sServiceNamespace{
		Service:   svc.Name,
		Namespace: svc.Namespace,
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()
	d.syncLB(nil, nil, svcns)
}

func (d *Daemon) endpointAddFn(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return
	}

	svcns := types.K8sServiceNamespace{
		Service:   ep.Name,
		Namespace: ep.Namespace,
	}

	newSvcEP := types.NewK8sServiceEndpoint()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			newSvcEP.BEIPs[addr.IP] = true
		}
		for _, port := range sub.Ports {
			lbPort, err := types.NewL4Addr(types.L4Type(port.Protocol), uint16(port.Port))
			if err != nil {
				log.Errorf("Error while creating a new LB Port: %s", err)
				continue
			}
			newSvcEP.Ports[types.FEPortName(port.Name)] = lbPort
		}
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	d.loadBalancer.K8sEndpoints[svcns] = newSvcEP

	d.syncLB(&svcns, nil, nil)
}

func (d *Daemon) endpointModFn(_ interface{}, newObj interface{}) {
	_, ok := newObj.(*v1.Endpoints)
	if !ok {
		return
	}

	d.endpointAddFn(newObj)
}

func (d *Daemon) endpointDelFn(obj interface{}) {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		return
	}

	svcns := &types.K8sServiceNamespace{
		Service:   ep.Name,
		Namespace: ep.Namespace,
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	d.syncLB(nil, nil, svcns)
}

func areIPsConsistent(ipv4Enabled, isSvcIPv4 bool, svc types.K8sServiceNamespace, se *types.K8sServiceEndpoint) bool {

	if isSvcIPv4 {
		if !ipv4Enabled {
			log.Warningf("Received an IPv4 kubernetes service but IPv4 is"+
				"disabled in the cilium daemon. Ignoring service %+v", svc)
			return false
		}

		for epIP := range se.BEIPs {
			//is IPv6?
			if net.ParseIP(epIP).To4() == nil {
				log.Errorf("Not all endpoints IPs are IPv4. Ignoring IPv4 service %+v", svc)
				return false
			}
		}
	} else {
		for epIP := range se.BEIPs {
			//is IPv4?
			if net.ParseIP(epIP).To4() != nil {
				log.Errorf("Not all endpoints IPs are IPv6. Ignoring IPv6 service %+v", svc)
				return false
			}
		}
	}
	return true
}

func getUniqPorts(svcPorts map[types.FEPortName]*types.FEPort) map[uint16]bool {
	// We are not discriminating the different L4 protocols on the same L4
	// port so we create the number of unique sets of service IP + service
	// port.
	uniqPorts := map[uint16]bool{}
	for _, svcPort := range svcPorts {
		uniqPorts[svcPort.Port] = true
	}
	return uniqPorts
}

func (d *Daemon) delK8sSVCs(svc types.K8sServiceNamespace, svcInfo *types.K8sServiceInfo, se *types.K8sServiceEndpoint) {
	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if !areIPsConsistent(d.conf.IPv4Enabled, isSvcIPv4, svc, se) {
		return
	}

	repPorts := getUniqPorts(svcInfo.Ports)

	for _, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		if svcPort.ID != 0 {
			if err := d.DeleteL3n4AddrIDByUUID(uint32(svcPort.ID)); err != nil {
				log.Warningf("Error while cleaning service ID: %s", err)
			}
		}

		fe, err := types.NewL3n4Addr(svcPort.Protocol, svcInfo.FEIP, svcPort.Port)
		if err != nil {
			log.Errorf("Error while creating a New L3n4AddrID: %s. Ignoring service %v...", err, svcInfo)
			continue
		}

		if err := d.SVCDelete(*fe); err != nil {
			log.Warningf("Error deleting service %+v, %s", fe, err)
		} else {
			log.Debugf("# cilium lb delete-service %s %d 0", svcInfo.FEIP, svcPort.Port)
		}

		if err := d.RevNATDelete(svcPort.ID); err != nil {
			log.Warningf("Error deleting reverse NAT %+v, %s", svcPort.ID, err)
		} else {
			log.Debugf("# cilium lb delete-rev-nat %d", svcPort.ID)
		}
	}
}

func (d *Daemon) addK8sSVCs(svc types.K8sServiceNamespace, svcInfo *types.K8sServiceInfo, se *types.K8sServiceEndpoint) {
	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if !areIPsConsistent(d.conf.IPv4Enabled, isSvcIPv4, svc, se) {
		return
	}

	uniqPorts := getUniqPorts(svcInfo.Ports)

	for fePortName, fePort := range svcInfo.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}

		k8sBEPort := se.Ports[fePortName]
		uniqPorts[fePort.Port] = false

		if fePort.ID == 0 {
			feAddr, err := types.NewL3n4Addr(fePort.Protocol, svcInfo.FEIP, fePort.Port)
			if err != nil {
				log.Errorf("Error while creating a new L3n4Addr: %s. Ignoring service...", err)
				continue
			}
			feAddrID, err := d.PutL3n4Addr(*feAddr, 0)
			if err != nil {
				log.Errorf("Error while getting a new service ID: %s. Ignoring service %v...", err, feAddr)
				continue
			}
			log.Debugf("Got feAddr ID %d for service %+v", feAddrID.ID, svc)
			fePort.ID = feAddrID.ID
		}

		besValues := []types.LBBackendServer{}

		if k8sBEPort != nil {
			for epIP := range se.BEIPs {
				bePort := types.LBBackendServer{
					Weight: 0,
					Addr: types.L3n4Addr{
						IP:     net.ParseIP(epIP),
						L4Addr: *k8sBEPort,
					},
				}
				besValues = append(besValues, bePort)
			}
		}

		fe, err := types.NewL3n4AddrID(fePort.Protocol, svcInfo.FEIP, fePort.Port, fePort.ID)
		if err != nil {
			log.Errorf("Error while creating a New L3n4AddrID: %s. Ignoring service %v...", err, svcInfo)
			continue
		}
		if err := d.svcAdd(*fe, besValues, true); err != nil {
			log.Errorf("Error while inserting service in LB map: %s", err)
		}
	}
}

func (d *Daemon) syncLB(newSN, modSN, delSN *types.K8sServiceNamespace) {
	deleteSN := func(delSN types.K8sServiceNamespace) {
		svc, ok := d.loadBalancer.K8sServices[delSN]
		if !ok {
			delete(d.loadBalancer.K8sEndpoints, delSN)
			return
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[delSN]
		if !ok {
			delete(d.loadBalancer.K8sServices, delSN)
			return
		}

		d.delK8sSVCs(delSN, svc, endpoint)

		delete(d.loadBalancer.K8sServices, delSN)
		delete(d.loadBalancer.K8sEndpoints, delSN)
	}

	addSN := func(addSN types.K8sServiceNamespace) {
		svcInfo, ok := d.loadBalancer.K8sServices[addSN]
		if !ok {
			return
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[addSN]
		if !ok {
			return
		}

		d.addK8sSVCs(addSN, svcInfo, endpoint)
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
