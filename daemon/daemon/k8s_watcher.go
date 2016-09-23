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
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/cilium/cilium/bpf/lbmap"
	"github.com/cilium/cilium/common/types"

	k8sAPI "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	k8sProxyConfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/watch"
)

type networkPolicyWatchEvent struct {
	Type   watch.EventType       `json:"type"`
	Object v1beta1.NetworkPolicy `json:"object"`
}

func (d *Daemon) EnableK8sWatcher(maxSeconds time.Duration) error {
	if !d.conf.IsK8sEnabled() {
		return nil
	}

	curSeconds := 2 * time.Second
	uNPs := d.k8sClient.Get().RequestURI("apis/extensions/v1beta1").
		Resource("networkpolicies").URL().String()
	uWatcher := d.k8sClient.Get().RequestURI("apis/extensions/v1beta1").
		Namespace("default").Resource("networkpolicies").Param("watch", "true").URL().String()
	go func() {
		reportError := true
		makeRequest := func(url string) *http.Response {
			for {
				resp, err := http.Get(url)
				if err != nil {
					if reportError {
						log.Warningf("Unable to install k8s watcher for URL %s: %s", url, err)
						reportError = false
					}
				} else if resp.StatusCode == http.StatusOK {
					// Once connected, report new errors again
					reportError = true
					return resp
				}
				time.Sleep(curSeconds)
				if curSeconds < maxSeconds {
					curSeconds = 2 * curSeconds
				}
			}
		}
		for {
			resp := makeRequest(uNPs)
			curSeconds = time.Second
			log.Info("Receiving all policies stored in kubernetes")
			npList := v1beta1.NetworkPolicyList{}
			err := json.NewDecoder(resp.Body).Decode(&npList)
			if err != nil {
				log.Errorf("Error while receiving data %s", err)
				resp.Body.Close()
				continue
			}
			log.Debugf("Received kubernetes network policies %+v\n", npList)
			for _, np := range npList.Items {
				go d.processNPE(networkPolicyWatchEvent{watch.Added, np})
			}
			resp.Body.Close()

			resp = makeRequest(uWatcher)
			log.Info("Listening for kubernetes network policies events")
			for {
				npwe := networkPolicyWatchEvent{}
				err := json.NewDecoder(resp.Body).Decode(&npwe)
				if err != nil {
					log.Errorf("Error while receiving data %s", err)
					resp.Body.Close()
					time.Sleep(curSeconds)
					break
				}
				log.Debugf("Received kubernetes network policy %+v\n", npwe)
				go d.processNPE(npwe)
			}
		}
	}()

	go func() {
		serviceConfig := k8sProxyConfig.NewServiceConfig()
		serviceConfig.RegisterHandler(d)

		endpointsConfig := k8sProxyConfig.NewEndpointsConfig()
		endpointsConfig.RegisterHandler(d)

		k8sProxyConfig.NewSourceAPI(
			d.k8sClient,
			15*time.Minute,
			serviceConfig.Channel("api"),
			endpointsConfig.Channel("api"),
		)
	}()

	return nil
}

func (d *Daemon) processNPE(npwe networkPolicyWatchEvent) {
	switch npwe.Type {
	case watch.Added, watch.Modified:
		nodePath, pn, err := types.K8sNP2CP(npwe.Object)
		if err != nil {
			log.Errorf("Error while parsing kubernetes network policy %+v: %s", npwe.Object, err)
			return
		}
		if err := d.PolicyAdd(nodePath, pn); err != nil {
			log.Errorf("Error while adding kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Infof("Kubernetes network policy successfully add %+v", npwe.Object)
	case watch.Deleted:
		nodePath, pn, err := types.K8sNP2CP(npwe.Object)
		if err != nil {
			log.Errorf("Error while parsing kubernetes network policy %+v: %s", npwe.Object, err)
			return
		}
		if err := d.PolicyDelete(nodePath); err != nil {
			log.Errorf("Error while deleting kubernetes network policy %+v: %s", pn, err)
			return
		}
		log.Infof("Kubernetes network policy successfully removed %+v", npwe.Object)
	}
}

func (d *Daemon) OnServiceUpdate(allServices []k8sAPI.Service) {
	log.Debugf("All Services %+v", allServices)
	d.loadBalancer.ServicesMU.Lock()
	defer d.loadBalancer.ServicesMU.Unlock()

	allNewServices := map[types.ServiceNamespace]bool{}
	newServices := map[types.ServiceNamespace]bool{}
	modServices := map[types.ServiceNamespace]bool{}
	for _, svc := range allServices {
		if svc.Spec.Type != k8sAPI.ServiceTypeClusterIP {
			log.Infof("Ignoring service %s/%s since its type is %s", svc.Namespace, svc.Name, svc.Spec.Type)
			continue
		}

		svcns := types.ServiceNamespace{
			Service:   svc.Name,
			Namespace: svc.Namespace,
		}
		allNewServices[svcns] = true

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

		if si, ok := d.loadBalancer.Services[svcns]; !ok {
			log.Debugf("Got new service %+v", newSI)
			newServices[svcns] = true
			d.loadBalancer.Services[svcns] = newSI
			// Note this equals doesn't check for different service ID
		} else if !newSI.Equals(si) {
			log.Debugf("Got mod service %+v, %+v", newSI, si)
			modServices[svcns] = true
			d.loadBalancer.Services[svcns] = newSI
		} else {
			log.Debugf("Service equals %+v, %+v", newSI, si)
		}
	}

	// Old services
	delServices := map[types.ServiceNamespace]bool{}
	for svc := range d.loadBalancer.Services {
		if !allNewServices[svc] {
			delServices[svc] = true
		}
	}

	d.syncLB(newServices, modServices, delServices)
}

func (d *Daemon) OnEndpointsUpdate(endpoints []k8sAPI.Endpoints) {
	log.Debugf("All Endpoints %+v", endpoints)
	d.loadBalancer.ServicesMU.Lock()
	defer d.loadBalancer.ServicesMU.Unlock()

	newAllSVCEPs := map[types.ServiceNamespace]bool{}
	newSVCEPs := map[types.ServiceNamespace]bool{}
	modSVCEPs := map[types.ServiceNamespace]bool{}
	for _, ep := range endpoints {
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

		if svcEP, ok := d.loadBalancer.Endpoints[svcns]; !ok {
			if len(newSvcEP.IPs) == 0 {
				continue
			}
			newAllSVCEPs[svcns] = true
			log.Debugf("Got new endpoint %+v", newSvcEP)
			newSVCEPs[svcns] = true
			d.loadBalancer.Endpoints[svcns] = newSvcEP
		} else {
			newAllSVCEPs[svcns] = true
			if !newSvcEP.Equals(svcEP) {
				log.Debugf("Got mod endpoint %+v", newSvcEP, svcEP)
				newSVCEPs[svcns] = true
				d.loadBalancer.Endpoints[svcns] = newSvcEP
			} else {
				log.Debugf("Endpoints equals %+v, %+v", newSvcEP, svcEP)
			}
		}
	}

	// Old endpoints
	delSVCEPs := map[types.ServiceNamespace]bool{}
	for ep := range d.loadBalancer.Endpoints {
		if !newAllSVCEPs[ep] {
			delSVCEPs[ep] = true
		}
	}

	d.syncLB(newSVCEPs, modSVCEPs, delSVCEPs)
}

func (d *Daemon) syncLB(newsn, modsn, delsn map[types.ServiceNamespace]bool) {
	if !d.conf.LBMode {
		return
	}

	log.Debugf("newsn %+v, modsn %+v, delsn %+v", newsn, modsn, delsn)

	// Clean old services
	for svcNS := range delsn {
		svc, ok := d.loadBalancer.Services[svcNS]
		if !ok {
			delete(d.loadBalancer.Endpoints, svcNS)
			continue
		}

		se, ok := d.loadBalancer.Endpoints[svcNS]
		if !ok {
			delete(d.loadBalancer.Services, svcNS)
			continue
		}
		d.delLBServices(svcNS, svc, se)

		delete(d.loadBalancer.Services, svcNS)
		delete(d.loadBalancer.Endpoints, svcNS)
	}

	for svcNS := range modsn {
		newsn[svcNS] = true
	}

	for svcNS := range newsn {
		svcInfo, ok := d.loadBalancer.Services[svcNS]
		if !ok {
			continue
		}

		se, ok := d.loadBalancer.Endpoints[svcNS]
		if !ok {
			continue
		}

		d.addLBServices(svcNS, svcInfo, se)
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
	if err := lbmap.Service4Map.Update(svc4k, svc4v); err != nil {
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
		if err := lbmap.Service4Map.Update(svc4k, svc4v); err != nil {
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
		if err := lbmap.RevNat4Map.Update(revNATk, revNATv); err != nil {
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
	if err := lbmap.Service6Map.Update(svc6k, svc6v); err != nil {
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
		if err := lbmap.Service6Map.Update(svc6k, svc6v); err != nil {
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
		if err := lbmap.RevNat6Map.Update(revNATk, revNATv); err != nil {
			log.Errorf("Error updating reverser NAT %+v, %s", revNATk, err)
		} else {
			log.Debugf("# cilium lb update-rev-nat %d %s %d",
				svcPort.ServiceID, svcInfo.IP, svcPort.Port)
		}
	}
}
