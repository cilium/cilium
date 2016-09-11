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
					break
				}
				log.Debugf("Received kubernetes network policy %+v\n", npwe)
				go d.processNPE(npwe)
			}
		}
	}()

	go func() {
		time.Sleep(30 * time.Second)
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

	newServices := map[types.ServiceNamespace]bool{}
	for _, svc := range allServices {
		if svc.Spec.Type != k8sAPI.ServiceTypeClusterIP {
			log.Infof("Ignoring service %s/%s since its type is %s", svc.Namespace, svc.Name, svc.Spec.Type)
			continue
		}

		svcns := types.ServiceNamespace{
			Service:   svc.Name,
			Namespace: svc.Namespace,
		}
		newServices[svcns] = true

		si, ok := d.loadBalancer.Services[svcns]
		clusterIP := net.ParseIP(svc.Spec.ClusterIP)
		if !ok {
			si = types.NewServiceInfo(clusterIP)
			d.loadBalancer.Services[svcns] = si
		} else {
			si.IP = clusterIP
		}

		for _, port := range svc.Spec.Ports {
			p, err := types.NewLBSvcPort(types.L4Type(port.Protocol), uint16(port.Port))
			if err != nil {
				log.Errorf("Unable to add service port %v: %s", port, err)
			}
			if _, ok := si.Ports[types.LBPortName(port.Name)]; !ok {
				si.Ports[types.LBPortName(port.Name)] = p
			}
		}
		log.Debugf("Got service %+v", si)
	}

	// Cleaning old services
	for svc := range d.loadBalancer.Services {
		if !newServices[svc] {
			delete(d.loadBalancer.Services, svc)
		}
	}

	d.syncLB()
}

func (d *Daemon) OnEndpointsUpdate(endpoints []k8sAPI.Endpoints) {
	log.Debugf("All Endpoints %+v", endpoints)
	d.loadBalancer.ServicesMU.Lock()
	defer d.loadBalancer.ServicesMU.Unlock()

	newEndpoints := map[types.ServiceNamespace]bool{}
	for _, ep := range endpoints {
		svcns := types.ServiceNamespace{
			Service:   ep.Name,
			Namespace: ep.Namespace,
		}
		newEndpoints[svcns] = true

		svcEp, ok := d.loadBalancer.Endpoints[svcns]
		if !ok {
			svcEp = types.NewServiceEndpoint()
			d.loadBalancer.Endpoints[svcns] = svcEp
		}

		newIPs := map[string]bool{}
		newLBPorts := map[types.LBPortName]bool{}
		for _, sub := range ep.Subsets {
			for _, addr := range sub.Addresses {
				svcEp.IPs[addr.IP] = true
				newIPs[addr.IP] = true
			}
			for _, port := range sub.Ports {
				lbPort, err := types.NewLBPort(types.L4Type(port.Protocol), uint16(port.Port))
				if err != nil {
					log.Errorf("Error while creating a new LB Port: %s", err)
					continue
				}
				svcEp.Ports[types.LBPortName(port.Name)] = lbPort
				newLBPorts[types.LBPortName(port.Name)] = true
			}
		}

		// Cleaning old IPs
		for ip := range svcEp.IPs {
			if !newIPs[ip] {
				delete(svcEp.IPs, ip)
			}
		}

		// Cleaning old service ports
		for portName := range svcEp.Ports {
			if !newLBPorts[portName] {
				delete(svcEp.Ports, portName)
			}
		}

	}

	// Cleaning old endpoints
	for ep := range d.loadBalancer.Endpoints {
		if !newEndpoints[ep] {
			delete(d.loadBalancer.Endpoints, ep)
		}
	}

	d.syncLB()
}

func (d *Daemon) syncLB() {
	for svc, svcInfo := range d.loadBalancer.Services {
		se, ok := d.loadBalancer.Endpoints[svc]
		if !ok {
			continue
		}

		for svcPortName, svcPort := range svcInfo.Ports {
			epPort, ok := se.Ports[svcPortName]
			if !ok {
				continue
			}
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
				svcPort.ServiceID = svcl4ID.ServiceID
			}
			isServerPresent := false

			serverIndex := 0

			if len(se.IPs) != 0 {
				log.Debugf("# cilium lb update-service %s %d %d %d %d %s %d",
					svcInfo.IP, svcPort.Port, serverIndex, len(svcInfo.Ports), svcPort.ServiceID,
					"::", 0)
			}
			for epIP := range se.IPs {
				serverIndex++
				log.Debugf("# cilium lb update-service %s %d %d %d %d %s %d",
					svcInfo.IP, svcPort.Port, serverIndex, len(svcInfo.Ports), svcPort.ServiceID,
					epIP, epPort.Port)

				if !isServerPresent {
					d.ipamConf.AllocatorMutex.RLock()
					if d.ipamConf.IPv6Allocator.Has(net.ParseIP(epIP)) ||
						d.ipamConf.IPv4Allocator.Has(net.ParseIP(epIP)) {
						isServerPresent = true
					}
					d.ipamConf.AllocatorMutex.RUnlock()
				}
			}
			if isServerPresent {
				log.Debugf("# cilium lb update-state %d %s %d",
					svcPort.ServiceID, svcInfo.IP, svcPort.Port)
			}
		}
	}
}
