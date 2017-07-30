// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeaddress"

	log "github.com/Sirupsen/logrus"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	networkingv1 "k8s.io/client-go/pkg/apis/networking/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	k8sErrLogTimeout = time.Minute
)

var (
	k8sErrMsgMU sync.RWMutex
	// k8sErrMsg stores a timer for each k8s error message received
	k8sErrMsg            = map[string]*time.Timer{}
	stopPolicyController = make(chan struct{})
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8sErrorHandler,
	}
}

// k8sErrorHandler handles the error messages on a non verbose way by omitting
// same error messages for a timeout defined with k8sErrLogTimeout.
func k8sErrorHandler(e error) {
	if e == nil {
		return
	}
	errstr := e.Error()
	k8sErrMsgMU.Lock()
	// if the error message already exists in the map then in print it
	// otherwise we create a new timer for that specific message in the
	// k8sErrMsg map.
	if t, ok := k8sErrMsg[errstr]; !ok {
		// Omitting the 'connection refused' common messages
		if strings.Contains(errstr, "connection refused") {
			k8sErrMsg[errstr] = time.NewTimer(k8sErrLogTimeout)
			k8sErrMsgMU.Unlock()
		} else {
			if strings.Contains(errstr, "Failed to list *v1.NetworkPolicy: the server could not find the requested resource") {
				k8sErrMsgMU.Unlock()
				log.Warningf("Consider upgrading kubernetes to >=1.7 to enforce NetworkPolicy version 1")
				stopPolicyController <- struct{}{}
			} else if strings.Contains(errstr, "Failed to list *k8s.CiliumNetworkPolicy: the server could not find the requested resource") {
				k8sErrMsg[errstr] = time.NewTimer(k8sErrLogTimeout)
				k8sErrMsgMU.Unlock()
				log.Warningf("Detected conflicting TPR and CRD, please migrate all ThirdPartyResource to CustomResourceDefinition! More info: https://cilium.link/migrate-tpr")
				log.Warningf("Due conflicting TPR and CRD rules CiliumNetworkPolicy enforcement can't be guaranteed!")
			}
		}
	} else {
		k8sErrMsgMU.Unlock()
		select {
		case <-t.C:
			log.Error(e)
			t.Reset(k8sErrLogTimeout)
		default:
		}
		return
	}
	// Still log other error messages
	log.Error(e)
}

func createCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	cnpCRDName := "ciliumnetworkpolicies." + k8s.CustomResourceDefinitionGroup

	res := &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpCRDName,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   k8s.CustomResourceDefinitionGroup,
			Version: k8s.CustomResourceDefinitionVersion,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     "ciliumnetworkpolicies",
				Singular:   "ciliumnetworkpolicy",
				ShortNames: []string{"cnp", "ciliumnp"},
				Kind:       "CiliumNetworkPolicy",
			},
			Scope: apiextensionsv1beta1.NamespaceScoped,
		},
	}

	_, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	log.Infof("k8s: Waiting for CRD to be established in k8s api-server...")
	// wait for CRD being established
	err = wait.Poll(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		crd, err := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Get(cnpCRDName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range crd.Status.Conditions {
			switch cond.Type {
			case apiextensionsv1beta1.Established:
				if cond.Status == apiextensionsv1beta1.ConditionTrue {
					return true, err
				}
			case apiextensionsv1beta1.NamesAccepted:
				if cond.Status == apiextensionsv1beta1.ConditionFalse {
					log.Errorf("Name conflict: %v", cond.Reason)
					return false, err
				}
			}
		}
		return false, err
	})
	if err != nil {
		deleteErr := clientset.ApiextensionsV1beta1().CustomResourceDefinitions().Delete(cnpCRDName, nil)
		if deleteErr != nil {
			return fmt.Errorf("k8s: unable to delete CRD %s. Deleting CRD due: %s", deleteErr, err)
		}
		return err
	}

	return nil
}

func (d *Daemon) createThirdPartyResources() error {
	res := &v1beta1.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-network-policy." + k8s.CustomResourceDefinitionGroup,
		},
		Description: "Cilium network policy rule",
		Versions: []v1beta1.APIVersion{
			{Name: k8s.ThirdPartyResourceVersion},
		},
	}

	// TODO: Retry a couple of times
	_, err := d.k8sClient.ExtensionsV1beta1().ThirdPartyResources().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// EnableK8sWatcher watches for policy, services and endpoint changes on the Kubernetes
// api server defined in the receiver's daemon k8sClient. Re-syncs all state from the
// Kubernetes api server at the given reSyncPeriod duration.
func (d *Daemon) EnableK8sWatcher(reSyncPeriod time.Duration) error {
	if !d.conf.IsK8sEnabled() {
		return nil
	}

	restConfig, err := k8s.CreateConfig(d.conf.K8sEndpoint, d.conf.K8sCfgPath)
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration: %s", err)
	}

	apiextensionsclientset, err := apiextensionsclient.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration for k8s CRD: %s", err)
	}

	// CRD and TPR clients are based on the same rest config
	var crdClient *rest.RESTClient

	if err := createCustomResourceDefinitions(apiextensionsclientset); errors.IsNotFound(err) {
		// If CRD was not found it means we are running in k8s <1.7
		// then we should set up TPR instead
		log.Debugf("Detected k8s <1.7, using TPR instead of CRD")
		if err := d.createThirdPartyResources(); err != nil {
			return fmt.Errorf("Unable to create third party resource: %s", err)
		}
		crdClient, err = k8s.CreateTPRClient(restConfig)
		if err != nil {
			return fmt.Errorf("Unable to create third party resource client: %s", err)
		}
	} else if err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %s", err)
	} else {
		crdClient, err = k8s.CreateCRDClient(restConfig)
		if err != nil {
			return fmt.Errorf("Unable to create custom resource definition client: %s", err)
		}
	}

	_, policyControllerDeprecated := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.ExtensionsV1beta1().RESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&v1beta1.NetworkPolicy{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addK8sNetworkPolicyDeprecated,
			UpdateFunc: d.updateK8sNetworkPolicyDeprecated,
			DeleteFunc: d.deleteK8sNetworkPolicyDeprecated,
		},
	)
	go policyControllerDeprecated.Run(wait.NeverStop)

	_, policyController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.NetworkingV1().RESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&networkingv1.NetworkPolicy{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addK8sNetworkPolicy,
			UpdateFunc: d.updateK8sNetworkPolicy,
			DeleteFunc: d.deleteK8sNetworkPolicy,
		},
	)
	go policyController.Run(stopPolicyController)

	_, svcController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.CoreV1().RESTClient(),
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
		cache.NewListWatchFromClient(d.k8sClient.CoreV1().RESTClient(),
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

	_, ingressController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.ExtensionsV1beta1().RESTClient(),
			"ingresses", v1.NamespaceAll, fields.Everything()),
		&v1beta1.Ingress{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.ingressAddFn,
			UpdateFunc: d.ingressModFn,
			DeleteFunc: d.ingressDelFn,
		},
	)
	go ingressController.Run(wait.NeverStop)

	_, ciliumRulesController := cache.NewInformer(
		cache.NewListWatchFromClient(crdClient, "ciliumnetworkpolicies",
			v1.NamespaceAll, fields.Everything()),
		&k8s.CiliumNetworkPolicy{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addCiliumNetworkPolicy,
			UpdateFunc: d.updateCiliumNetworkPolicy,
			DeleteFunc: d.deleteCiliumNetworkPolicy,
		},
	)
	go ciliumRulesController.Run(wait.NeverStop)

	_, nodesController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.Everything()),
		&v1.Node{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.nodesAddFn,
			UpdateFunc: d.nodesModFn,
			DeleteFunc: d.nodesDelFn,
		},
	)
	go nodesController.Run(wait.NeverStop)
	return nil
}

func (d *Daemon) addK8sNetworkPolicy(obj interface{}) {
	k8sNP, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s NetworkPolicy addition")
		return
	}
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}

	opts := AddOptions{Replace: true}
	if _, err := d.PolicyAdd(rules, &opts); err != nil {
		log.Errorf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Kubernetes network policy '%s' successfully add", k8sNP.Name)
}

func (d *Daemon) updateK8sNetworkPolicy(oldObj interface{}, newObj interface{}) {
	log.Debugf("Modified policy %+v->%+v", oldObj, newObj)
	d.addK8sNetworkPolicy(newObj)
}

func (d *Daemon) deleteK8sNetworkPolicy(obj interface{}) {
	k8sNP, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s NetworkPolicy deletion")
		return
	}

	labels := labels.ParseSelectLabelArray(k8s.ExtractPolicyName(k8sNP))

	if _, err := d.PolicyDelete(labels); err != nil {
		log.Errorf("Error while deleting kubernetes network policy %+v: %s", labels, err)
	} else {
		log.Infof("Kubernetes network policy '%s' successfully removed", k8sNP.Name)
	}
}

// addK8sNetworkPolicyDeprecated FIXME remove in k8s 1.8
func (d *Daemon) addK8sNetworkPolicyDeprecated(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s v1beta1 NetworkPolicy addition")
		return
	}
	rules, err := k8s.ParseNetworkPolicyDeprecated(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes v1beta1 network policy %+v: %s", obj, err)
		return
	}

	opts := AddOptions{Replace: true}
	if _, err := d.PolicyAdd(rules, &opts); err != nil {
		log.Errorf("Error while adding kubernetes v1beta1 network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Kubernetes v1beta1 network policy '%s' successfully added", k8sNP.Name)
}

// updateK8sNetworkPolicyDeprecated FIXME remove in k8s 1.8
func (d *Daemon) updateK8sNetworkPolicyDeprecated(oldObj interface{}, newObj interface{}) {
	log.Debugf("Modified v1beta1 policy %+v->%+v", oldObj, newObj)
	d.addK8sNetworkPolicyDeprecated(newObj)
}

// deleteK8sNetworkPolicyDeprecated FIXME remove in k8s 1.8
func (d *Daemon) deleteK8sNetworkPolicyDeprecated(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s v1beta1.NetworkPolicy deletion")
		return
	}

	labels := labels.ParseSelectLabelArray(k8s.ExtractPolicyNameDeprecated(k8sNP))

	if _, err := d.PolicyDelete(labels); err != nil {
		log.Errorf("Error while deleting v1beta1 kubernetes network policy %+v: %s", labels, err)
	} else {
		log.Infof("Kubernetes v1beta1 network policy '%s' successfully removed", k8sNP.Name)
	}
}

func (d *Daemon) serviceAddFn(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	switch svc.Spec.Type {
	case v1.ServiceTypeClusterIP, v1.ServiceTypeNodePort, v1.ServiceTypeLoadBalancer:
		break

	case v1.ServiceTypeExternalName:
		// External-name services must be ignored
		return

	default:
		log.Warningf("Ignoring k8s service %s/%s, reason unsupported type %s",
			svc.Namespace, svc.Name, svc.Spec.Type)
		return
	}

	if strings.ToLower(svc.Spec.ClusterIP) == "none" || svc.Spec.ClusterIP == "" {
		log.Infof("Ignoring k8s service %s/%s, reason: headless",
			svc.Namespace, svc.Name, svc.Spec.Type)
		return
	}

	svcns := types.K8sServiceNamespace{
		Service:   svc.Name,
		Namespace: svc.Namespace,
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	newSI := types.NewK8sServiceInfo(clusterIP)

	// FIXME: Add support for
	//  - NodePort

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

	if err := d.syncExternalLB(&svcns, nil, nil); err != nil {
		log.Errorf("Unable to add endpoints on ingress service %s: %s", svcns, err)
		return
	}
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
	if err := d.syncExternalLB(nil, nil, svcns); err != nil {
		log.Errorf("Unable to remove endpoints on ingress service %s: %s", svcns, err)
		return
	}
}

func areIPsConsistent(ipv4Enabled, isSvcIPv4 bool, svc types.K8sServiceNamespace, se *types.K8sServiceEndpoint) error {
	if isSvcIPv4 {
		if !ipv4Enabled {
			return fmt.Errorf("Received an IPv4 kubernetes service but IPv4 is "+
				"disabled in the cilium daemon. Ignoring service %+v", svc)
		}

		for epIP := range se.BEIPs {
			//is IPv6?
			if net.ParseIP(epIP).To4() == nil {
				return fmt.Errorf("Not all endpoints IPs are IPv4. Ignoring IPv4 service %+v", svc)
			}
		}
	} else {
		for epIP := range se.BEIPs {
			//is IPv4?
			if net.ParseIP(epIP).To4() != nil {
				return fmt.Errorf("Not all endpoints IPs are IPv6. Ignoring IPv6 service %+v", svc)
			}
		}
	}
	return nil
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

func (d *Daemon) delK8sSVCs(svc types.K8sServiceNamespace, svcInfo *types.K8sServiceInfo, se *types.K8sServiceEndpoint) error {
	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if err := areIPsConsistent(!d.conf.IPv4Disabled, isSvcIPv4, svc, se); err != nil {
		return err
	}

	repPorts := getUniqPorts(svcInfo.Ports)

	for _, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		if svcPort.ID != 0 {
			if err := DeleteL3n4AddrIDByUUID(uint32(svcPort.ID)); err != nil {
				log.Warningf("Error while cleaning service ID: %s", err)
			}
		}

		fe, err := types.NewL3n4Addr(svcPort.Protocol, svcInfo.FEIP, svcPort.Port)
		if err != nil {
			log.Errorf("Error while creating a New L3n4AddrID: %s. Ignoring service %v...", err, svcInfo)
			continue
		}

		if err := d.svcDeleteByFrontend(fe); err != nil {
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
	return nil
}

func (d *Daemon) addK8sSVCs(svc types.K8sServiceNamespace, svcInfo *types.K8sServiceInfo, se *types.K8sServiceEndpoint) error {
	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if err := areIPsConsistent(!d.conf.IPv4Disabled, isSvcIPv4, svc, se); err != nil {
		return err
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
			feAddrID, err := PutL3n4Addr(*feAddr, 0)
			if err != nil {
				log.Errorf("Error while getting a new service ID: %s. Ignoring service %v...", err, feAddr)
				continue
			}
			log.Debugf("Got feAddr ID %d for service %+v", feAddrID.ID, svc)
			fePort.ID = feAddrID.ID
		}

		besValues := []types.LBBackEnd{}

		if k8sBEPort != nil {
			for epIP := range se.BEIPs {
				bePort := types.LBBackEnd{
					L3n4Addr: types.L3n4Addr{IP: net.ParseIP(epIP), L4Addr: *k8sBEPort},
					Weight:   0,
				}
				besValues = append(besValues, bePort)
			}
		}

		fe, err := types.NewL3n4AddrID(fePort.Protocol, svcInfo.FEIP, fePort.Port, fePort.ID)
		if err != nil {
			log.Errorf("Error while creating a New L3n4AddrID: %s. Ignoring service %v...", err, svcInfo)
			continue
		}
		if _, err := d.svcAdd(*fe, besValues, true); err != nil {
			log.Errorf("Error while inserting service in LB map: %s", err)
		}
	}
	return nil
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

		if err := d.delK8sSVCs(delSN, svc, endpoint); err != nil {
			log.Errorf("Unable to delete k8s service: %s", err)
			return
		}

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

		if err := d.addK8sSVCs(addSN, svcInfo, endpoint); err != nil {
			log.Errorf("Unable to add K8s service: %s", err)
		}
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

func (d *Daemon) ingressAddFn(obj interface{}) {
	ingress, ok := obj.(*v1beta1.Ingress)
	if !ok {
		return
	}

	if ingress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		return
	}

	svcName := types.K8sServiceNamespace{
		Service:   ingress.Spec.Backend.ServiceName,
		Namespace: ingress.Namespace,
	}

	ingressPort := ingress.Spec.Backend.ServicePort.IntValue()
	fePort, err := types.NewFEPort(types.TCP, uint16(ingressPort))
	if err != nil {
		return
	}

	var host net.IP
	if d.conf.IPv4Disabled {
		host = nodeaddress.GetIPv6()
	} else {
		host = nodeaddress.GetExternalIPv4()
	}
	ingressSvcInfo := types.NewK8sServiceInfo(host)
	ingressSvcInfo.Ports[types.FEPortName(ingress.Spec.Backend.ServicePort.StrVal)] = fePort

	syncIngress := func(ingressSvcInfo *types.K8sServiceInfo) error {
		d.loadBalancer.K8sIngress[svcName] = ingressSvcInfo

		if err := d.syncExternalLB(&svcName, nil, nil); err != nil {
			return fmt.Errorf("Unable to add ingress service %s: %s", svcName, err)
		}
		return nil
	}

	d.loadBalancer.K8sMU.Lock()
	err = syncIngress(ingressSvcInfo)
	d.loadBalancer.K8sMU.Unlock()
	if err != nil {
		log.Errorf("%s", err)
		return
	}

	hostname, _ := os.Hostname()
	ingress.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
		{
			IP:       host.String(),
			Hostname: hostname,
		},
	}

	_, err = d.k8sClient.Extensions().Ingresses(ingress.Namespace).UpdateStatus(ingress)
	if err != nil {
		log.Errorf("Unable to update status of ingress %s: %s", ingress.Name, err)
		return
	}
}

func (d *Daemon) ingressModFn(oldObj interface{}, newObj interface{}) {
	oldIngress, ok := oldObj.(*v1beta1.Ingress)
	if !ok {
		return
	}
	newIngress, ok := newObj.(*v1beta1.Ingress)
	if !ok {
		return
	}

	if oldIngress.Spec.Backend == nil || newIngress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		return
	}

	// Add RevNAT to the BPF Map for non-LB nodes when a LB node update the
	// ingress status with its address.
	port := newIngress.Spec.Backend.ServicePort.IntValue()
	for _, loadbalancer := range newIngress.Status.LoadBalancer.Ingress {
		ingressIP := net.ParseIP(loadbalancer.IP)
		if ingressIP == nil {
			continue
		}
		feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
		if err != nil {
			log.Errorf("Error while creating a new L3n4Addr: %s. Ignoring ingress %s/%s...", err, newIngress.Namespace, newIngress.Name)
			continue
		}
		feAddrID, err := PutL3n4Addr(*feAddr, 0)
		if err != nil {
			log.Errorf("Error while getting a new service ID: %s. Ignoring ingress %s/%s...", err, newIngress.Namespace, newIngress.Name)
			continue
		}
		log.Debugf("Got service ID %d for ingress %s/%s", feAddrID.ID, newIngress.Namespace, newIngress.Name)

		if err := d.RevNATAdd(feAddrID.ID, feAddrID.L3n4Addr); err != nil {
			log.Errorf("Unable to add reverse NAT ID for ingress %s/%s: %s", newIngress.Namespace, newIngress.Name, err)
		}
	}

	if oldIngress.Spec.Backend.ServiceName == newIngress.Spec.Backend.ServiceName &&
		oldIngress.Spec.Backend.ServicePort == newIngress.Spec.Backend.ServicePort {
		return
	}

	d.ingressAddFn(newObj)
}

func (d *Daemon) ingressDelFn(obj interface{}) {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		return
	}

	if ing.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		return
	}

	svcName := types.K8sServiceNamespace{
		Service:   ing.Spec.Backend.ServiceName,
		Namespace: ing.Namespace,
	}

	// Remove RevNAT from the BPF Map for non-LB nodes.
	port := ing.Spec.Backend.ServicePort.IntValue()
	for _, loadbalancer := range ing.Status.LoadBalancer.Ingress {
		ingressIP := net.ParseIP(loadbalancer.IP)
		if ingressIP == nil {
			continue
		}
		feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
		if err != nil {
			log.Errorf("Error while creating a new L3n4Addr: %s. Ignoring ingress %s/%s...", err, ing.Namespace, ing.Name)
			continue
		}
		// This is the only way that we can get the service's ID
		// without accessing the KVStore.
		svc := d.svcGetBySHA256Sum(feAddr.SHA256Sum())
		if svc != nil {
			if err := d.RevNATDelete(svc.FE.ID); err != nil {
				log.Errorf("Error while removing RevNAT for ID %d for ingress %s/%s: %s", svc.FE.ID, ing.Namespace, ing.Name, err)
			}
		}
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	ingressSvcInfo, ok := d.loadBalancer.K8sIngress[svcName]
	if !ok {
		return
	}

	// Get all active endpoints for the service specified in ingress
	k8sEP, ok := d.loadBalancer.K8sEndpoints[svcName]
	if !ok {
		return
	}

	err := d.delK8sSVCs(svcName, ingressSvcInfo, k8sEP)
	if err != nil {
		log.Errorf("Unable to delete K8s ingress: %s", err)
		return
	}
	delete(d.loadBalancer.K8sIngress, svcName)
}

func (d *Daemon) syncExternalLB(newSN, modSN, delSN *types.K8sServiceNamespace) error {
	deleteSN := func(delSN types.K8sServiceNamespace) error {
		ingSvc, ok := d.loadBalancer.K8sIngress[delSN]
		if !ok {
			return nil
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[delSN]
		if !ok {
			return nil
		}

		if err := d.delK8sSVCs(delSN, ingSvc, endpoint); err != nil {
			return err
		}

		delete(d.loadBalancer.K8sServices, delSN)
		return nil
	}

	addSN := func(addSN types.K8sServiceNamespace) error {
		ingressSvcInfo, ok := d.loadBalancer.K8sIngress[addSN]
		if !ok {
			return nil
		}

		k8sEP, ok := d.loadBalancer.K8sEndpoints[addSN]
		if !ok {
			return nil
		}

		err := d.addK8sSVCs(addSN, ingressSvcInfo, k8sEP)
		if err != nil {
			return err
		}
		return nil
	}

	if delSN != nil {
		// Clean old services
		return deleteSN(*delSN)
	}
	if modSN != nil {
		// Re-add modified services
		return addSN(*modSN)
	}
	if newSN != nil {
		// Add new services
		return addSN(*newSN)
	}
	return nil
}

func (d *Daemon) addCiliumNetworkPolicy(obj interface{}) {
	rule, ok := obj.(*k8s.CiliumNetworkPolicy)
	if !ok {
		log.Warningf("Invalid third-party objected, expected CiliumNetworkPolicy, got %+v", obj)
		return
	}

	log.Debugf("Adding k8s CRD CiliumNetworkPolicy %+v", rule)

	rules, err := rule.Parse()
	if err != nil {
		log.Warningf("Ignoring invalid third-party policy rule: %s", err)
		return
	}

	opts := AddOptions{Replace: true}
	if _, err := d.PolicyAdd(rules, &opts); err != nil {
		log.Warningf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Imported third-party policy rule '%s'", rule.Metadata.Name)
}

func (d *Daemon) deleteCiliumNetworkPolicy(obj interface{}) {
	rule, ok := obj.(*k8s.CiliumNetworkPolicy)
	if !ok {
		log.Warningf("Invalid third-party objected, expected CiliumNetworkPolicy, got %+v", obj)
		return
	}

	log.Debugf("Deleting k8s CRD CiliumNetworkPolicy %+v", rule)

	rules, err := rule.Parse()
	if err != nil {
		log.Warningf("Ignoring invalid third-party policy rule: %s", err)
		return
	}

	if _, err := d.PolicyDelete(rules[0].Labels); err != nil {
		log.Warningf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Deleted third-party policy rule '%s'", rule.Metadata.Name)
}

func (d *Daemon) updateCiliumNetworkPolicy(oldObj interface{}, newObj interface{}) {
	// FIXME
	d.deleteCiliumNetworkPolicy(oldObj)
	d.addCiliumNetworkPolicy(newObj)
}

func (d *Daemon) nodesAddFn(obj interface{}) {
	k8sNode, ok := obj.(*v1.Node)
	if !ok {
		log.Warningf("Invalid objected, expected v1.Node, got %+v", obj)
		return
	}
	ni := node.Identity{Name: k8sNode.Name}

	n := k8s.ParseNode(k8sNode)
	node.UpdateNode(ni, n)
	log.Debugf("Added node %s: %+v", ni, n)
}

func (d *Daemon) nodesModFn(oldObj interface{}, newObj interface{}) {
	k8sNode, ok := newObj.(*v1.Node)
	if !ok {
		log.Warningf("Invalid objected, expected v1.Node, got %+v", newObj)
		return
	}

	newNode := k8s.ParseNode(k8sNode)
	ni := node.Identity{Name: k8sNode.Name}

	oldNode := node.GetNode(ni)

	// If node is the same don't even change it on the map
	// TODO: Run the DeepEqual only for the metadata that we care about?
	if reflect.DeepEqual(oldNode, newNode) {
		return
	}

	node.UpdateNode(ni, newNode)

	log.Debugf("k8s: Updated node %s to %+v", ni, newNode)
}

func (d *Daemon) nodesDelFn(obj interface{}) {
	k8sNode, ok := obj.(*v1.Node)
	if !ok {
		log.Warningf("Invalid objected, expected v1.Node, got %+v", obj)
		return
	}

	ni := node.Identity{Name: k8sNode.Name}

	node.DeleteNode(ni)

	log.Debugf("k8s: Removed node %s", ni)
}
