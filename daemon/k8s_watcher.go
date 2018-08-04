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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	informer "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfIPCache "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/service"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

const (
	k8sErrLogTimeout = time.Minute

	k8sAPIGroupCRD              = "CustomResourceDefinition"
	k8sAPIGroupNodeV1Core       = "core/v1::Node"
	k8sAPIGroupNamespaceV1Core  = "core/v1::Namespace"
	k8sAPIGroupServiceV1Core    = "core/v1::Service"
	k8sAPIGroupEndpointV1Core   = "core/v1::Endpoint"
	k8sAPIGroupPodV1Core        = "core/v1::Pods"
	k8sAPIGroupNetworkingV1Core = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupIngressV1Beta1   = "extensions/v1beta1::Ingress"
	k8sAPIGroupCiliumV2         = "cilium/v2::CiliumNetworkPolicy"
)

var (
	// k8sErrMsgMU guards additions and removals to k8sErrMsg, which stores a
	// time after which a repeat error message can be printed
	k8sErrMsgMU  lock.Mutex
	k8sErrMsg    = map[string]time.Time{}
	k8sServerVer *go_version.Version

	ciliumNPClient clientset.Interface

	networkPolicyV1VerConstr, _ = go_version.NewConstraint(">= 1.7.0")

	ciliumv2VerConstr, _           = go_version.NewConstraint(">= 1.7.0")
	ciliumUpdateStatusVerConstr, _ = go_version.NewConstraint(">= 1.11.0")

	k8sCM = controller.NewManager()
)

// k8sAPIGroupsUsed is a lockable map to hold which k8s API Groups we have
// enabled/in-use
// Note: We can replace it with a Go 1.9 map once we require that version
type k8sAPIGroupsUsed struct {
	lock.RWMutex
	apis map[string]bool
}

func (m *k8sAPIGroupsUsed) addAPI(api string) {
	m.Lock()
	defer m.Unlock()
	if m.apis == nil {
		m.apis = make(map[string]bool)
	}
	m.apis[api] = true
}

func (m *k8sAPIGroupsUsed) removeAPI(api string) {
	m.Lock()
	defer m.Unlock()
	delete(m.apis, api)
}

func (m *k8sAPIGroupsUsed) getGroups() []string {
	m.RLock()
	defer m.RUnlock()
	groups := make([]string, 0, len(m.apis))
	for k := range m.apis {
		groups = append(groups, k)
	}
	return groups
}

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8sErrorHandler,
	}
}

// k8sErrorUpdateCheckUnmuteTime returns a boolean indicating whether we should
// log errmsg or not. It manages once-per-k8sErrLogTimeout entry in k8sErrMsg.
// When errmsg is new or more than k8sErrLogTimeout has passed since the last
// invocation that returned true, it returns true.
func k8sErrorUpdateCheckUnmuteTime(errstr string, now time.Time) bool {
	k8sErrMsgMU.Lock()
	defer k8sErrMsgMU.Unlock()

	if unmuteDeadline, ok := k8sErrMsg[errstr]; !ok || now.After(unmuteDeadline) {
		k8sErrMsg[errstr] = now.Add(k8sErrLogTimeout)
		return true
	}

	return false
}

// k8sErrorHandler handles the error messages in a non verbose way by omitting
// repeated instances of the same error message for a timeout defined with
// k8sErrLogTimeout.
func k8sErrorHandler(e error) {
	if e == nil {
		return
	}

	// We rate-limit certain categories of error message. These are matched
	// below, with a default behaviour to print everything else without
	// rate-limiting.
	// Note: We also have side-effects in some of the special cases.
	now := time.Now()
	errstr := e.Error()
	switch {
	// This can occur when cilium comes up before the k8s API server, and keeps
	// trying to connect.
	case strings.Contains(errstr, "connection refused"):
		if k8sErrorUpdateCheckUnmuteTime(errstr, now) {
			log.WithError(e).Error("k8sError")
		}

	// k8s does not allow us to watch both ThirdPartyResource and
	// CustomResourceDefinition. This would occur when a user mixes these within
	// the k8s cluster, and might occur when upgrading from versions of cilium
	// that used ThirdPartyResource to define CiliumNetworkPolicy.
	case strings.Contains(errstr, "Failed to list *v2.CiliumNetworkPolicy: the server could not find the requested resource"):
		if k8sErrorUpdateCheckUnmuteTime(errstr, now) {
			log.WithError(e).Error("Conflicting TPR and CRD resources")
			log.Warn("Detected conflicting TPR and CRD, please migrate all ThirdPartyResource to CustomResourceDefinition! More info: https://cilium.link/migrate-tpr")
			log.Warn("Due to conflicting TPR and CRD rules, CiliumNetworkPolicy enforcement can't be guaranteed!")
		}

	// fromCIDR and toCIDR used to expect an "ip" subfield (so, they were a YAML
	// map with one field) but common usage and expectation would simply list the
	// CIDR ranges and IPs desired as a YAML list. In these cases we would see
	// this decode error. We have since changed the definition to be a simple
	// list of strings.
	case strings.Contains(errstr, "Unable to decode an event from the watch stream: unable to decode watch event"),
		strings.Contains(errstr, "Failed to list *v1.CiliumNetworkPolicy: only encoded map or array can be decoded into a struct"),
		strings.Contains(errstr, "Failed to list *v2.CiliumNetworkPolicy: only encoded map or array can be decoded into a struct"),
		strings.Contains(errstr, "Failed to list *v2.CiliumNetworkPolicy: v2.CiliumNetworkPolicyList:"):
		if k8sErrorUpdateCheckUnmuteTime(errstr, now) {
			log.WithError(e).Error("Unable to decode k8s watch event")
		}

	default:
		log.WithError(e).Error("k8sError")
	}
}

// EnableK8sWatcher watches for policy, services and endpoint changes on the Kubernetes
// api server defined in the receiver's daemon k8sClient. Re-syncs all state from the
// Kubernetes api server at the given reSyncPeriod duration.
func (d *Daemon) EnableK8sWatcher(reSyncPeriod time.Duration) error {
	if !k8s.IsEnabled() {
		log.Debug("Not enabling k8s event listener because k8s is not enabled")
		return nil
	}
	log.Info("Enabling k8s event listener")

	restConfig, err := k8s.CreateConfig()
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration: %s", err)
	}

	apiextensionsclientset, err := apiextensionsclient.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create rest configuration for k8s CRD: %s", err)
	}

	k8sServerVer, err = k8s.GetServerVersion()
	if err != nil {
		return fmt.Errorf("unable to retrieve kubernetes serverversion: %s", err)
	}

	switch {
	case ciliumv2VerConstr.Check(k8sServerVer):
		err = cilium_v2.CreateCustomResourceDefinitions(apiextensionsclientset)
		if err != nil {
			return fmt.Errorf("Unable to create custom resource definition: %s", err)
		}
		d.k8sAPIGroups.addAPI(k8sAPIGroupCRD)
		d.k8sAPIGroups.addAPI(k8sAPIGroupCiliumV2)
	default:
		return fmt.Errorf("Unsupported k8s version. Minimal supported version is >= 1.7.0")
	}

	ciliumNPClient, err = clientset.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("Unable to create cilium network policy client: %s", err)
	}

	serKNPs := serializer.NewFunctionQueue(20)
	serSvcs := serializer.NewFunctionQueue(20)
	serEps := serializer.NewFunctionQueue(20)
	serCNPs := serializer.NewFunctionQueue(20)
	serPods := serializer.NewFunctionQueue(1024)
	serNodes := serializer.NewFunctionQueue(20)
	serNamespaces := serializer.NewFunctionQueue(20)

	switch {
	case networkPolicyV1VerConstr.Check(k8sServerVer):
		_, policyController := cache.NewInformer(
			cache.NewListWatchFromClient(k8s.Client().NetworkingV1().RESTClient(),
				"networkpolicies", v1.NamespaceAll, fields.Everything()),
			&networkingv1.NetworkPolicy{},
			reSyncPeriod,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if k8sNP := copyObjToV1NetworkPolicy(obj); k8sNP != nil {
						serKNPs.Enqueue(func() error {
							d.addK8sNetworkPolicyV1(k8sNP)
							return nil
						}, serializer.NoRetry)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if oldK8sNP := copyObjToV1NetworkPolicy(oldObj); oldK8sNP != nil {
						if newK8sNP := copyObjToV1NetworkPolicy(newObj); newK8sNP != nil {
							serKNPs.Enqueue(func() error {
								d.updateK8sNetworkPolicyV1(oldK8sNP, newK8sNP)
								return nil
							}, serializer.NoRetry)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if k8sNP := copyObjToV1NetworkPolicy(obj); k8sNP != nil {
						serKNPs.Enqueue(func() error {
							d.deleteK8sNetworkPolicyV1(k8sNP)
							return nil
						}, serializer.NoRetry)
					}
				},
			},
		)
		d.k8sResourceSyncWaitGroup.Add(1)
		go policyController.Run(wait.NeverStop)
		go func() {
			completed := make(<-chan struct{})
			log.Debug("waiting for cache to synchronize for NetworkPolicies")
			if ok := cache.WaitForCacheSync(completed, policyController.HasSynced); !ok {
				// If we can't get NetworkPolicies for K8s, fatally exit.
				log.Fatalf("failed to wait for cache to sync for NetworkPolicies")
			}
			log.Debug("caches synced for NetworkPolicies")
			d.k8sResourceSyncWaitGroup.Done()
		}()

		d.k8sAPIGroups.addAPI(k8sAPIGroupNetworkingV1Core)
	}

	_, svcController := cache.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if svc := copyObjToV1Services(obj); svc != nil {
					serSvcs.Enqueue(func() error {
						d.addK8sServiceV1(svc)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldK8sSvc := copyObjToV1Services(oldObj); oldK8sSvc != nil {
					if newK8sSvc := copyObjToV1Services(newObj); newK8sSvc != nil {
						serSvcs.Enqueue(func() error {
							d.updateK8sServiceV1(oldK8sSvc, newK8sSvc)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if svc := copyObjToV1Services(obj); svc != nil {
					serSvcs.Enqueue(func() error {
						d.deleteK8sServiceV1(svc)
						return nil
					}, serializer.NoRetry)
				}
			},
		},
	)
	go svcController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupServiceV1Core)

	_, endpointController := cache.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"endpoints", v1.NamespaceAll, fields.Everything()),
		&v1.Endpoints{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if k8sEP := copyObjToV1Endpoints(obj); k8sEP != nil {
					serEps.Enqueue(func() error {
						d.addK8sEndpointV1(k8sEP)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldK8sEP := copyObjToV1Endpoints(oldObj); oldK8sEP != nil {
					if newK8sEP := copyObjToV1Endpoints(newObj); newK8sEP != nil {
						serEps.Enqueue(func() error {
							d.updateK8sEndpointV1(oldK8sEP, newK8sEP)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if k8sEP := copyObjToV1Endpoints(obj); k8sEP != nil {
					serEps.Enqueue(func() error {
						d.deleteK8sEndpointV1(k8sEP)
						return nil
					}, serializer.NoRetry)
				}
			},
		},
	)
	go endpointController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupEndpointV1Core)

	if option.Config.IsLBEnabled() {
		_, ingressController := cache.NewInformer(
			cache.NewListWatchFromClient(k8s.Client().ExtensionsV1beta1().RESTClient(),
				"ingresses", v1.NamespaceAll, fields.Everything()),
			&v1beta1.Ingress{},
			reSyncPeriod,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if ing := copyObjToV1beta1Ingress(obj); ing != nil {
						serEps.Enqueue(func() error {
							d.addIngressV1beta1(ing)
							return nil
						}, serializer.NoRetry)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if oldIng := copyObjToV1beta1Ingress(oldObj); oldIng != nil {
						if newIng := copyObjToV1beta1Ingress(newObj); newIng != nil {
							serEps.Enqueue(func() error {
								d.updateIngressV1beta1(oldIng, newIng)
								return nil
							}, serializer.NoRetry)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					metrics.SetTSValue(metrics.EventTSK8s, time.Now())
					if ing := copyObjToV1beta1Ingress(obj); ing != nil {
						serEps.Enqueue(func() error {
							d.deleteIngressV1beta1(ing)
							return nil
						}, serializer.NoRetry)
					}
				},
			},
		)
		go ingressController.Run(wait.NeverStop)
		d.k8sAPIGroups.addAPI(k8sAPIGroupIngressV1Beta1)
	}

	si := informer.NewSharedInformerFactory(ciliumNPClient, reSyncPeriod)

	switch {
	case ciliumv2VerConstr.Check(k8sServerVer):
		ciliumV2Controller := si.Cilium().V2().CiliumNetworkPolicies().Informer()
		cnpStore := ciliumV2Controller.GetStore()
		ciliumV2Controller.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if cnp := copyObjToV2CNP(obj); cnp != nil {
					serCNPs.Enqueue(func() error {
						d.addCiliumNetworkPolicyV2(cnpStore, cnp)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldCNP := copyObjToV2CNP(oldObj); oldCNP != nil {
					if newCNP := copyObjToV2CNP(newObj); newCNP != nil {
						serCNPs.Enqueue(func() error {
							d.updateCiliumNetworkPolicyV2(cnpStore, oldCNP, newCNP)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if cnp := copyObjToV2CNP(obj); cnp != nil {
					serCNPs.Enqueue(func() error {
						d.deleteCiliumNetworkPolicyV2(cnp)
						return nil
					}, serializer.NoRetry)
				}
			},
		})

		d.k8sResourceSyncWaitGroup.Add(1)
		go func() {
			completed := make(<-chan struct{})
			log.Debug("waiting for cache to synchronize for CiliumNetworkPolicies")
			if ok := cache.WaitForCacheSync(completed, ciliumV2Controller.HasSynced); !ok {
				// If we can't get CiliumNetworkPolicies for K8s, fatally exit.
				log.Fatalf("failed to wait for cache to sync for CiliumNetworkPolicies")
			}
			log.Debug("caches synced for CiliumNetworkPolicies")
			d.k8sResourceSyncWaitGroup.Done()
		}()
	}

	si.Start(wait.NeverStop)

	_, podsController := cache.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"pods", v1.NamespaceAll, fields.Everything()),
		&v1.Pod{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if newK8sPod := copyObjToV1Pod(newObj); newK8sPod != nil {
					serPods.Enqueue(func() error {
						d.addK8sPodV1(newK8sPod)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldK8sPod := copyObjToV1Pod(oldObj); oldK8sPod != nil {
					if newK8sPod := copyObjToV1Pod(newObj); newK8sPod != nil {
						serPods.Enqueue(func() error {
							d.updateK8sPodV1(oldK8sPod, newK8sPod)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(oldObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldK8sPod := copyObjToV1Pod(oldObj); oldK8sPod != nil {
					serPods.Enqueue(func() error {
						d.deleteK8sPodV1(oldK8sPod)
						return nil
					}, serializer.NoRetry)
				}
			},
		},
	)

	go podsController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupPodV1Core)

	_, nodesController := cache.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"nodes", v1.NamespaceAll, fields.Everything()),
		&v1.Node{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if k8sNode := copyObjToV1Node(obj); k8sNode != nil {
					serNodes.Enqueue(func() error {
						d.addK8sNodeV1(k8sNode)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldK8sNode := copyObjToV1Node(oldObj); oldK8sNode != nil {
					if newK8sNode := copyObjToV1Node(newObj); newK8sNode != nil {
						serNodes.Enqueue(func() error {
							d.updateK8sNodeV1(oldK8sNode, newK8sNode)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if k8sNode := copyObjToV1Node(obj); k8sNode != nil {
					serNodes.Enqueue(func() error {
						d.deleteK8sNodeV1(k8sNode)
						return nil
					}, serializer.NoRetry)
				}
			},
		},
	)

	go nodesController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupNodeV1Core)

	_, namespaceController := cache.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"namespaces", v1.NamespaceAll, fields.Everything()),
		&v1.Namespace{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			// AddFunc does not matter since the endpoint will fetch
			// namespace labels when the endpoint is created
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.SetTSValue(metrics.EventTSK8s, time.Now())
				if oldns := copyObjToV1Namespace(oldObj); oldns != nil {
					if newns := copyObjToV1Namespace(newObj); newns != nil {
						serNamespaces.Enqueue(func() error {
							d.updateK8sV1Namespace(oldns, newns)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			// DelFunc does not matter since, when a namespace is deleted, all
			// pods belonging to that namespace are also deleted.
		},
	)

	go namespaceController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupNamespaceV1Core)

	endpoint.RunK8sCiliumEndpointSyncGC()

	return nil
}

func copyObjToV1NetworkPolicy(obj interface{}) *networkingv1.NetworkPolicy {
	k8sNP, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 NetworkPolicy")
		return nil
	}
	return k8sNP.DeepCopy()
}

func copyObjToV1beta1NetworkPolicy(obj interface{}) *v1beta1.NetworkPolicy {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1beta1 NetworkPolicy")
		return nil
	}
	return k8sNP.DeepCopy()
}

func copyObjToV1Services(obj interface{}) *v1.Service {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Service")
		return nil
	}
	return svc.DeepCopy()
}

func copyObjToV1Endpoints(obj interface{}) *v1.Endpoints {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Endpoints")
		return nil
	}
	return ep.DeepCopy()
}

func copyObjToV1beta1Ingress(obj interface{}) *v1beta1.Ingress {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1beta1 Ingress")
		return nil
	}
	return ing.DeepCopy()
}

func copyObjToV2CNP(obj interface{}) *cilium_v2.CiliumNetworkPolicy {
	cnp, ok := obj.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v2 CiliumNetworkPolicy")
		return nil
	}
	return cnp.DeepCopy()
}

func copyObjToV1Node(obj interface{}) *v1.Node {
	node, ok := obj.(*v1.Node)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Node")
		return nil
	}
	return node.DeepCopy()
}

func copyObjToV1Namespace(obj interface{}) *v1.Namespace {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Namespace")
		return nil
	}
	return ns.DeepCopy()
}

func copyObjToV1Pod(obj interface{}) *v1.Pod {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Pod")
		return nil
	}
	return pod.DeepCopy()
}

func (d *Daemon) addK8sNetworkPolicyV1(k8sNP *networkingv1.NetworkPolicy) {
	scopedLog := log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

	opts := AddOptions{Replace: true}
	if _, err := d.PolicyAdd(rules, &opts); err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(rules),
		}).Error("Unable to add NetworkPolicy rules to policy repository")
		return
	}

	scopedLog.Info("NetworkPolicy successfully added")
}

func (d *Daemon) updateK8sNetworkPolicyV1(oldk8sNP, newk8sNP *networkingv1.NetworkPolicy) {
	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                 oldk8sNP.TypeMeta.APIVersion,
		logfields.K8sNetworkPolicyName + ".old": oldk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":         oldk8sNP.ObjectMeta.Namespace,
		logfields.K8sNetworkPolicyName:          newk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:                  newk8sNP.ObjectMeta.Namespace,
	}).Debug("Received policy update")

	d.addK8sNetworkPolicyV1(newk8sNP)
}

func (d *Daemon) deleteK8sNetworkPolicyV1(k8sNP *networkingv1.NetworkPolicy) {
	labels := k8s.GetPolicyLabelsv1(k8sNP)

	if labels == nil {
		log.Fatalf("provided v1 NetworkPolicy is nil, so cannot delete it")
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNetworkPolicyName: k8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:         k8sNP.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:        k8sNP.TypeMeta.APIVersion,
		logfields.Labels:               logfields.Repr(labels),
	})
	if _, err := d.PolicyDelete(labels); err != nil {
		scopedLog.WithError(err).Error("Error while deleting k8s NetworkPolicy")
	} else {
		scopedLog.Info("NetworkPolicy successfully removed")
	}
}

func (d *Daemon) addK8sServiceV1(svc *v1.Service) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:    svc.ObjectMeta.Name,
		logfields.K8sNamespace:  svc.ObjectMeta.Namespace,
		logfields.K8sAPIVersion: svc.TypeMeta.APIVersion,
		logfields.K8sSvcType:    svc.Spec.Type,
	})

	switch svc.Spec.Type {
	case v1.ServiceTypeClusterIP, v1.ServiceTypeNodePort, v1.ServiceTypeLoadBalancer:
		break

	case v1.ServiceTypeExternalName:
		// External-name services must be ignored
		return

	default:
		scopedLog.Warn("Ignoring k8s service: unsupported type")
		return
	}

	if svc.Spec.ClusterIP == "" {
		scopedLog.Info("Ignoring k8s service: empty ClusterIP")
		return
	}

	svcns := types.K8sServiceNamespace{
		ServiceName: svc.ObjectMeta.Name,
		Namespace:   svc.ObjectMeta.Namespace,
	}

	clusterIP := net.ParseIP(svc.Spec.ClusterIP)
	headless := false
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		headless = true
	}
	newSI := types.NewK8sServiceInfo(clusterIP, headless, svc.Labels, svc.Spec.Selector)

	// FIXME: Add support for
	//  - NodePort

	for _, port := range svc.Spec.Ports {
		p, err := types.NewFEPort(types.L4Type(port.Protocol), uint16(port.Port))
		if err != nil {
			scopedLog.WithError(err).WithField("port", port).Error("Unable to add service port")
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

func (d *Daemon) updateK8sServiceV1(oldSvc, newSvc *v1.Service) {
	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:         oldSvc.TypeMeta.APIVersion,
		logfields.K8sSvcName + ".old":   oldSvc.ObjectMeta.Name,
		logfields.K8sNamespace + ".old": oldSvc.ObjectMeta.Namespace,
		logfields.K8sSvcType + ".old":   oldSvc.Spec.Type,
		logfields.K8sSvcName:            newSvc.ObjectMeta.Name,
		logfields.K8sNamespace:          newSvc.ObjectMeta.Namespace,
		logfields.K8sSvcType:            newSvc.Spec.Type,
	}).Debug("Received service update")

	d.addK8sServiceV1(newSvc)
}

func (d *Daemon) deleteK8sServiceV1(svc *v1.Service) {
	log.WithFields(logrus.Fields{
		logfields.K8sSvcName:    svc.ObjectMeta.Name,
		logfields.K8sNamespace:  svc.ObjectMeta.Namespace,
		logfields.K8sAPIVersion: svc.TypeMeta.APIVersion,
	}).Debug("Deleting k8s service")

	svcns := &types.K8sServiceNamespace{
		ServiceName: svc.ObjectMeta.Name,
		Namespace:   svc.ObjectMeta.Namespace,
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()
	d.syncLB(nil, nil, svcns)
}

func (d *Daemon) addK8sEndpointV1(ep *v1.Endpoints) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: ep.ObjectMeta.Name,
		logfields.K8sNamespace:    ep.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:   ep.TypeMeta.APIVersion,
	})

	svcns := types.K8sServiceNamespace{
		ServiceName: ep.ObjectMeta.Name,
		Namespace:   ep.ObjectMeta.Namespace,
	}

	newSvcEP := types.NewK8sServiceEndpoint()

	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			newSvcEP.BEIPs[addr.IP] = true
		}
		for _, port := range sub.Ports {
			lbPort, err := types.NewL4Addr(types.L4Type(port.Protocol), uint16(port.Port))
			if err != nil {
				scopedLog.WithError(err).Error("Error while creating a new LB Port")
				continue
			}
			newSvcEP.Ports[types.FEPortName(port.Name)] = lbPort
		}
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	d.loadBalancer.K8sEndpoints[svcns] = newSvcEP

	d.syncLB(&svcns, nil, nil)

	if option.Config.IsLBEnabled() {
		if err := d.syncExternalLB(&svcns, nil, nil); err != nil {
			scopedLog.WithError(err).Error("Unable to add endpoints on ingress service")
			return
		}
	}

	svc, ok := d.loadBalancer.K8sServices[svcns]
	if ok && svc.IsExternal() {
		translator := k8s.NewK8sTranslator(svcns, *newSvcEP, false, svc.Labels, bpfIPCache.IPCache)
		err := d.policy.TranslateRules(translator)
		if err != nil {
			log.Errorf("Unable to repopulate egress policies from ToService rules: %v", err)
		} else {
			d.TriggerPolicyUpdates(true)
		}
	}
}

func (d *Daemon) updateK8sEndpointV1(oldEP, newEP *v1.Endpoints) {
	// TODO only print debug message if the difference between the old endpoint
	// and the new endpoint are important to us.
	//log.WithFields(logrus.Fields{
	//	logfields.K8sAPIVersion:            oldEP.TypeMeta.APIVersion,
	//	logfields.K8sEndpointName + ".old": oldEP.ObjectMeta.Name,
	//	logfields.K8sNamespace + ".old":    oldEP.ObjectMeta.Namespace,
	//	logfields.K8sEndpointName: newEP.ObjectMeta.Name,
	//	logfields.K8sNamespace:    newEP.ObjectMeta.Namespace,
	//}).Debug("Received endpoint update")

	d.addK8sEndpointV1(newEP)
}

func (d *Daemon) deleteK8sEndpointV1(ep *v1.Endpoints) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: ep.ObjectMeta.Name,
		logfields.K8sNamespace:    ep.ObjectMeta.Namespace,
		logfields.K8sAPIVersion:   ep.TypeMeta.APIVersion,
	})

	svcns := types.K8sServiceNamespace{
		ServiceName: ep.ObjectMeta.Name,
		Namespace:   ep.ObjectMeta.Namespace,
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	if endpoint, ok := d.loadBalancer.K8sEndpoints[svcns]; ok {
		svc, ok := d.loadBalancer.K8sServices[svcns]
		if ok && svc.IsExternal() {
			translator := k8s.NewK8sTranslator(svcns, *endpoint, true, svc.Labels, bpfIPCache.IPCache)
			err := d.policy.TranslateRules(translator)
			if err != nil {
				log.Errorf("Unable to depopulate egress policies from ToService rules: %v", err)
			} else {
				d.TriggerPolicyUpdates(true)
			}
		}
	}

	d.syncLB(nil, nil, &svcns)
	if option.Config.IsLBEnabled() {
		if err := d.syncExternalLB(nil, nil, &svcns); err != nil {
			scopedLog.WithError(err).Error("Unable to remove endpoints on ingress service")
			return
		}
	}
}

func areIPsConsistent(ipv4Enabled, isSvcIPv4 bool, svc types.K8sServiceNamespace, se *types.K8sServiceEndpoint) error {
	if isSvcIPv4 {
		if !ipv4Enabled {
			return fmt.Errorf("Received an IPv4 k8s service but IPv4 is "+
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
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if lb := viper.GetBool("disable-k8s-services"); lb == true {
		return nil
	}

	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return nil
	}

	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if err := areIPsConsistent(!option.Config.IPv4Disabled, isSvcIPv4, svc, se); err != nil {
		return err
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.ServiceName,
		logfields.K8sNamespace: svc.Namespace,
	})

	repPorts := getUniqPorts(svcInfo.Ports)

	for _, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		if svcPort.ID != 0 {
			if err := service.DeleteID(uint32(svcPort.ID)); err != nil {
				scopedLog.WithError(err).Warn("Error while cleaning service ID")
			}
		}

		fe, err := types.NewL3n4Addr(svcPort.Protocol, svcInfo.FEIP, svcPort.Port)
		if err != nil {
			scopedLog.WithError(err).Error("Error while creating a New L3n4AddrID. Ignoring service")
			continue
		}

		if err := d.svcDeleteByFrontend(fe); err != nil {
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(fe)).
				Warn("Error deleting service by frontend")

		} else {
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", svcInfo.FEIP, svcPort.Port)
		}

		if err := d.RevNATDelete(svcPort.ID); err != nil {
			scopedLog.WithError(err).WithField(logfields.ServiceID, svcPort.ID).Warn("Error deleting reverse NAT")
		} else {
			scopedLog.Debugf("# cilium lb delete-rev-nat %d", svcPort.ID)
		}
	}
	return nil
}

func (d *Daemon) addK8sSVCs(svc types.K8sServiceNamespace, svcInfo *types.K8sServiceInfo, se *types.K8sServiceEndpoint) error {
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if lb := viper.GetBool("disable-k8s-services"); lb == true {
		return nil
	}

	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.ServiceName,
		logfields.K8sNamespace: svc.Namespace,
	})

	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if err := areIPsConsistent(!option.Config.IPv4Disabled, isSvcIPv4, svc, se); err != nil {
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
				scopedLog.WithError(err).WithFields(logrus.Fields{
					logfields.ServiceID: fePortName,
					logfields.IPAddr:    svcInfo.FEIP,
					logfields.Port:      fePort.Port,
					logfields.Protocol:  fePort.Protocol,
				}).Error("Error while creating a new L3n4Addr. Ignoring service...")
				continue
			}
			feAddrID, err := service.AcquireID(*feAddr, 0)
			if err != nil {
				scopedLog.WithError(err).WithFields(logrus.Fields{
					logfields.ServiceID: fePortName,
					logfields.IPAddr:    svcInfo.FEIP,
					logfields.Port:      fePort.Port,
					logfields.Protocol:  fePort.Protocol,
				}).Error("Error while getting a new service ID. Ignoring service...")
				continue
			}
			scopedLog.WithFields(logrus.Fields{
				logfields.ServiceName: fePortName,
				logfields.ServiceID:   feAddrID.ID,
				logfields.Object:      logfields.Repr(svc),
			}).Debug("Got feAddr ID for service")
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
			scopedLog.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr: svcInfo.FEIP,
				logfields.Port:   svcInfo.Ports,
			}).Error("Error while creating a New L3n4AddrID. Ignoring service...")
			continue
		}
		if _, err := d.svcAdd(*fe, besValues, true); err != nil {
			scopedLog.WithError(err).Error("Error while inserting service in LB map")
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
			log.WithError(err).WithFields(logrus.Fields{
				logfields.K8sSvcName:   delSN.ServiceName,
				logfields.K8sNamespace: delSN.Namespace,
			}).Error("Unable to delete k8s service")
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
			log.WithError(err).WithFields(logrus.Fields{
				logfields.K8sSvcName:   addSN.ServiceName,
				logfields.K8sNamespace: addSN.Namespace,
			}).Error("Unable to add k8s service")
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

func (d *Daemon) addIngressV1beta1(ingress *v1beta1.Ingress) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sIngressName: ingress.ObjectMeta.Name,
		logfields.K8sAPIVersion:  ingress.TypeMeta.APIVersion,
		logfields.K8sNamespace:   ingress.ObjectMeta.Namespace,
	})

	if ingress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		scopedLog.Warn("Cilium only supports Single Service Ingress for now, ignoring ingress")
		return
	}

	svcName := types.K8sServiceNamespace{
		ServiceName: ingress.Spec.Backend.ServiceName,
		Namespace:   ingress.ObjectMeta.Namespace,
	}

	ingressPort := ingress.Spec.Backend.ServicePort.IntValue()
	fePort, err := types.NewFEPort(types.TCP, uint16(ingressPort))
	if err != nil {
		return
	}

	var host net.IP
	if option.Config.IPv4Disabled {
		host = option.Config.HostV6Addr
	} else {
		host = option.Config.HostV4Addr
	}
	ingressSvcInfo := types.NewK8sServiceInfo(host, false, nil, nil)
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
		scopedLog.WithError(err).Error("Error in syncIngress")
		return
	}

	hostname, _ := os.Hostname()
	dpyCopyIngress := ingress.DeepCopy()
	dpyCopyIngress.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
		{
			IP:       host.String(),
			Hostname: hostname,
		},
	}

	_, err = k8s.Client().ExtensionsV1beta1().Ingresses(dpyCopyIngress.ObjectMeta.Namespace).UpdateStatus(dpyCopyIngress)
	if err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.K8sIngress: dpyCopyIngress,
		}).Error("Unable to update status of ingress")
		return
	}
}

func (d *Daemon) updateIngressV1beta1(oldIngress, newIngress *v1beta1.Ingress) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sIngressName + ".old": oldIngress.ObjectMeta.Name,
		logfields.K8sAPIVersion + ".old":  oldIngress.TypeMeta.APIVersion,
		logfields.K8sNamespace + ".old":   oldIngress.ObjectMeta.Namespace,
		logfields.K8sIngressName:          newIngress.ObjectMeta.Name,
		logfields.K8sAPIVersion:           newIngress.TypeMeta.APIVersion,
		logfields.K8sNamespace:            newIngress.ObjectMeta.Namespace,
	})

	if oldIngress.Spec.Backend == nil || newIngress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		scopedLog.Warn("Cilium only supports Single Service Ingress for now, ignoring ingress")
		return
	}

	// Add RevNAT to the BPF Map for non-LB nodes when a LB node update the
	// ingress status with its address.
	if !option.Config.IsLBEnabled() {
		port := newIngress.Spec.Backend.ServicePort.IntValue()
		for _, loadbalancer := range newIngress.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(loadbalancer.IP)
			if ingressIP == nil {
				continue
			}
			feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
			if err != nil {
				scopedLog.WithError(err).Error("Error while creating a new L3n4Addr. Ignoring ingress...")
				continue
			}
			feAddrID, err := service.AcquireID(*feAddr, 0)
			if err != nil {
				scopedLog.WithError(err).Error("Error while getting a new service ID. Ignoring ingress...")
				continue
			}
			scopedLog.WithFields(logrus.Fields{
				logfields.ServiceID: feAddrID.ID,
			}).Debug("Got service ID for ingress")

			if err := d.RevNATAdd(feAddrID.ID, feAddrID.L3n4Addr); err != nil {
				scopedLog.WithError(err).WithFields(logrus.Fields{
					logfields.ServiceID: feAddrID.ID,
					logfields.IPAddr:    feAddrID.L3n4Addr.IP,
					logfields.Port:      feAddrID.L3n4Addr.Port,
					logfields.Protocol:  feAddrID.L3n4Addr.Protocol,
				}).Error("Unable to add reverse NAT ID for ingress")
			}
		}
		return
	}

	if oldIngress.Spec.Backend.ServiceName == newIngress.Spec.Backend.ServiceName &&
		oldIngress.Spec.Backend.ServicePort == newIngress.Spec.Backend.ServicePort {
		return
	}

	d.addIngressV1beta1(newIngress)
}

func (d *Daemon) deleteIngressV1beta1(ingress *v1beta1.Ingress) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sIngressName: ingress.ObjectMeta.Name,
		logfields.K8sAPIVersion:  ingress.TypeMeta.APIVersion,
		logfields.K8sNamespace:   ingress.ObjectMeta.Namespace,
	})

	if ingress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		scopedLog.Warn("Cilium only supports Single Service Ingress for now, ignoring ingress deletion")
		return
	}

	svcName := types.K8sServiceNamespace{
		ServiceName: ingress.Spec.Backend.ServiceName,
		Namespace:   ingress.ObjectMeta.Namespace,
	}

	// Remove RevNAT from the BPF Map for non-LB nodes.
	if !option.Config.IsLBEnabled() {
		port := ingress.Spec.Backend.ServicePort.IntValue()
		for _, loadbalancer := range ingress.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(loadbalancer.IP)
			if ingressIP == nil {
				continue
			}
			feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
			if err != nil {
				scopedLog.WithError(err).Error("Error while creating a new L3n4Addr. Ignoring ingress...")
				continue
			}
			// This is the only way that we can get the service's ID
			// without accessing the KVStore.
			svc := d.svcGetBySHA256Sum(feAddr.SHA256Sum())
			if svc != nil {
				if err := d.RevNATDelete(svc.FE.ID); err != nil {
					scopedLog.WithError(err).WithFields(logrus.Fields{
						logfields.ServiceID: svc.FE.ID,
					}).Error("Error while removing RevNAT for ingress")
				}
			}
		}
		return
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
		scopedLog.WithError(err).Error("Unable to delete K8s ingress")
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

// getUpdatedCNPFromStore gets the most recent version of cnp from the store
// ciliumV2Store, which is updated by the Kubernetes watcher. This reduces
// the possibility of Cilium trying to update cnp in Kubernetes which has
// been updated between the time the watcher in this Cilium instance has
// received cnp, and when this function is called. This still may occur, though
// and users of the returned CiliumNetworkPolicy may not be able to update
// the cnp because it may become out-of-date. Returns an error if the CNP cannot
// be retrieved from the store, or the object retrieved from the store is not of
// the expected type.
func getUpdatedCNPFromStore(ciliumV2Store cache.Store, cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	serverRuleStore, exists, err := ciliumV2Store.Get(cnp)
	if err != nil {
		return nil, fmt.Errorf("unable to find v2.CiliumNetworkPolicy in local cache: %s", err)
	}
	if !exists {
		return nil, errors.New("v2.CiliumNetworkPolicy does not exist in local cache")
	}

	serverRule, ok := serverRuleStore.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		return nil, errors.New("Received object of unknown type from API server, expecting v2.CiliumNetworkPolicy")
	}

	return serverRule, nil
}

func (d *Daemon) addCiliumNetworkPolicyV2(ciliumV2Store cache.Store, cnp *cilium_v2.CiliumNetworkPolicy) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	var rev uint64

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil && len(rules) > 0 {
		d.loadBalancer.K8sMU.Lock()
		policyImportErr = k8s.PreprocessRules(rules, d.loadBalancer.K8sEndpoints, d.loadBalancer.K8sServices)
		d.loadBalancer.K8sMU.Unlock()
		if policyImportErr == nil {
			rev, policyImportErr = d.PolicyAdd(rules, &AddOptions{Replace: true})
		}
	}

	if policyImportErr != nil {
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}
	ctrlName := cnp.GetControllerName()
	k8sCM.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func() error {

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				waitForEPsErr := endpointmanager.WaitForEndpointsAtPolicyRev(ctx, rev)

				serverRule, fromStoreErr := getUpdatedCNPFromStore(ciliumV2Store, cnp)
				if fromStoreErr != nil {
					scopedLog.WithError(fromStoreErr).Error("error getting updated CNP from store")
					return fromStoreErr
				}

				// Make a copy since the rule is a pointer, and any of its fields
				// which are also pointers could be modified outside of this
				// function.
				serverRuleCpy := serverRule.DeepCopy()
				_, ruleCopyParseErr := serverRuleCpy.Parse()
				if ruleCopyParseErr != nil {
					// If we can't parse the rule then we should signalize
					// it in the status
					log.WithError(ruleCopyParseErr).WithField(logfields.Object, logfields.Repr(serverRuleCpy)).
						Warn("Error parsing new CiliumNetworkPolicy rule")
				}

				var err3 error

				// Update the status of whether the rule is enforced on this node.
				// If we are unable to parse the CNP retrieved from the store,
				// or if endpoints did not reach the desired policy revision
				// after 30 seconds, then mark the rule as not being enforced.
				if policyImportErr != nil {
					// OK is false here because the policy wasn't imported into
					// cilium on this node; since it wasn't imported, it also
					// isn't enforced.
					err3 = updateCNPNodeStatus(serverRuleCpy, false, false, policyImportErr, rev, cnp.Annotations)
				} else if ruleCopyParseErr != nil {
					// This handles the case where the initial instance of this
					// rule was imported into the policy repository successfully
					// (policyImportErr == nil), but, the rule has been updated
					// in the store soon after, and is now invalid. As such,
					// the rule is not OK because it cannot be imported due
					// to parsing errors, and cannot be enforced because it is
					// not OK.
					err3 = updateCNPNodeStatus(serverRuleCpy, false, false, ruleCopyParseErr, rev, cnp.Annotations)
				} else {
					// If the deadline by the above context, then not all
					// endpoints are enforcing the given policy, and
					// waitForEpsErr will be non-nil.
					err3 = updateCNPNodeStatus(serverRuleCpy, waitForEPsErr == nil, true, waitForEPsErr, rev, cnp.Annotations)
				}

				if err3 == nil {
					scopedLog.WithField("status", serverRuleCpy.Status).Debug("successfully updated with status")
				} else {
					return err3
				}

				return waitForEPsErr
			},
		},
	)
}

func updateCNPNodeStatus(cnp *cilium_v2.CiliumNetworkPolicy, enforcing, ok bool, err error, rev uint64, annotations map[string]string) error {
	var (
		cnpns cilium_v2.CiliumNetworkPolicyNodeStatus
		err2  error
	)

	if err != nil {
		cnpns = cilium_v2.CiliumNetworkPolicyNodeStatus{
			Enforcing:   enforcing,
			Error:       err.Error(),
			OK:          ok,
			LastUpdated: cilium_v2.NewTimestamp(),
			Annotations: annotations,
		}
	} else {
		cnpns = cilium_v2.CiliumNetworkPolicyNodeStatus{
			Enforcing:   enforcing,
			Revision:    rev,
			OK:          ok,
			LastUpdated: cilium_v2.NewTimestamp(),
			Annotations: annotations,
		}
	}

	nodeName := node.GetName()
	cnp.SetPolicyStatus(nodeName, cnpns)
	ns := k8sUtils.ExtractNamespace(&cnp.ObjectMeta)

	switch {
	case ciliumUpdateStatusVerConstr.Check(k8sServerVer):
		_, err2 = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).UpdateStatus(cnp)
	default:
		_, err2 = ciliumNPClient.CiliumV2().CiliumNetworkPolicies(ns).Update(cnp)
	}
	return err2
}

func (d *Daemon) deleteCiliumNetworkPolicyV2(cnp *cilium_v2.CiliumNetworkPolicy) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	ctrlName := cnp.GetControllerName()
	err := k8sCM.RemoveController(ctrlName)
	if err != nil {
		log.Debugf("Unable to remove controller %s: %s", ctrlName, err)
	}

	rules, err := cnp.Parse()
	if err == nil {
		if len(rules) > 0 {
			// On a CNP, the transformed rule is stored in the local repository
			// with a set of labels. On a CNP with multiple rules all rules are
			// stored in the local repository with the same set of labels.
			// Therefore the deletion on the local repository can be done with
			// the set of labels of the first rule.
			_, err = d.PolicyDelete(rules[0].Labels)
		}
	}
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
}

func updateRuleAnnotations(ciliumV2Store cache.Store, cnp *cilium_v2.CiliumNetworkPolicy) error {

	updatedCNPFromStore, err := getUpdatedCNPFromStore(ciliumV2Store, cnp)
	if err != nil {
		return err
	}

	// Make a copy since the rule is a pointer, and any of its fields
	// which are also pointers could be modified outside of this
	// function.
	updatedCNPFromStoreCopy := updatedCNPFromStore.DeepCopy()

	// Only update annotations for node on which this agent is running.
	nodeName := node.GetName()
	cnpNodeStatus := cnp.GetPolicyStatus(nodeName)

	var cnpErr error
	if cnpNodeStatus.Error != "" {
		cnpErr = fmt.Errorf(cnpNodeStatus.Error)
	}

	// Update server with updated rule with new annotations.
	err = updateCNPNodeStatus(updatedCNPFromStoreCopy, cnpNodeStatus.Enforcing, cnpNodeStatus.OK, cnpErr, cnpNodeStatus.Revision, cnp.Annotations)
	if err != nil {
		return err
	}

	log.WithField("rule", logfields.Repr(updatedCNPFromStoreCopy)).Debug("rule had no policy changes, but had annotation changes; successfully updated annotations of rule")

	return nil
}

func (d *Daemon) updateCiliumNetworkPolicyV2(ciliumV2Store cache.Store,
	oldRuleCpy, newRuleCpy *cilium_v2.CiliumNetworkPolicy) {

	_, err := oldRuleCpy.Parse()
	if err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
			Warn("Error parsing old CiliumNetworkPolicy rule")
		return
	}
	_, err = newRuleCpy.Parse()
	if err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(newRuleCpy)).
			Warn("Error parsing new CiliumNetworkPolicy rule")
		return
	}

	// Do not add rule into policy repository if the spec remains unchanged, as
	// policy recalculation is not needed.
	if oldRuleCpy.SpecEquals(newRuleCpy) {
		// If the annotations differ between the rules, but the specs are the same,
		// just update the annotations within the CNP new rule directly, but
		// only if the policy has already been realized for all endpoints.
		if !oldRuleCpy.AnnotationsEquals(newRuleCpy) {

			// Update annotations within a controller so the status of the update
			// is trackable from the list of running controllers, and so we do
			// not block subsequent policy lifecycle operations from Kubernetes
			// until the update is complete.
			oldCtrlName := oldRuleCpy.GetControllerName()
			newCtrlName := newRuleCpy.GetControllerName()

			// In case the controller name changes between copies of rules,
			// remove old controller so we do not leak goroutines.
			if oldCtrlName != newCtrlName {
				err := k8sCM.RemoveController(oldCtrlName)
				if err != nil {
					log.Debugf("Unable to remove controller %s: %s", oldCtrlName, err)
				}
			}

			k8sCM.UpdateController(newCtrlName,
				controller.ControllerParams{
					DoFunc: func() error {
						return updateRuleAnnotations(ciliumV2Store, newRuleCpy)
					},
				},
			)
		}

		return

	}

	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                    oldRuleCpy.TypeMeta.APIVersion,
		logfields.CiliumNetworkPolicyName + ".old": oldRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":            oldRuleCpy.ObjectMeta.Namespace,
		logfields.CiliumNetworkPolicyName:          newRuleCpy.ObjectMeta.Name,
		logfields.K8sNamespace:                     newRuleCpy.ObjectMeta.Namespace,
		"annotations.old":                          oldRuleCpy.ObjectMeta.Annotations,
		"annotations":                              newRuleCpy.ObjectMeta.Annotations,
	}).Debug("Modified CiliumNetworkPolicy")

	d.addCiliumNetworkPolicyV2(ciliumV2Store, newRuleCpy)
}

func (d *Daemon) updatePodHostIP(pod *v1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	hostIP := net.ParseIP(pod.Status.HostIP)
	if hostIP == nil {
		return true, fmt.Errorf("no/invalid HostIP: %s", pod.Status.HostIP)
	}

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.Status.PodIP)
	}

	selfOwned := ipcache.IPIdentityCache.Upsert(pod.Status.PodIP, hostIP, ipcache.Identity{
		ID:     identity.ReservedIdentityCluster,
		Source: ipcache.FromKubernetes,
	})
	if !selfOwned {
		return true, fmt.Errorf("ipcache entry owned by kvstore or agent")
	}

	return false, nil
}

func (d *Daemon) deletePodHostIP(pod *v1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.Status.PodIP)
	}

	// a small race condition exists here as deletion could occur in
	// parallel based on another event but it doesn't matter as the
	// identity is going away
	id, exists := ipcache.IPIdentityCache.LookupByIP(pod.Status.PodIP)
	if !exists {
		return true, fmt.Errorf("identity for IP does not exist in case")
	}

	if id.Source != ipcache.FromKubernetes {
		return true, fmt.Errorf("ipcache entry not owned by kubernetes source")
	}

	ipcache.IPIdentityCache.Delete(pod.Status.PodIP)

	return false, nil
}

func (d *Daemon) addK8sPodV1(pod *v1.Pod) {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"hostIP":               pod.Status.HostIP,
	})

	skipped, err := d.updatePodHostIP(pod)
	switch {
	case skipped:
		logger.WithError(err).Debug("Skipped ipcache map update on pod add")
	case err != nil:
		logger.WithError(err).Warning("Unable to update ipcache map entry on pod add ")
	default:
		logger.Debug("Updated ipcache map entry on pod add")
	}
}

func (d *Daemon) updateK8sPodV1(oldK8sPod, newK8sPod *v1.Pod) {
	if oldK8sPod == nil || newK8sPod == nil {
		return
	}

	// The pod IP can never change, it can only switch from unassigned to
	// assigned
	d.addK8sPodV1(newK8sPod)

	// We only care about label updates
	oldPodLabels := oldK8sPod.GetLabels()
	newPodLabels := newK8sPod.GetLabels()
	if comparator.MapStringEquals(oldPodLabels, newPodLabels) {
		return
	}

	podNSName := k8sUtils.GetObjNamespaceName(&newK8sPod.ObjectMeta)

	podEP := endpointmanager.LookupPodName(podNSName)
	if podEP == nil {
		log.WithField("pod", podNSName).Debugf("Endpoint not found running for the given pod")
		return
	}

	newLabels := labels.Map2Labels(newPodLabels, labels.LabelSourceK8s)
	newIdtyLabels, _ := labels.FilterLabels(newLabels)
	oldLabels := labels.Map2Labels(oldPodLabels, labels.LabelSourceK8s)
	oldIdtyLabels, _ := labels.FilterLabels(oldLabels)

	err := podEP.ModifyIdentityLabels(d, newIdtyLabels, oldIdtyLabels)
	if err != nil {
		log.WithError(err).Debugf("error while updating endpoint with new labels")
		return
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: podEP.GetID(),
		logfields.Labels:     logfields.Repr(newIdtyLabels),
	}).Debug("Update endpoint with new labels")
}

func (d *Daemon) deleteK8sPodV1(pod *v1.Pod) {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"hostIP":               pod.Status.HostIP,
	})

	skipped, err := d.deletePodHostIP(pod)
	switch {
	case skipped:
		logger.WithError(err).Debug("Skipped ipcache map delete on pod delete")
	case err != nil:
		logger.WithError(err).Warning("Unable to delete ipcache map entry on pod delete")
	default:
		logger.Debug("Deleted ipcache map entry on pod delete")
	}
}

func (d *Daemon) updateK8sV1Namespace(oldNS, newNS *v1.Namespace) {
	if oldNS == nil || newNS == nil {
		return
	}

	// We only care about label updates
	if comparator.MapStringEquals(oldNS.GetLabels(), newNS.GetLabels()) {
		return
	}

	oldNSLabels := map[string]string{}
	newNSLabels := map[string]string{}

	for k, v := range oldNS.GetLabels() {
		oldNSLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	for k, v := range newNS.GetLabels() {
		newNSLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}

	oldLabels := labels.Map2Labels(oldNSLabels, labels.LabelSourceK8s)
	newLabels := labels.Map2Labels(newNSLabels, labels.LabelSourceK8s)

	oldIdtyLabels, _ := labels.FilterLabels(oldLabels)
	newIdtyLabels, _ := labels.FilterLabels(newLabels)

	eps := endpointmanager.GetEndpoints()
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if oldNS.Name == epNS {
			err := ep.ModifyIdentityLabels(d, newIdtyLabels, oldIdtyLabels)
			if err != nil {
				log.WithError(err).WithField(logfields.EndpointID, ep.ID).
					Warningf("unable to update endpoint with new namespace labels")
			}

		}
	}
}

func (d *Daemon) updateK8sNodeTunneling(k8sNodeOld, k8sNodeNew *v1.Node) error {
	nodeNew := k8s.ParseNode(k8sNodeNew, node.FromKubernetes)
	// Ignore own node
	if nodeNew.Name == node.GetName() {
		return nil
	}

	getIDs := func(node *node.Node, k8sNode *v1.Node) (string, net.IP, error) {
		if node == nil {
			return "", nil, nil
		}
		hostIP := node.GetNodeIP(false)
		if ip4 := hostIP.To4(); ip4 == nil {
			return "", nil, fmt.Errorf("HostIP is not an IPv4 address: %s", hostIP)
		}

		ciliumIPStr := k8sNode.GetAnnotations()[annotation.CiliumHostIP]
		ciliumIP := net.ParseIP(ciliumIPStr)
		if ciliumIP == nil {
			return "", nil, fmt.Errorf("no/invalid Cilium-Host IP for host %s: %s", hostIP, ciliumIPStr)
		}

		return ciliumIPStr, hostIP, nil
	}

	ciliumIPStrNew, hostIPNew, err := getIDs(nodeNew, k8sNodeNew)
	if err != nil || ciliumIPStrNew == "" || hostIPNew == nil {
		return err
	}

	if k8sNodeOld != nil {
		nodeOld := k8s.ParseNode(k8sNodeOld, node.FromKubernetes)
		var (
			err            error
			ciliumIPStrOld string
		)
		ciliumIPStrOld, _, err = getIDs(nodeOld, k8sNodeOld)
		if err != nil {
			return err
		}

		// If the annotation of the node resource has changed, the old
		// ipcache has to be removed manually as Upsert() only handes
		// updates if the key itself is unchanged.
		if ciliumIPStrNew != ciliumIPStrOld {
			d.deleteK8sNodeV1(k8sNodeOld)
		}
	}

	selfOwned := ipcache.IPIdentityCache.Upsert(ciliumIPStrNew, hostIPNew, ipcache.Identity{
		ID:     identity.ReservedIdentityHost,
		Source: ipcache.FromKubernetes,
	})
	if !selfOwned {
		return fmt.Errorf("ipcache entry owned by kvstore or agent")
	}

	routeTypes := node.TunnelRoute

	// Add IPv6 routing only in non encap. With encap we do it with bpf tunnel
	// FIXME create a function to know on which mode is the daemon running on
	var ownAddr net.IP
	if option.Config.AutoIPv6NodeRoutes && option.Config.Device != "undefined" {
		ownAddr = node.GetIPv6()
		routeTypes |= node.DirectRoute
	}

	node.UpdateNode(nodeNew, routeTypes, ownAddr)

	return nil
}

func (d *Daemon) addK8sNodeV1(k8sNode *v1.Node) {
	if err := d.updateK8sNodeTunneling(nil, k8sNode); err != nil {
		log.WithError(err).Warning("Unable to add ipcache entry of Kubernetes node")
	}
}

func (d *Daemon) updateK8sNodeV1(k8sNodeOld, k8sNodeNew *v1.Node) {
	if err := d.updateK8sNodeTunneling(k8sNodeOld, k8sNodeNew); err != nil {
		log.WithError(err).Warning("Unable to update ipcache entry of Kubernetes node")
	}
}

func (d *Daemon) deleteK8sNodeV1(k8sNode *v1.Node) {
	ip := k8sNode.GetAnnotations()[annotation.CiliumHostIP]

	logger := log.WithFields(logrus.Fields{
		"K8sNodeName":    k8sNode.ObjectMeta.Name,
		logfields.IPAddr: ip,
	})

	ni := node.Identity{
		Name:    k8sNode.ObjectMeta.Name,
		Cluster: option.Config.ClusterName,
	}

	node.DeleteNode(ni, node.TunnelRoute|node.DirectRoute)

	id, exists := ipcache.IPIdentityCache.LookupByIP(ip)
	if !exists {
		logger.Warning("identity for Cilium IP not found")
		return
	}

	// The ipcache entry ownership may have been taken over by a kvstore
	// based entry in which case we should ignore the delete event and wait
	// for the kvstore delete event.
	if id.Source != ipcache.FromKubernetes {
		logger.Debug("ipcache entry for Cilium IP no longer owned by Kubernetes")
		return
	}

	ipcache.IPIdentityCache.Delete(ip)

	ciliumIP := net.ParseIP(ip)
	if ciliumIP == nil {
		logger.Warning("Unable to parse Cilium IP")
		return
	}
}
