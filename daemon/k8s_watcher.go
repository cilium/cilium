// Copyright 2016-2019 Authors of Cilium
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
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfIPCache "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	k8s_metrics "k8s.io/client-go/tools/metrics"
)

const (
	k8sAPIGroupCRD              = "CustomResourceDefinition"
	k8sAPIGroupNodeV1Core       = "core/v1::Node"
	k8sAPIGroupNamespaceV1Core  = "core/v1::Namespace"
	k8sAPIGroupServiceV1Core    = "core/v1::Service"
	k8sAPIGroupEndpointV1Core   = "core/v1::Endpoint"
	k8sAPIGroupPodV1Core        = "core/v1::Pods"
	k8sAPIGroupNetworkingV1Core = "networking.k8s.io/v1::NetworkPolicy"
	k8sAPIGroupIngressV1Beta1   = "extensions/v1beta1::Ingress"
	k8sAPIGroupCiliumV2         = "cilium/v2::CiliumNetworkPolicy"
	cacheSyncTimeout            = time.Duration(3 * time.Minute)

	metricCNP      = "CiliumNetworkPolicy"
	metricEndpoint = "Endpoint"
	metricIngress  = "Ingress"
	metricKNP      = "NetworkPolicy"
	metricNS       = "Namespace"
	metricNode     = "Node"
	metricPod      = "Pod"
	metricService  = "Service"
	metricCreate   = "create"
	metricDelete   = "delete"
	metricUpdate   = "update"
)

var (
	k8sCM = controller.NewManager()

	importMetadataCache = ruleImportMetadataCache{
		ruleImportMetadataMap: make(map[string]policyImportMetadata),
	}

	// local cache of Kubernetes Endpoints which relate to external services.
	endpointMetadataCache = endpointImportMetadataCache{
		endpointImportMetadataMap: make(map[string]endpointImportMetadata),
	}
)

// ruleImportMetadataCache maps the unique identifier of a CiliumNetworkPolicy
// (namespace and name) to metadata about the importing of the rule into the
// agent's policy repository at the time said rule was imported (revision
// number, and if any error occurred while importing).
type ruleImportMetadataCache struct {
	mutex                 lock.RWMutex
	ruleImportMetadataMap map[string]policyImportMetadata
}

type policyImportMetadata struct {
	revision          uint64
	policyImportError error
}

func (r *ruleImportMetadataCache) upsert(cnp *types.SlimCNP, revision uint64, importErr error) {
	if cnp == nil {
		return
	}

	meta := policyImportMetadata{
		revision:          revision,
		policyImportError: importErr,
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)

	r.mutex.Lock()
	r.ruleImportMetadataMap[podNSName] = meta
	r.mutex.Unlock()
}

func (r *ruleImportMetadataCache) delete(cnp *types.SlimCNP) {
	if cnp == nil {
		return
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)

	r.mutex.Lock()
	delete(r.ruleImportMetadataMap, podNSName)
	r.mutex.Unlock()
}

func (r *ruleImportMetadataCache) get(cnp *types.SlimCNP) (policyImportMetadata, bool) {
	if cnp == nil {
		return policyImportMetadata{}, false
	}
	podNSName := k8sUtils.GetObjNamespaceName(&cnp.ObjectMeta)
	r.mutex.RLock()
	policyImportMeta, ok := r.ruleImportMetadataMap[podNSName]
	r.mutex.RUnlock()
	return policyImportMeta, ok
}

// endpointImportMetadataCache maps the unique identifier of a Kubernetes
// Endpoint (namespace and name) to metadata about whether translation of the
// rules involving services that the endpoint corresponds to into the
// agent's policy repository at the time said rule was imported (if any error
// occurred while importing).
type endpointImportMetadataCache struct {
	mutex                     lock.RWMutex
	endpointImportMetadataMap map[string]endpointImportMetadata
}

type endpointImportMetadata struct {
	ruleTranslationError error
}

func (r *endpointImportMetadataCache) upsert(id k8s.ServiceID, ruleTranslationErr error) {
	meta := endpointImportMetadata{
		ruleTranslationError: ruleTranslationErr,
	}

	r.mutex.Lock()
	r.endpointImportMetadataMap[id.String()] = meta
	r.mutex.Unlock()
}

func (r *endpointImportMetadataCache) delete(id k8s.ServiceID) {
	r.mutex.Lock()
	delete(r.endpointImportMetadataMap, id.String())
	r.mutex.Unlock()
}

func (r *endpointImportMetadataCache) get(id k8s.ServiceID) (endpointImportMetadata, bool) {
	r.mutex.RLock()
	endpointImportMeta, ok := r.endpointImportMetadataMap[id.String()]
	r.mutex.RUnlock()
	return endpointImportMeta, ok
}

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

// k8sMetrics implements the LatencyMetric and ResultMetric interface from
// k8s client-go package
type k8sMetrics struct{}

func (*k8sMetrics) Observe(verb string, u url.URL, latency time.Duration) {
	if option.Config.IsSubsysMetricEnabled(metrics.SubsystemK8sClientMask) {
		metrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
	}
}

func (*k8sMetrics) Increment(code string, method string, host string) {
	if option.Config.IsSubsysMetricEnabled(metrics.SubsystemK8sClientMask) {
		metrics.KubernetesAPICalls.WithLabelValues(host, method, code).Inc()
	}
	k8smetrics.LastInteraction.Reset()
}

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}

	k8sMetric := &k8sMetrics{}
	k8s_metrics.Register(k8sMetric, k8sMetric)
}

// blockWaitGroupToSyncResources ensures that anything which waits on waitGroup
// waits until all objects of the specified resource stored in Kubernetes are
// received by the informer and processed by controller.
// Fatally exits if syncing these initial objects fails.
// If the given stop channel is closed, it does not fatal.
func (d *Daemon) blockWaitGroupToSyncResources(stop <-chan struct{}, informer cache.Controller, resourceName string) {
	ch := make(chan struct{})
	d.k8sResourceSyncedMu.Lock()
	d.k8sResourceSynced[resourceName] = ch
	d.k8sResourceSyncedMu.Unlock()
	go func() {
		scopedLog := log.WithField("kubernetesResource", resourceName)
		scopedLog.Debug("waiting for cache to synchronize")
		if ok := cache.WaitForCacheSync(stop, informer.HasSynced); !ok {
			select {
			case <-stop:
				scopedLog.Debug("canceled cache synchronization")
				// do not fatal if the channel was stopped
			default:
				// Fatally exit it resource fails to sync
				scopedLog.Fatalf("failed to wait for cache to sync")
			}
		} else {
			scopedLog.Debug("cache synced")
		}
		close(ch)
	}()
}

// waitForCacheSync waits for k8s caches to be synchronized for the given
// resource. Returns once all resourcesNames are synchronized with cilium-agent.
func (d *Daemon) waitForCacheSync(resourceNames ...string) {
	for _, resourceName := range resourceNames {
		d.k8sResourceSyncedMu.RLock()
		c, ok := d.k8sResourceSynced[resourceName]
		d.k8sResourceSyncedMu.RUnlock()
		if !ok {
			continue
		}
		<-c
	}
}

// initK8sSubsystem returns a channel for which it will be closed when all
// caches essential for daemon are synchronized.
func (d *Daemon) initK8sSubsystem() <-chan struct{} {
	if err := d.EnableK8sWatcher(option.Config.K8sWatcherQueueSize); err != nil {
		log.WithError(err).Fatal("Unable to establish connection to Kubernetes apiserver")
	}

	cachesSynced := make(chan struct{})

	go func() {
		log.Info("Waiting until all pre-existing resources related to policy have been received")
		// Wait only for certain caches, but not all!
		// We don't wait for nodes synchronization nor ingresses.
		d.waitForCacheSync(
			// To perform the service translation and have the BPF LB datapath
			// with the right service -> backend (k8s endpoints) translation.
			k8sAPIGroupServiceV1Core,
			// To perform the service translation and have the BPF LB datapath
			// with the right service -> backend (k8s endpoints) translation.
			k8sAPIGroupEndpointV1Core,
			// We need all network policies in place before restoring to make sure
			// we are enforcing the correct policies for each endpoint before
			// restarting.
			k8sAPIGroupCiliumV2,
			// We need all network policies in place before restoring to make sure
			// we are enforcing the correct policies for each endpoint before
			// restarting.
			k8sAPIGroupNetworkingV1Core,
			// Namespaces can contain labels which are essential for endpoints
			// being restored to have the right identity.
			k8sAPIGroupNamespaceV1Core,
			// Pods can contain labels which are essential for endpoints
			// being restored to have the right identity.
			k8sAPIGroupPodV1Core,
		)
		close(cachesSynced)
	}()

	go func() {
		select {
		case <-cachesSynced:
			log.Info("All pre-existing resources related to policy have been received; continuing")
		case <-time.After(cacheSyncTimeout):
			log.Fatalf("Timed out waiting for pre-existing resources related to policy to be received; exiting")
		}
	}()

	return cachesSynced
}

func (d *Daemon) k8sEventReceived(scope string, action string, valid, equal bool) {
	metrics.EventTSK8s.SetToCurrentTime()
	k8smetrics.LastInteraction.Reset()

	metrics.KubernetesEventReceived.WithLabelValues(scope, action, strconv.FormatBool(valid), strconv.FormatBool(equal)).Inc()
}

// EnableK8sWatcher watches for policy, services and endpoint changes on the Kubernetes
// api server defined in the receiver's daemon k8sClient.
// queueSize specifies the queue length used to serialize k8s events.
func (d *Daemon) EnableK8sWatcher(queueSize uint) error {
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

	err = cilium_v2.CreateCustomResourceDefinitions(apiextensionsclientset)
	if err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %s", err)
	}
	d.k8sAPIGroups.addAPI(k8sAPIGroupCRD)

	ciliumNPClient := k8s.CiliumClient()

	serKNPs := serializer.NewFunctionQueue(queueSize)
	serSvcs := serializer.NewFunctionQueue(queueSize)
	serEps := serializer.NewFunctionQueue(queueSize)
	serIngresses := serializer.NewFunctionQueue(queueSize)
	serCNPs := serializer.NewFunctionQueue(queueSize)
	serPods := serializer.NewFunctionQueue(queueSize)
	serNodes := serializer.NewFunctionQueue(queueSize)
	serNamespaces := serializer.NewFunctionQueue(queueSize)

	_, policyController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().NetworkingV1().RESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&networkingv1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricKNP, metricCreate, valid, equal) }()
				if k8sNP := k8s.CopyObjToV1NetworkPolicy(obj); k8sNP != nil {
					valid = true
					serKNPs.Enqueue(func() error {
						err := d.addK8sNetworkPolicyV1(k8sNP)
						updateK8sEventMetric(metricKNP, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricKNP, metricUpdate, valid, equal) }()
				if oldK8sNP := k8s.CopyObjToV1NetworkPolicy(oldObj); oldK8sNP != nil {
					valid = true
					if newK8sNP := k8s.CopyObjToV1NetworkPolicy(newObj); newK8sNP != nil {
						if k8s.EqualV1NetworkPolicy(oldK8sNP, newK8sNP) {
							equal = true
							return
						}

						serKNPs.Enqueue(func() error {
							err := d.updateK8sNetworkPolicyV1(oldK8sNP, newK8sNP)
							updateK8sEventMetric(metricKNP, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricKNP, metricDelete, valid, equal) }()
				k8sNP := k8s.CopyObjToV1NetworkPolicy(obj)
				if k8sNP == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sNP = k8s.CopyObjToV1NetworkPolicy(deletedObj.Obj)
					if k8sNP == nil {
						return
					}
				}

				valid = true
				serKNPs.Enqueue(func() error {
					err := d.deleteK8sNetworkPolicyV1(k8sNP)
					updateK8sEventMetric(metricKNP, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToNetworkPolicy,
	)
	d.blockWaitGroupToSyncResources(wait.NeverStop, policyController, k8sAPIGroupNetworkingV1Core)
	go policyController.Run(wait.NeverStop)

	d.k8sAPIGroups.addAPI(k8sAPIGroupNetworkingV1Core)

	_, svcController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricService, metricCreate, valid, equal) }()
				if k8sSvc := k8s.CopyObjToV1Services(obj); k8sSvc != nil {
					valid = true
					serSvcs.Enqueue(func() error {
						err := d.addK8sServiceV1(k8sSvc)
						updateK8sEventMetric(metricService, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricService, metricUpdate, valid, equal) }()
				if oldk8sSvc := k8s.CopyObjToV1Services(oldObj); oldk8sSvc != nil {
					valid = true
					if newk8sSvc := k8s.CopyObjToV1Services(newObj); newk8sSvc != nil {
						if k8s.EqualV1Services(oldk8sSvc, newk8sSvc) {
							equal = true
							return
						}

						serSvcs.Enqueue(func() error {
							err := d.updateK8sServiceV1(oldk8sSvc, newk8sSvc)
							updateK8sEventMetric(metricService, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricService, metricDelete, valid, equal) }()
				k8sSvc := k8s.CopyObjToV1Services(obj)
				if k8sSvc == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sSvc = k8s.CopyObjToV1Services(deletedObj.Obj)
					if k8sSvc == nil {
						return
					}
				}

				valid = true
				serSvcs.Enqueue(func() error {
					err := d.deleteK8sServiceV1(k8sSvc)
					updateK8sEventMetric(metricService, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToK8sService,
	)
	d.blockWaitGroupToSyncResources(wait.NeverStop, svcController, k8sAPIGroupServiceV1Core)
	go svcController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupServiceV1Core)

	_, endpointController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"endpoints", v1.NamespaceAll,
			fields.ParseSelectorOrDie(option.Config.K8sWatcherEndpointSelector),
		),
		&v1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricEndpoint, metricCreate, valid, equal) }()
				if k8sEP := k8s.CopyObjToV1Endpoints(obj); k8sEP != nil {
					valid = true
					serEps.Enqueue(func() error {
						err := d.addK8sEndpointV1(k8sEP)
						updateK8sEventMetric(metricEndpoint, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricEndpoint, metricUpdate, valid, equal) }()
				if oldk8sEP := k8s.CopyObjToV1Endpoints(oldObj); oldk8sEP != nil {
					valid = true
					if newk8sEP := k8s.CopyObjToV1Endpoints(newObj); newk8sEP != nil {
						if k8s.EqualV1Endpoints(oldk8sEP, newk8sEP) {
							equal = true
							return
						}

						serEps.Enqueue(func() error {
							err := d.updateK8sEndpointV1(oldk8sEP, newk8sEP)
							updateK8sEventMetric(metricEndpoint, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricEndpoint, metricDelete, valid, equal) }()
				k8sEP := k8s.CopyObjToV1Endpoints(obj)
				if k8sEP == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					k8sEP = k8s.CopyObjToV1Endpoints(deletedObj.Obj)
					if k8sEP == nil {
						return
					}
				}
				valid = true
				serEps.Enqueue(func() error {
					err := d.deleteK8sEndpointV1(k8sEP)
					updateK8sEventMetric(metricEndpoint, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		k8s.ConvertToK8sEndpoints,
	)
	d.blockWaitGroupToSyncResources(wait.NeverStop, endpointController, k8sAPIGroupEndpointV1Core)
	go endpointController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupEndpointV1Core)

	if option.Config.IsLBEnabled() {
		_, ingressController := informer.NewInformer(
			cache.NewListWatchFromClient(k8s.Client().ExtensionsV1beta1().RESTClient(),
				"ingresses", v1.NamespaceAll, fields.Everything()),
			&v1beta1.Ingress{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { d.k8sEventReceived(metricEndpoint, metricCreate, valid, equal) }()
					if k8sIngress := k8s.CopyObjToV1beta1Ingress(obj); k8sIngress != nil {
						valid = true
						serIngresses.Enqueue(func() error {
							err := d.addIngressV1beta1(k8sIngress)
							updateK8sEventMetric(metricIngress, metricCreate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { d.k8sEventReceived(metricEndpoint, metricUpdate, valid, equal) }()
					if oldk8sIngress := k8s.CopyObjToV1beta1Ingress(oldObj); oldk8sIngress != nil {
						valid = true
						if newk8sIngress := k8s.CopyObjToV1beta1Ingress(newObj); newk8sIngress != nil {
							if k8s.EqualV1beta1Ingress(oldk8sIngress, newk8sIngress) {
								equal = true
								return
							}

							serIngresses.Enqueue(func() error {
								err := d.updateIngressV1beta1(oldk8sIngress, newk8sIngress)
								updateK8sEventMetric(metricIngress, metricUpdate, err == nil)
								return nil
							}, serializer.NoRetry)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { d.k8sEventReceived(metricEndpoint, metricDelete, valid, equal) }()
					k8sIngress := k8s.CopyObjToV1beta1Ingress(obj)
					if k8sIngress == nil {
						deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
						if !ok {
							return
						}
						// Delete was not observed by the watcher but is
						// removed from kube-apiserver. This is the last
						// known state and the object no longer exists.
						k8sIngress = k8s.CopyObjToV1beta1Ingress(deletedObj.Obj)
						if k8sIngress == nil {
							return
						}
					}
					valid = true
					serEps.Enqueue(func() error {
						err := d.deleteIngressV1beta1(k8sIngress)
						updateK8sEventMetric(metricIngress, metricDelete, err == nil)
						return nil
					}, serializer.NoRetry)
				},
			},
			k8s.ConvertToIngress,
		)
		d.blockWaitGroupToSyncResources(wait.NeverStop, ingressController, k8sAPIGroupIngressV1Beta1)
		go ingressController.Run(wait.NeverStop)
		d.k8sAPIGroups.addAPI(k8sAPIGroupIngressV1Beta1)
	}

	var (
		cnpEventStore    cache.Store
		cnpConverterFunc informer.ConvertFunc
	)
	cnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	switch {
	case k8sversion.Capabilities().Patch:
		// k8s >= 1.13 does not require a store to update CNP status so
		// we don't even need to keep the status of a CNP with us.
		cnpConverterFunc = k8s.ConvertToCNP
	default:
		cnpEventStore = cnpStore
		cnpConverterFunc = k8s.ConvertToCNPWithStatus
	}

	ciliumV2Controller := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			"ciliumnetworkpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricCNP, metricCreate, valid, equal) }()
				if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
					valid = true
					serCNPs.Enqueue(func() error {
						if cnp.RequiresDerivative() {
							return nil
						}
						err := d.addCiliumNetworkPolicyV2(ciliumNPClient, cnpEventStore, cnp)
						updateK8sEventMetric(metricCNP, metricCreate, err == nil)
						return nil
					}, serializer.NoRetry)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricCNP, metricUpdate, valid, equal) }()
				if oldCNP := k8s.CopyObjToV2CNP(oldObj); oldCNP != nil {
					valid = true
					if newCNP := k8s.CopyObjToV2CNP(newObj); newCNP != nil {
						if k8s.EqualV2CNP(oldCNP, newCNP) {
							equal = true
							return
						}

						serCNPs.Enqueue(func() error {
							if newCNP.RequiresDerivative() {
								return nil
							}

							err := d.updateCiliumNetworkPolicyV2(ciliumNPClient, cnpEventStore, oldCNP, newCNP)
							updateK8sEventMetric(metricCNP, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricCNP, metricDelete, valid, equal) }()
				cnp := k8s.CopyObjToV2CNP(obj)
				if cnp == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					cnp = k8s.CopyObjToV2CNP(deletedObj.Obj)
					if cnp == nil {
						return
					}
				}
				valid = true
				serCNPs.Enqueue(func() error {
					err := d.deleteCiliumNetworkPolicyV2(cnp)
					updateK8sEventMetric(metricCNP, metricDelete, err == nil)
					return nil
				}, serializer.NoRetry)
			},
		},
		cnpConverterFunc,
		cnpStore,
	)
	d.blockWaitGroupToSyncResources(wait.NeverStop, ciliumV2Controller, k8sAPIGroupCiliumV2)
	go ciliumV2Controller.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupCiliumV2)

	asyncControllers := sync.WaitGroup{}
	asyncControllers.Add(1)
	go func() {
		var once sync.Once
		for {
			createPodController := func(fieldSelector fields.Selector) cache.Controller {
				_, podController := informer.NewInformer(
					cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
						"pods", v1.NamespaceAll, fieldSelector),
					&v1.Pod{},
					0,
					cache.ResourceEventHandlerFuncs{
						AddFunc: func(obj interface{}) {
							var valid, equal bool
							defer func() { d.k8sEventReceived(metricPod, metricCreate, valid, equal) }()
							if pod := k8s.CopyObjToV1Pod(obj); pod != nil {
								valid = true
								serPods.Enqueue(func() error {
									err := d.addK8sPodV1(pod)
									updateK8sEventMetric(metricPod, metricCreate, err == nil)
									return nil
								}, serializer.NoRetry)
							}
						},
						UpdateFunc: func(oldObj, newObj interface{}) {
							var valid, equal bool
							defer func() { d.k8sEventReceived(metricPod, metricUpdate, valid, equal) }()
							if oldPod := k8s.CopyObjToV1Pod(oldObj); oldPod != nil {
								valid = true
								if newPod := k8s.CopyObjToV1Pod(newObj); newPod != nil {
									if k8s.EqualV1Pod(oldPod, newPod) {
										equal = true
										return
									}

									serPods.Enqueue(func() error {
										err := d.updateK8sPodV1(oldPod, newPod)
										updateK8sEventMetric(metricPod, metricUpdate, err == nil)
										return nil
									}, serializer.NoRetry)
								}
							}
						},
						DeleteFunc: func(obj interface{}) {
							var valid, equal bool
							defer func() { d.k8sEventReceived(metricPod, metricDelete, valid, equal) }()
							if pod := k8s.CopyObjToV1Pod(obj); pod != nil {
								valid = true
								serPods.Enqueue(func() error {
									err := d.deleteK8sPodV1(pod)
									updateK8sEventMetric(metricPod, metricDelete, err == nil)
									return nil
								}, serializer.NoRetry)
							}
						},
					},
					k8s.ConvertToPod,
				)
				return podController
			}
			podController := createPodController(fields.Everything())

			isConnected := make(chan struct{})
			// once isConnected is closed, it will stop waiting on caches to be
			// synchronized.
			d.blockWaitGroupToSyncResources(isConnected, podController, k8sAPIGroupPodV1Core)
			once.Do(func() {
				asyncControllers.Done()
				d.k8sAPIGroups.addAPI(k8sAPIGroupPodV1Core)
			})
			go podController.Run(isConnected)

			if !option.Config.K8sEventHandover {
				return
			}

			// Replace pod controller by only receiving events from our own
			// node once we are connected to the kvstore.

			<-kvstore.Client().Connected()
			close(isConnected)

			log.WithField(logfields.Node, node.GetName()).Info("Connected to KVStore, watching for pod events on node")
			// Only watch for pod events for our node.
			podController = createPodController(fields.ParseSelectorOrDie("spec.nodeName=" + node.GetName()))
			isConnected = make(chan struct{})
			go podController.Run(isConnected)

			// Create a new pod controller when we are disconnected with the
			// kvstore
			<-kvstore.Client().Disconnected()
			close(isConnected)
			log.Info("Disconnected from KVStore, watching for pod events all nodes")
		}
	}()

	asyncControllers.Add(1)
	go func() {
		var once sync.Once
		for {
			_, nodeController := informer.NewInformer(
				cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
					"nodes", v1.NamespaceAll, fields.Everything()),
				&v1.Node{},
				0,
				cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						var valid, equal bool
						defer func() { d.k8sEventReceived(metricNode, metricCreate, valid, equal) }()
						if Node := k8s.CopyObjToV1Node(obj); Node != nil {
							valid = true
							serNodes.Enqueue(func() error {
								err := d.addK8sNodeV1(Node)
								updateK8sEventMetric(metricNode, metricCreate, err == nil)
								return nil
							}, serializer.NoRetry)
						}
					},
					UpdateFunc: func(oldObj, newObj interface{}) {
						var valid, equal bool
						defer func() { d.k8sEventReceived(metricNode, metricUpdate, valid, equal) }()
						if oldNode := k8s.CopyObjToV1Node(oldObj); oldNode != nil {
							valid = true
							if newNode := k8s.CopyObjToV1Node(newObj); newNode != nil {
								if k8s.EqualV1Node(oldNode, newNode) {
									equal = true
									return
								}

								serNodes.Enqueue(func() error {
									err := d.updateK8sNodeV1(oldNode, newNode)
									updateK8sEventMetric(metricNode, metricUpdate, err == nil)
									return nil
								}, serializer.NoRetry)
							}
						}
					},
					DeleteFunc: func(obj interface{}) {
						var valid, equal bool
						defer func() { d.k8sEventReceived(metricNode, metricDelete, valid, equal) }()
						node := k8s.CopyObjToV1Node(obj)
						if node == nil {
							deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
							if !ok {
								return
							}
							// Delete was not observed by the watcher but is
							// removed from kube-apiserver. This is the last
							// known state and the object no longer exists.
							node = k8s.CopyObjToV1Node(deletedObj.Obj)
							if node == nil {
								return
							}
						}
						valid = true
						serNodes.Enqueue(func() error {
							err := d.deleteK8sNodeV1(node)
							updateK8sEventMetric(metricNode, metricDelete, err == nil)
							return nil
						}, serializer.NoRetry)
					},
				},
				k8s.ConvertToNode,
			)
			isConnected := make(chan struct{})
			// once isConnected is closed, it will stop waiting on caches to be
			// synchronized.
			d.blockWaitGroupToSyncResources(isConnected, nodeController, k8sAPIGroupNodeV1Core)

			once.Do(func() {
				// Signalize that we have put node controller in the wait group
				// to sync resources.
				asyncControllers.Done()
			})
			d.k8sAPIGroups.addAPI(k8sAPIGroupNodeV1Core)
			go nodeController.Run(isConnected)
			// TODO: do we really need to wait until etcd watcher signalizes
			// "listDone" or connected to it is sufficient?

			if !option.Config.K8sEventHandover {
				return
			}

			<-kvstore.Client().Connected()
			close(isConnected)

			log.Info("Connected to KVStore, stopping k8s node watcher")

			d.k8sAPIGroups.removeAPI(k8sAPIGroupNodeV1Core)
			// Create a new node controller when we are disconnected with the
			// kvstore
			<-kvstore.Client().Disconnected()

			log.Info("Disconnected from KVStore, restarting k8s node watcher")
		}
	}()

	_, namespaceController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.Client().CoreV1().RESTClient(),
			"namespaces", v1.NamespaceAll, fields.Everything()),
		&v1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			// AddFunc does not matter since the endpoint will fetch
			// namespace labels when the endpoint is created
			// DelFunc does not matter since, when a namespace is deleted, all
			// pods belonging to that namespace are also deleted.
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { d.k8sEventReceived(metricNS, metricUpdate, valid, equal) }()
				if oldNS := k8s.CopyObjToV1Namespace(oldObj); oldNS != nil {
					valid = true
					if newNS := k8s.CopyObjToV1Namespace(newObj); newNS != nil {
						if k8s.EqualV1Namespace(oldNS, newNS) {
							equal = true
							return
						}

						serNamespaces.Enqueue(func() error {
							err := d.updateK8sV1Namespace(oldNS, newNS)
							updateK8sEventMetric(metricNS, metricUpdate, err == nil)
							return nil
						}, serializer.NoRetry)
					}
				}
			},
		},
		k8s.ConvertToNamespace,
	)

	go namespaceController.Run(wait.NeverStop)
	d.k8sAPIGroups.addAPI(k8sAPIGroupNamespaceV1Core)

	asyncControllers.Wait()

	return nil
}

func (d *Daemon) addK8sNetworkPolicyV1(k8sNP *types.NetworkPolicy) error {
	scopedLog := log.WithField(logfields.K8sAPIVersion, k8sNP.TypeMeta.APIVersion)
	rules, err := k8s.ParseNetworkPolicy(k8sNP.NetworkPolicy)
	if err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(k8sNP),
		}).Error("Error while parsing k8s kubernetes NetworkPolicy")
		return err
	}
	scopedLog = scopedLog.WithField(logfields.K8sNetworkPolicyName, k8sNP.ObjectMeta.Name)

	opts := AddOptions{Replace: true, Source: metrics.LabelEventSourceK8s}
	if _, err := d.PolicyAdd(rules, &opts); err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicy: logfields.Repr(rules),
		}).Error("Unable to add NetworkPolicy rules to policy repository")
		return err
	}

	scopedLog.Info("NetworkPolicy successfully added")
	return nil
}

func (d *Daemon) updateK8sNetworkPolicyV1(oldk8sNP, newk8sNP *types.NetworkPolicy) error {
	log.WithFields(logrus.Fields{
		logfields.K8sAPIVersion:                 oldk8sNP.TypeMeta.APIVersion,
		logfields.K8sNetworkPolicyName + ".old": oldk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace + ".old":         oldk8sNP.ObjectMeta.Namespace,
		logfields.K8sNetworkPolicyName:          newk8sNP.ObjectMeta.Name,
		logfields.K8sNamespace:                  newk8sNP.ObjectMeta.Namespace,
	}).Debug("Received policy update")

	return d.addK8sNetworkPolicyV1(newk8sNP)
}

func (d *Daemon) deleteK8sNetworkPolicyV1(k8sNP *types.NetworkPolicy) error {
	labels := k8s.GetPolicyLabelsv1(k8sNP.NetworkPolicy)

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
		return err
	}

	scopedLog.Info("NetworkPolicy successfully removed")
	return nil
}

func (d *Daemon) k8sServiceHandler() {
	for {
		event, ok := <-d.k8sSvcCache.Events
		if !ok {
			return
		}

		svc := event.Service

		scopedLog := log.WithFields(logrus.Fields{
			logfields.K8sSvcName:   event.ID.Name,
			logfields.K8sNamespace: event.ID.Namespace,
		})

		scopedLog.WithFields(logrus.Fields{
			"action":    event.Action.String(),
			"service":   event.Service.String(),
			"endpoints": event.Endpoints.String(),
		}).Debug("Kubernetes service definition changed")

		switch event.Action {
		case k8s.UpdateService, k8s.UpdateIngress:
			if err := d.addK8sSVCs(event.ID, svc, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to add/update service to implement k8s event")
			}

			if !svc.IsExternal() {
				continue
			}

			serviceImportMeta, cacheOK := endpointMetadataCache.get(event.ID)

			// If this is the first time adding this Endpoint, or there was an error
			// adding it last time, then try to add translate it and its
			// corresponding external service for any toServices rules which
			// select said service.
			if !cacheOK || (cacheOK && serviceImportMeta.ruleTranslationError != nil) {
				translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, false, svc.Labels, bpfIPCache.IPCache)
				result, err := d.policy.TranslateRules(translator)
				endpointMetadataCache.upsert(event.ID, err)
				if err != nil {
					log.Errorf("Unable to repopulate egress policies from ToService rules: %v", err)
					break
				} else if result.NumToServicesRules > 0 {
					// Only trigger policy updates if ToServices rules are in effect
					d.TriggerPolicyUpdates(true, "Kubernetes service endpoint added")
				}
			} else if serviceImportMeta.ruleTranslationError == nil {
				d.TriggerPolicyUpdates(true, "Kubernetes service endpoint updated")
			}

		case k8s.DeleteService, k8s.DeleteIngress:
			if err := d.delK8sSVCs(event.ID, event.Service, event.Endpoints); err != nil {
				scopedLog.WithError(err).Error("Unable to delete service to implement k8s event")
			}

			if !svc.IsExternal() {
				continue
			}

			endpointMetadataCache.delete(event.ID)

			translator := k8s.NewK8sTranslator(event.ID, *event.Endpoints, true, svc.Labels, bpfIPCache.IPCache)
			result, err := d.policy.TranslateRules(translator)
			if err != nil {
				log.Errorf("Unable to depopulate egress policies from ToService rules: %v", err)
				break
			} else if result.NumToServicesRules > 0 {
				// Only trigger policy updates if ToServices rules are in effect
				d.TriggerPolicyUpdates(true, "Kubernetes service endpoint deleted")
			}
		}
	}
}

func (d *Daemon) runK8sServiceHandler() {
	go d.k8sServiceHandler()
}

func (d *Daemon) addK8sServiceV1(svc *types.Service) error {
	d.k8sSvcCache.UpdateService(svc)
	return nil
}

func (d *Daemon) updateK8sServiceV1(oldSvc, newSvc *types.Service) error {
	return d.addK8sServiceV1(newSvc)
}

func (d *Daemon) deleteK8sServiceV1(svc *types.Service) error {
	d.k8sSvcCache.DeleteService(svc)
	return nil
}

func (d *Daemon) addK8sEndpointV1(ep *types.Endpoints) error {
	d.k8sSvcCache.UpdateEndpoints(ep)
	return nil
}

func (d *Daemon) updateK8sEndpointV1(oldEP, newEP *types.Endpoints) error {
	d.k8sSvcCache.UpdateEndpoints(newEP)
	return nil
}

func (d *Daemon) deleteK8sEndpointV1(ep *types.Endpoints) error {
	d.k8sSvcCache.DeleteEndpoints(ep)
	return nil
}

func (d *Daemon) delK8sSVCs(svc k8s.ServiceID, svcInfo *k8s.Service, se *k8s.Endpoints) error {
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if option.Config.DisableK8sServices {
		return nil
	}

	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	})

	repPorts := svcInfo.UniquePorts()

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

		fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, svcInfo.FrontendIP, svcPort.Port)
		if err := d.svcDeleteByFrontend(fe); err != nil {
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(fe)).
				Warn("Error deleting service by frontend")

		} else {
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", svcInfo.FrontendIP, svcPort.Port)
		}

		if err := d.RevNATDelete(svcPort.ID); err != nil {
			scopedLog.WithError(err).WithField(logfields.ServiceID, svcPort.ID).Warn("Error deleting reverse NAT")
		} else {
			scopedLog.Debugf("# cilium lb delete-rev-nat %d", svcPort.ID)
		}
	}
	return nil
}

func (d *Daemon) addK8sSVCs(svcID k8s.ServiceID, svc *k8s.Service, endpoints *k8s.Endpoints) error {
	// If east-west load balancing is disabled, we should not sync(add or delete)
	// K8s service to a cilium service.
	if option.Config.DisableK8sServices {
		return nil
	}

	// Headless services do not need any datapath implementation
	if svc.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})

	uniqPorts := svc.UniquePorts()

	for fePortName, fePort := range svc.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}

		uniqPorts[fePort.Port] = false

		if fePort.ID == 0 {
			feAddr := loadbalancer.NewL3n4Addr(fePort.Protocol, svc.FrontendIP, fePort.Port)
			feAddrID, err := service.AcquireID(*feAddr, 0)
			if err != nil {
				scopedLog.WithError(err).WithFields(logrus.Fields{
					logfields.ServiceID: fePortName,
					logfields.IPAddr:    svc.FrontendIP,
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
			fePort.ID = loadbalancer.ServiceID(feAddrID.ID)
		}

		besValues := []loadbalancer.LBBackEnd{}
		for ip, portConfiguration := range endpoints.Backends {
			if backendPort := portConfiguration[string(fePortName)]; backendPort != nil {
				besValues = append(besValues, loadbalancer.LBBackEnd{
					L3n4Addr: loadbalancer.L3n4Addr{IP: net.ParseIP(ip), L4Addr: *backendPort},
					Weight:   0,
				})
			}
		}

		fe := loadbalancer.NewL3n4AddrID(fePort.Protocol, svc.FrontendIP, fePort.Port,
			loadbalancer.ID(fePort.ID))
		if _, err := d.svcAdd(*fe, besValues, true); err != nil {
			scopedLog.WithError(err).Error("Error while inserting service in LB map")
		}
	}
	return nil
}

func (d *Daemon) addIngressV1beta1(ingress *types.Ingress) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sIngressName: ingress.ObjectMeta.Name,
		logfields.K8sAPIVersion:  ingress.TypeMeta.APIVersion,
		logfields.K8sNamespace:   ingress.ObjectMeta.Namespace,
	})
	scopedLog.Info("Kubernetes ingress added")

	var host net.IP
	switch {
	case option.Config.EnableIPv4:
		host = option.Config.HostV4Addr
	case option.Config.EnableIPv6:
		host = option.Config.HostV6Addr
	default:
		return fmt.Errorf("either IPv4 or IPv6 must be enabled")
	}

	_, err := d.k8sSvcCache.UpdateIngress(ingress, host)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	dpyCopyIngress := ingress.DeepCopy()
	dpyCopyIngress.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
		{
			IP:       host.String(),
			Hostname: hostname,
		},
	}

	_, err = k8s.Client().ExtensionsV1beta1().Ingresses(dpyCopyIngress.ObjectMeta.Namespace).UpdateStatus(dpyCopyIngress.Ingress)
	if err != nil {
		scopedLog.WithError(err).WithFields(logrus.Fields{
			logfields.K8sIngress: dpyCopyIngress,
		}).Error("Unable to update status of ingress")
	}
	return err
}

func (d *Daemon) updateIngressV1beta1(oldIngress, newIngress *types.Ingress) error {
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
		return nil
	}

	// Add RevNAT to the BPF Map for non-LB nodes when a LB node update the
	// ingress status with its address.
	if !option.Config.IsLBEnabled() {
		port := newIngress.Spec.Backend.ServicePort.IntValue()
		for _, lb := range newIngress.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(lb.IP)
			if ingressIP == nil {
				continue
			}
			feAddr := loadbalancer.NewL3n4Addr(loadbalancer.TCP, ingressIP, uint16(port))
			feAddrID, err := service.AcquireID(*feAddr, 0)
			if err != nil {
				scopedLog.WithError(err).Error("Error while getting a new service ID. Ignoring ingress...")
				continue
			}
			scopedLog.WithFields(logrus.Fields{
				logfields.ServiceID: feAddrID.ID,
			}).Debug("Got service ID for ingress")

			if err := d.RevNATAdd(loadbalancer.ServiceID(feAddrID.ID),
				feAddrID.L3n4Addr); err != nil {
				scopedLog.WithError(err).WithFields(logrus.Fields{
					logfields.ServiceID: feAddrID.ID,
					logfields.IPAddr:    feAddrID.L3n4Addr.IP,
					logfields.Port:      feAddrID.L3n4Addr.Port,
					logfields.Protocol:  feAddrID.L3n4Addr.Protocol,
				}).Error("Unable to add reverse NAT ID for ingress")
			}
		}
		return nil
	}

	if oldIngress.Spec.Backend.ServiceName == newIngress.Spec.Backend.ServiceName &&
		oldIngress.Spec.Backend.ServicePort == newIngress.Spec.Backend.ServicePort {
		return nil
	}

	return d.addIngressV1beta1(newIngress)
}

func (d *Daemon) deleteIngressV1beta1(ingress *types.Ingress) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sIngressName: ingress.ObjectMeta.Name,
		logfields.K8sAPIVersion:  ingress.TypeMeta.APIVersion,
		logfields.K8sNamespace:   ingress.ObjectMeta.Namespace,
	})

	if ingress.Spec.Backend == nil {
		// We only support Single Service Ingress for now
		scopedLog.Warn("Cilium only supports Single Service Ingress for now, ignoring ingress deletion")
		return nil
	}

	d.k8sSvcCache.DeleteIngress(ingress)

	// Remove RevNAT from the BPF Map for non-LB nodes.
	if !option.Config.IsLBEnabled() {
		port := ingress.Spec.Backend.ServicePort.IntValue()
		for _, lb := range ingress.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(lb.IP)
			if ingressIP == nil {
				continue
			}
			feAddr := loadbalancer.NewL3n4Addr(loadbalancer.TCP, ingressIP, uint16(port))
			// This is the only way that we can get the service's ID
			// without accessing the KVStore.
			svc := d.svcGetBySHA256Sum(feAddr.SHA256Sum())
			if svc != nil {
				if err := d.RevNATDelete(loadbalancer.ServiceID(svc.FE.ID)); err != nil {
					scopedLog.WithError(err).WithFields(logrus.Fields{
						logfields.ServiceID: svc.FE.ID,
					}).Error("Error while removing RevNAT for ingress")
				}
			}
		}
		return nil
	}

	return nil
}

func (d *Daemon) updateCiliumNetworkPolicyV2AnnotationsOnly(ciliumNPClient clientset.Interface, ciliumV2Store cache.Store, cnp *types.SlimCNP) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Info("updating node status due to annotations-only change to CiliumNetworkPolicy")

	ctrlName := cnp.GetControllerName()

	// Revision will *always* be populated because importMetadataCache is guaranteed
	// to be updated by addCiliumNetworkPolicyV2 before calls to
	// updateCiliumNetworkPolicyV2 are invoked.
	meta, _ := importMetadataCache.get(cnp)
	updateContext := &k8s.CNPStatusUpdateContext{
		CiliumNPClient:              ciliumNPClient,
		CiliumV2Store:               ciliumV2Store,
		NodeName:                    node.GetName(),
		NodeManager:                 d.nodeDiscovery.Manager,
		WaitForEndpointsAtPolicyRev: endpointmanager.WaitForEndpointsAtPolicyRev,
	}
	if option.Config.IsSubsysMetricEnabled(metrics.SubsystemK8sMask) {
		updateContext.UpdateDuration = spanstat.Start()
	}

	k8sCM.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return updateContext.UpdateStatus(ctx, cnp, meta.revision, meta.policyImportError)
			},
		})

}

func (d *Daemon) addCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface, ciliumV2Store cache.Store, cnp *types.SlimCNP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	var rev uint64

	rules, policyImportErr := cnp.Parse()
	if policyImportErr == nil {
		policyImportErr = k8s.PreprocessRules(rules, &d.k8sSvcCache)
		// Replace all rules with the same name, namespace and
		// resourceTypeCiliumNetworkPolicy
		rev, policyImportErr = d.PolicyAdd(rules, &AddOptions{
			ReplaceWithLabels: cnp.GetIdentityLabels(),
			Source:            metrics.LabelEventSourceK8s,
		})
	}

	if policyImportErr != nil {
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}

	// Upsert to rule revision cache outside of controller, because upsertion
	// *must* be synchronous so that if we get an update for the CNP, the cache
	// is populated by the time updateCiliumNetworkPolicyV2 is invoked.
	importMetadataCache.upsert(cnp, rev, policyImportErr)

	updateContext := &k8s.CNPStatusUpdateContext{
		CiliumNPClient:              ciliumNPClient,
		CiliumV2Store:               ciliumV2Store,
		NodeName:                    node.GetName(),
		NodeManager:                 d.nodeDiscovery.Manager,
		WaitForEndpointsAtPolicyRev: endpointmanager.WaitForEndpointsAtPolicyRev,
	}
	if option.Config.IsSubsysMetricEnabled(metrics.SubsystemK8sMask) {
		updateContext.UpdateDuration = spanstat.Start()
	}

	ctrlName := cnp.GetControllerName()
	k8sCM.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return updateContext.UpdateStatus(ctx, cnp, rev, policyImportErr)
			},
		},
	)
	return policyImportErr
}

func (d *Daemon) deleteCiliumNetworkPolicyV2(cnp *types.SlimCNP) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	importMetadataCache.delete(cnp)
	ctrlName := cnp.GetControllerName()
	err := k8sCM.RemoveControllerAndWait(ctrlName)
	if err != nil {
		log.Debugf("Unable to remove controller %s: %s", ctrlName, err)
	}

	_, err = d.PolicyDelete(cnp.GetIdentityLabels())
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
	return err
}

func (d *Daemon) updateCiliumNetworkPolicyV2(ciliumNPClient clientset.Interface,
	ciliumV2Store cache.Store,
	oldRuleCpy, newRuleCpy *types.SlimCNP) error {

	_, err := oldRuleCpy.Parse()
	if err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(oldRuleCpy)).
			Warn("Error parsing old CiliumNetworkPolicy rule")
		return err
	}
	_, err = newRuleCpy.Parse()
	if err != nil {
		log.WithError(err).WithField(logfields.Object, logfields.Repr(newRuleCpy)).
			Warn("Error parsing new CiliumNetworkPolicy rule")
		return err
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

	// Do not add rule into policy repository if the spec remains unchanged.
	if oldRuleCpy.SpecEquals(newRuleCpy.CiliumNetworkPolicy) {
		if !oldRuleCpy.AnnotationsEquals(newRuleCpy.CiliumNetworkPolicy) {

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
			d.updateCiliumNetworkPolicyV2AnnotationsOnly(ciliumNPClient, ciliumV2Store, newRuleCpy)
		}
		return nil
	}

	return d.addCiliumNetworkPolicyV2(ciliumNPClient, ciliumV2Store, newRuleCpy)
}

func (d *Daemon) updatePodHostIP(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	hostIP := net.ParseIP(pod.StatusHostIP)
	if hostIP == nil {
		return true, fmt.Errorf("no/invalid HostIP: %s", pod.StatusHostIP)
	}

	podIP := net.ParseIP(pod.StatusPodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.StatusPodIP)
	}

	hostKey := node.GetIPsecKeyIdentity()

	// Initial mapping of podIP <-> hostIP <-> identity. The mapping is
	// later updated once the allocator has determined the real identity.
	// If the endpoint remains unmanaged, the identity remains untouched.
	selfOwned := ipcache.IPIdentityCache.Upsert(pod.StatusPodIP, hostIP, hostKey, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: ipcache.FromKubernetes,
	})
	if !selfOwned {
		return true, fmt.Errorf("ipcache entry owned by kvstore or agent")
	}

	return false, nil
}

func (d *Daemon) deletePodHostIP(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIP := net.ParseIP(pod.StatusPodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.StatusPodIP)
	}

	// a small race condition exists here as deletion could occur in
	// parallel based on another event but it doesn't matter as the
	// identity is going away
	id, exists := ipcache.IPIdentityCache.LookupByIP(pod.StatusPodIP)
	if !exists {
		return true, fmt.Errorf("identity for IP does not exist in case")
	}

	if id.Source != ipcache.FromKubernetes {
		return true, fmt.Errorf("ipcache entry not owned by kubernetes source")
	}

	ipcache.IPIdentityCache.Delete(pod.StatusPodIP, ipcache.FromKubernetes)

	return false, nil
}

func (d *Daemon) addK8sPodV1(pod *types.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
	})

	skipped, err := d.updatePodHostIP(pod)
	switch {
	case skipped:
		logger.WithError(err).Debug("Skipped ipcache map update on pod add")
		return nil
	case err != nil:
		logger.WithError(err).Warning("Unable to update ipcache map entry on pod add ")
	default:
		logger.Debug("Updated ipcache map entry on pod add")
	}
	return err
}

func (d *Daemon) updateK8sPodV1(oldK8sPod, newK8sPod *types.Pod) error {
	if oldK8sPod == nil || newK8sPod == nil {
		return nil
	}

	// The pod IP can never change, it can only switch from unassigned to
	// assigned
	d.addK8sPodV1(newK8sPod)

	// We only care about label updates
	oldPodLabels := oldK8sPod.GetLabels()
	newPodLabels := newK8sPod.GetLabels()
	if comparator.MapStringEquals(oldPodLabels, newPodLabels) {
		return nil
	}

	podNSName := k8sUtils.GetObjNamespaceName(&newK8sPod.ObjectMeta)

	podEP := endpointmanager.LookupPodName(podNSName)
	if podEP == nil {
		log.WithField("pod", podNSName).Debugf("Endpoint not found running for the given pod")
		return nil
	}

	newLabels := labels.Map2Labels(newPodLabels, labels.LabelSourceK8s)
	newIdtyLabels, _ := labels.FilterLabels(newLabels)
	oldLabels := labels.Map2Labels(oldPodLabels, labels.LabelSourceK8s)
	oldIdtyLabels, _ := labels.FilterLabels(oldLabels)

	err := podEP.ModifyIdentityLabels(d, newIdtyLabels, oldIdtyLabels)
	if err != nil {
		log.WithError(err).Debugf("error while updating endpoint with new labels")
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: podEP.GetID(),
		logfields.Labels:     logfields.Repr(newIdtyLabels),
	}).Debug("Update endpoint with new labels")
	return nil
}

func (d *Daemon) deleteK8sPodV1(pod *types.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
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
	return err
}

func (d *Daemon) updateK8sV1Namespace(oldNS, newNS *types.Namespace) error {
	if oldNS == nil || newNS == nil {
		return nil
	}

	// We only care about label updates
	if comparator.MapStringEquals(oldNS.GetLabels(), newNS.GetLabels()) {
		return nil
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
	failed := false
	for _, ep := range eps {
		epNS := ep.GetK8sNamespace()
		if oldNS.Name == epNS {
			err := ep.ModifyIdentityLabels(d, newIdtyLabels, oldIdtyLabels)
			if err != nil {
				log.WithError(err).WithField(logfields.EndpointID, ep.ID).
					Warningf("unable to update endpoint with new namespace labels")
				failed = true
			}
		}
	}
	if failed {
		return errors.New("unable to update some endpoints with new namespace labels")
	}
	return nil
}

func (d *Daemon) updateK8sNodeTunneling(k8sNodeOld, k8sNodeNew *types.Node) error {
	nodeNew := k8s.ParseNode(k8sNodeNew, node.FromKubernetes)
	// Ignore own node
	if nodeNew.Name == node.GetName() {
		return nil
	}

	getIDs := func(node *node.Node, k8sNode *types.Node) (string, net.IP, error) {
		if node == nil {
			return "", nil, nil
		}
		hostIP := node.GetNodeIP(false)
		if ip4 := hostIP.To4(); ip4 == nil {
			return "", nil, fmt.Errorf("HostIP is not an IPv4 address: %s", hostIP)
		}

		ciliumIPStr := k8sNode.GetAnnotations()[annotation.CiliumHostIP]
		if ciliumIPStr == "" {
			// Don't return an error here, as the node may not have been
			// annotated yet by the Cilium agent on it. If the node is annotated
			// later, we will receive an event via the K8s watcher.
			log.Debugf("not updating ipcache entry for node %s because it does not have the CiliumHostIP annotation yet", k8sNode.Name)
			return "", nil, nil
		}
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

		if nodeNew.PublicAttrEquals(nodeOld) {
			// Ignore updates for the same node.
			return nil
		}

		// If the annotation of the node resource has changed, the old
		// ipcache has to be removed manually as Upsert() only handes
		// updates if the key itself is unchanged.
		if ciliumIPStrNew != ciliumIPStrOld {
			d.deleteK8sNodeV1(k8sNodeOld)
		}
	}

	hostKey := node.GetIPsecKeyIdentity()
	selfOwned := ipcache.IPIdentityCache.Upsert(ciliumIPStrNew, hostIPNew, hostKey, ipcache.Identity{
		ID:     identity.ReservedIdentityHost,
		Source: ipcache.FromKubernetes,
	})
	if !selfOwned {
		d.nodeDiscovery.Manager.NodeSoftUpdated(*nodeNew)
		return fmt.Errorf("ipcache entry owned by kvstore or agent")
	}

	nodeNew.EncryptionKey = hostKey
	d.nodeDiscovery.Manager.NodeUpdated(*nodeNew)

	return nil
}

func (d *Daemon) addK8sNodeV1(k8sNode *types.Node) error {
	if err := d.updateK8sNodeTunneling(nil, k8sNode); err != nil {
		log.WithError(err).Warning("Unable to add ipcache entry of Kubernetes node")
		return err
	}
	return nil
}

func (d *Daemon) updateK8sNodeV1(k8sNodeOld, k8sNodeNew *types.Node) error {
	if err := d.updateK8sNodeTunneling(k8sNodeOld, k8sNodeNew); err != nil {
		log.WithError(err).Warning("Unable to update ipcache entry of Kubernetes node")
		return err
	}
	return nil
}

func (d *Daemon) deleteK8sNodeV1(k8sNode *types.Node) error {
	oldNode := k8s.ParseNode(k8sNode, node.FromKubernetes)
	// Ignore own node
	if oldNode.Name == node.GetName() {
		return nil
	}

	ip := k8sNode.GetAnnotations()[annotation.CiliumHostIP]

	logger := log.WithFields(logrus.Fields{
		"K8sNodeName":    k8sNode.ObjectMeta.Name,
		logfields.IPAddr: ip,
	})

	d.nodeDiscovery.Manager.NodeDeleted(*oldNode)

	id, exists := ipcache.IPIdentityCache.LookupByIP(ip)
	if !exists {
		logger.Debug("identity for Cilium IP not found")
		return nil
	}

	// The ipcache entry ownership may have been taken over by a kvstore
	// based entry in which case we should ignore the delete event and wait
	// for the kvstore delete event.
	if id.Source != ipcache.FromKubernetes {
		logger.Debug("ipcache entry for Cilium IP no longer owned by Kubernetes")
		return nil
	}

	ipcache.IPIdentityCache.Delete(ip, ipcache.FromKubernetes)

	ciliumIP := net.ParseIP(ip)
	if ciliumIP == nil {
		logger.Warning("Unable to parse Cilium IP")
		return nil
	}
	return nil
}

// updateK8sEventMetric incrment the given metric per event type and the result
// status of the function
func updateK8sEventMetric(scope string, action string, status bool) {
	result := "success"
	if status == false {
		result = "failed"
	}

	metrics.KubernetesEventProcessed.WithLabelValues(scope, action, result).Inc()
}
