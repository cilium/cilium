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

package watchers

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) podsInit(k8sClient kubernetes.Interface, asyncControllers *sync.WaitGroup) {
	var once sync.Once
	for {
		createPodController := func(fieldSelector fields.Selector) (cache.Store, cache.Controller) {
			return informer.NewInformer(
				cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
					"pods", v1.NamespaceAll, fieldSelector),
				&v1.Pod{},
				0,
				cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						var valid bool
						if pod := k8s.ObjTov1Pod(obj); pod != nil {
							valid = true
							err := k.addK8sPodV1(pod)
							k.K8sEventProcessed(metricPod, metricCreate, err == nil)
						}
						k.K8sEventReceived(metricPod, metricCreate, valid, false)
					},
					UpdateFunc: func(oldObj, newObj interface{}) {
						var valid, equal bool
						if oldPod := k8s.ObjTov1Pod(oldObj); oldPod != nil {
							if newPod := k8s.ObjTov1Pod(newObj); newPod != nil {
								valid = true
								if k8s.EqualV1Pod(oldPod, newPod) {
									equal = true
								} else {
									err := k.updateK8sPodV1(oldPod, newPod)
									k.K8sEventProcessed(metricPod, metricUpdate, err == nil)
								}
							}
						}
						k.K8sEventReceived(metricPod, metricUpdate, valid, equal)
					},
					DeleteFunc: func(obj interface{}) {
						var valid bool
						if pod := k8s.ObjTov1Pod(obj); pod != nil {
							valid = true
							err := k.deleteK8sPodV1(pod)
							k.K8sEventProcessed(metricPod, metricDelete, err == nil)
						}
						k.K8sEventReceived(metricPod, metricDelete, valid, false)
					},
				},
				k8s.ConvertToPod,
			)
		}
		podStore, podController := createPodController(fields.Everything())

		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, nil, podController, k8sAPIGroupPodV1Core)
		once.Do(func() {
			asyncControllers.Done()
			k.k8sAPIGroups.addAPI(k8sAPIGroupPodV1Core)
		})
		go podController.Run(isConnected)

		k.podStoreMU.Lock()
		k.podStore = podStore
		k.podStoreMU.Unlock()
		k.podStoreOnce.Do(func() {
			close(k.podStoreSet)
		})

		if !option.Config.K8sEventHandover {
			return
		}

		// Replace pod controller by only receiving events from our own
		// node once we are connected to the kvstore.

		<-kvstore.Client().Connected(context.TODO())
		close(isConnected)

		log.WithField(logfields.Node, node.GetName()).Info("Connected to KVStore, watching for pod events on node")
		// Only watch for pod events for our node.
		podStore, podController = createPodController(fields.ParseSelectorOrDie("spec.nodeName=" + node.GetName()))
		isConnected = make(chan struct{})
		k.podStoreMU.Lock()
		k.podStore = podStore
		k.podStoreMU.Unlock()

		k.blockWaitGroupToSyncResources(isConnected, nil, podController, k8sAPIGroupPodV1Core)
		go podController.Run(isConnected)

		// Create a new pod controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()
		close(isConnected)
		log.Info("Disconnected from KVStore, watching for pod events all nodes")
	}
}

func (k *K8sWatcher) addK8sPodV1(pod *types.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
	})

	skipped, err := k.updatePodHostData(pod)
	switch {
	case skipped:
		logger.WithError(err).Debug("Skipped ipcache map update on pod add")
		return nil
	case err != nil:
		msg := "Unable to update ipcache map entry on pod add"
		if err == errIPCacheOwnedByNonK8s {
			logger.WithError(err).Debug(msg)
		} else {
			logger.WithError(err).Warning(msg)
		}
	default:
		logger.Debug("Updated ipcache map entry on pod add")
	}
	return err
}

func (k *K8sWatcher) updateK8sPodV1(oldK8sPod, newK8sPod *types.Pod) error {
	if oldK8sPod == nil || newK8sPod == nil {
		return nil
	}

	// The pod IP can never change, it can only switch from unassigned to
	// assigned
	// Process IP updates
	k.addK8sPodV1(newK8sPod)

	// Check annotation updates.
	oldAnno := oldK8sPod.GetAnnotations()
	newAnno := newK8sPod.GetAnnotations()
	annotationsChanged := !k8s.AnnotationsEqual([]string{annotation.ProxyVisibility}, oldAnno, newAnno)

	// Check label updates too.
	oldPodLabels := oldK8sPod.GetLabels()
	newPodLabels := newK8sPod.GetLabels()
	labelsChanged := !comparator.MapStringEquals(oldPodLabels, newPodLabels)

	// Nothing changed.
	if !annotationsChanged && !labelsChanged {
		return nil
	}

	podNSName := k8sUtils.GetObjNamespaceName(&newK8sPod.ObjectMeta)

	podEP := k.endpointManager.LookupPodName(podNSName)
	if podEP == nil {
		log.WithField("pod", podNSName).Debugf("Endpoint not found running for the given pod")
		return nil
	}

	if labelsChanged {
		err := updateEndpointLabels(podEP, oldPodLabels, newPodLabels)
		if err != nil {
			return err
		}
	}

	if annotationsChanged {
		podEP.UpdateVisibilityPolicy(func(ns, podName string) (proxyVisibility string, err error) {
			p, err := k.GetCachedPod(ns, podName)
			if err != nil {
				return "", nil
			}
			return p.Annotations[annotation.ProxyVisibility], nil
		})
		realizePodAnnotationUpdate(podEP)
	}
	return nil
}

func realizePodAnnotationUpdate(podEP *endpoint.Endpoint) {
	// No need to log an error if the state transition didn't succeed,
	// if it didn't succeed that means the endpoint is being deleted, or
	// another regeneration has already been queued up for this endpoint.
	stateTransitionSucceeded := podEP.SetState(endpoint.StateWaitingToRegenerate, "annotations updated")
	if stateTransitionSucceeded {
		podEP.Regenerate(&regeneration.ExternalRegenerationMetadata{
			Reason:            "annotations updated",
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		})
	}
}

func updateEndpointLabels(ep *endpoint.Endpoint, oldLbls, newLbls map[string]string) error {
	newLabels := labels.Map2Labels(newLbls, labels.LabelSourceK8s)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	oldLabels := labels.Map2Labels(oldLbls, labels.LabelSourceK8s)
	oldIdtyLabels, _ := labelsfilter.Filter(oldLabels)

	err := ep.ModifyIdentityLabels(newIdtyLabels, oldIdtyLabels)
	if err != nil {
		log.WithError(err).Debugf("error while updating endpoint with new labels")
		return err
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: ep.GetID(),
		logfields.Labels:     logfields.Repr(newIdtyLabels),
	}).Debug("Updated endpoint with new labels")
	return nil

}

func (k *K8sWatcher) deleteK8sPodV1(pod *types.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
	})

	skipped, err := k.deletePodHostData(pod)
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

func genServiceMappings(pod *types.Pod) []loadbalancer.SVC {
	var svcs []loadbalancer.SVC
	for _, c := range pod.SpecContainers {
		for _, p := range c.HostPorts {
			if p.HostPort == 0 {
				continue
			}
			feIP := net.ParseIP(p.HostIP)
			if feIP == nil {
				feIP = net.ParseIP(pod.StatusHostIP)
			}
			proto, err := loadbalancer.NewL4Type(p.Protocol)
			if err != nil {
				continue
			}
			fe := loadbalancer.L3n4AddrID{
				L3n4Addr: loadbalancer.L3n4Addr{
					IP: feIP,
					L4Addr: loadbalancer.L4Addr{
						Protocol: proto,
						Port:     uint16(p.HostPort),
					},
				},
				ID: loadbalancer.ID(0),
			}
			be := loadbalancer.Backend{
				L3n4Addr: loadbalancer.L3n4Addr{
					IP: net.ParseIP(pod.StatusPodIP),
					L4Addr: loadbalancer.L4Addr{
						Protocol: proto,
						Port:     uint16(p.ContainerPort),
					},
				},
			}
			svcs = append(svcs,
				loadbalancer.SVC{
					Frontend: fe,
					Backends: []loadbalancer.Backend{be},
					Type:     loadbalancer.SVCTypeHostPort,
					// We don't have the node name available here, but in
					// any case in the BPF data path we drop any potential
					// non-local backends anyway (which should never exist).
					TrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
				})
		}
	}

	return svcs
}

func (k *K8sWatcher) UpsertHostPortMapping(pod *types.Pod) error {
	if option.Config.DisableK8sServices || !option.Config.EnableHostPort {
		return nil
	}

	svcs := genServiceMappings(pod)
	if len(svcs) == 0 {
		return nil
	}

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
	})

	hostIP := net.ParseIP(pod.StatusHostIP)
	if hostIP == nil {
		logger.Error("Cannot upsert HostPort service for the podIP due to missing hostIP")
		return fmt.Errorf("no/invalid HostIP: %s", pod.StatusHostIP)
	}

	for _, dpSvc := range svcs {
		if _, _, err := k.svcManager.UpsertService(dpSvc.Frontend, dpSvc.Backends, dpSvc.Type,
			dpSvc.TrafficPolicy, dpSvc.HealthCheckNodePort, pod.ObjectMeta.Name+"-host-port",
			pod.ObjectMeta.Namespace); err != nil {
			logger.WithError(err).Error("Error while inserting service in LB map")
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) DeleteHostPortMapping(pod *types.Pod) error {
	if option.Config.DisableK8sServices || !option.Config.EnableHostPort {
		return nil
	}

	svcs := genServiceMappings(pod)
	if len(svcs) == 0 {
		return nil
	}

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.StatusPodIP,
		"hostIP":               pod.StatusHostIP,
	})

	hostIP := net.ParseIP(pod.StatusHostIP)
	if hostIP == nil {
		logger.Error("Cannot delete HostPort service for the podIP due to missing hostIP")
		return fmt.Errorf("no/invalid HostIP: %s", pod.StatusHostIP)
	}

	for _, dpSvc := range svcs {
		if _, err := k.svcManager.DeleteService(dpSvc.Frontend.L3n4Addr); err != nil {
			logger.WithError(err).Error("Error while deleting service in LB map")
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) updatePodHostData(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIP := net.ParseIP(pod.StatusPodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.StatusPodIP)
	}

	err := k.UpsertHostPortMapping(pod)
	if err != nil {
		return true, fmt.Errorf("cannot upsert hostPort for PodIP: %s", pod.StatusPodIP)
	}

	hostIP := net.ParseIP(pod.StatusHostIP)
	if hostIP == nil {
		return true, fmt.Errorf("no/invalid HostIP: %s", pod.StatusHostIP)
	}

	hostKey := node.GetIPsecKeyIdentity()

	k8sMeta := &ipcache.K8sMetadata{
		Namespace: pod.Namespace,
		PodName:   pod.Name,
	}

	// Initial mapping of podIP <-> hostIP <-> identity. The mapping is
	// later updated once the allocator has determined the real identity.
	// If the endpoint remains unmanaged, the identity remains untouched.
	selfOwned := ipcache.IPIdentityCache.Upsert(pod.StatusPodIP, hostIP, hostKey, k8sMeta, ipcache.Identity{
		ID:     identity.ReservedIdentityUnmanaged,
		Source: source.Kubernetes,
	})
	if !selfOwned {
		return true, fmt.Errorf("ipcache entry owned by kvstore or agent")
	}

	return false, nil
}

func (k *K8sWatcher) deletePodHostData(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIP := net.ParseIP(pod.StatusPodIP)
	if podIP == nil {
		return true, fmt.Errorf("no/invalid PodIP: %s", pod.StatusPodIP)
	}

	k.DeleteHostPortMapping(pod)

	// a small race condition exists here as deletion could occur in
	// parallel based on another event but it doesn't matter as the
	// identity is going away
	id, exists := ipcache.IPIdentityCache.LookupByIP(pod.StatusPodIP)
	if !exists {
		return true, fmt.Errorf("identity for IP does not exist in case")
	}

	if id.Source != source.Kubernetes {
		return true, fmt.Errorf("ipcache entry not owned by kubernetes source")
	}

	ipcache.IPIdentityCache.Delete(pod.StatusPodIP, source.Kubernetes)

	return false, nil
}

// GetCachedPod returns a pod from the local store. Depending if the Cilium
// agent flag `option.Config.K8sEventHandover` this function might only return
// local pods.
// If `option.Config.K8sEventHandover` is:
//  - true: returns only local pods received by the pod watcher.
//  - false: returns any pod in the cluster received by the pod watcher.
func (k *K8sWatcher) GetCachedPod(namespace, name string) (*types.Pod, error) {
	<-k.controllersStarted
	k.WaitForCacheSync(k8sAPIGroupPodV1Core)
	<-k.podStoreSet
	k.podStoreMU.RLock()
	defer k.podStoreMU.RUnlock()
	pName := &types.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	podInterface, exists, err := k.podStore.Get(pName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "pod",
		}, name)
	}
	return podInterface.(*types.Pod).DeepCopy(), nil
}
