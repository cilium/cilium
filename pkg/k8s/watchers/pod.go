// Copyright 2016-2020 Authors of Cilium
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
	"errors"
	"fmt"
	"net"
	"strings"
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
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/source"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) podsInit(k8sClient kubernetes.Interface, serPods *serializer.FunctionQueue, asyncControllers *sync.WaitGroup) {
	var once sync.Once
	for {
		swgPods := lock.NewStoppableWaitGroup()
		createPodController := func(fieldSelector fields.Selector) (cache.Store, cache.Controller) {
			return informer.NewInformer(
				cache.NewListWatchFromClient(k8sClient.CoreV1().RESTClient(),
					"pods", v1.NamespaceAll, fieldSelector),
				&v1.Pod{},
				0,
				cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						var valid, equal bool
						defer func() { k.K8sEventReceived(metricPod, metricCreate, valid, equal) }()
						if pod := k8s.CopyObjToV1Pod(obj); pod != nil {
							valid = true
							swgPods.Add()
							serPods.Enqueue(func() error {
								defer swgPods.Done()
								err := k.addK8sPodV1(pod)
								k.K8sEventProcessed(metricPod, metricCreate, err == nil)
								return nil
							}, serializer.NoRetry)
						}
					},
					UpdateFunc: func(oldObj, newObj interface{}) {
						var valid, equal bool
						defer func() { k.K8sEventReceived(metricPod, metricUpdate, valid, equal) }()
						if oldPod := k8s.CopyObjToV1Pod(oldObj); oldPod != nil {
							valid = true
							if newPod := k8s.CopyObjToV1Pod(newObj); newPod != nil {
								if k8s.EqualV1Pod(oldPod, newPod) {
									equal = true
									return
								}
								swgPods.Add()
								serPods.Enqueue(func() error {
									defer swgPods.Done()
									err := k.updateK8sPodV1(oldPod, newPod)
									k.K8sEventProcessed(metricPod, metricUpdate, err == nil)
									return nil
								}, serializer.NoRetry)
							}
						}
					},
					DeleteFunc: func(obj interface{}) {
						var valid, equal bool
						defer func() { k.K8sEventReceived(metricPod, metricDelete, valid, equal) }()
						if pod := k8s.CopyObjToV1Pod(obj); pod != nil {
							valid = true
							swgPods.Add()
							serPods.Enqueue(func() error {
								defer swgPods.Done()
								err := k.deleteK8sPodV1(pod)
								k.K8sEventProcessed(metricPod, metricDelete, err == nil)
								return nil
							}, serializer.NoRetry)
						}
					},
				},
				k8s.ConvertToPod,
			)
		}
		podStore, podController := createPodController(fields.Everything())

		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, swgPods, podController, k8sAPIGroupPodV1Core)
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
		<-kvstore.Connected()
		close(isConnected)

		log.WithField(logfields.Node, node.GetName()).Info("Connected to KVStore, watching for pod events on node")
		// Only watch for pod events for our node.
		podStore, podController = createPodController(fields.ParseSelectorOrDie("spec.nodeName=" + node.GetName()))
		isConnected = make(chan struct{})
		k.podStoreMU.Lock()
		k.podStore = podStore
		k.podStoreMU.Unlock()

		k.blockWaitGroupToSyncResources(isConnected, swgPods, podController, k8sAPIGroupPodV1Core)
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
		"podIPs":               pod.StatusPodIPs,
		"hostIP":               pod.StatusHostIP,
	})

	skipped, err := k.updatePodHostIP(pod)
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
	regenMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            "annotations updated",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
	}
	// No need to log an error if the state transition didn't succeed,
	// if it didn't succeed that means the endpoint is being deleted, or
	// another regeneration has already been queued up for this endpoint.
	regen, _ := podEP.SetRegenerateStateIfAlive(regenMetadata)
	if regen {
		podEP.Regenerate(regenMetadata)
	}
}

func updateEndpointLabels(ep *endpoint.Endpoint, oldLbls, newLbls map[string]string) error {
	newLabels := labels.Map2Labels(newLbls, labels.LabelSourceK8s)
	newIdtyLabels, _ := labels.FilterLabels(newLabels)
	oldLabels := labels.Map2Labels(oldLbls, labels.LabelSourceK8s)
	oldIdtyLabels, _ := labels.FilterLabels(oldLabels)

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
		"podIPs":               pod.StatusPodIPs,
		"hostIP":               pod.StatusHostIP,
	})

	skipped, err := k.deletePodHostIP(pod)
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

func (k *K8sWatcher) updatePodHostIP(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	hostIP := net.ParseIP(pod.StatusHostIP)
	if hostIP == nil {
		return true, fmt.Errorf("no/invalid HostIP: %s", pod.StatusHostIP)
	}

	err := validIPs(pod.StatusPodIPs)
	if err != nil {
		return true, err
	}

	hostKey := node.GetIPsecKeyIdentity()

	k8sMeta := &ipcache.K8sMetadata{
		Namespace: pod.Namespace,
		PodName:   pod.Name,
	}

	var (
		errs    []string
		skipped bool
	)
	for _, podIP := range pod.StatusPodIPs {
		// Initial mapping of podIP <-> hostIP <-> identity. The mapping is
		// later updated once the allocator has determined the real identity.
		// If the endpoint remains unmanaged, the identity remains untouched.
		selfOwned := ipcache.IPIdentityCache.Upsert(podIP, hostIP, hostKey, k8sMeta, ipcache.Identity{
			ID:     identity.ReservedIdentityUnmanaged,
			Source: source.Kubernetes,
		})
		if !selfOwned {
			skipped = true
			errs = append(errs, fmt.Sprintf("ipcache entry for podIP %s owned by kvstore or agent", podIP))
		}
	}
	if len(errs) != 0 {
		return skipped, errors.New(strings.Join(errs, ", "))
	}

	return skipped, nil
}

func (k *K8sWatcher) deletePodHostIP(pod *types.Pod) (bool, error) {
	if pod.SpecHostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	err := validIPs(pod.StatusPodIPs)
	if err != nil {
		return true, err
	}

	var (
		errs    []string
		skipped bool
	)

	for _, podIP := range pod.StatusPodIPs {
		// a small race condition exists here as deletion could occur in
		// parallel based on another event but it doesn't matter as the
		// identity is going away
		id, exists := ipcache.IPIdentityCache.LookupByIP(podIP)
		if !exists {
			skipped = true
			errs = append(errs, fmt.Sprintf("identity for IP %s does not exist in case", podIP))
			continue
		}

		if id.Source != source.Kubernetes {
			skipped = true
			errs = append(errs, fmt.Sprintf("ipcache entry for IP %s not owned by kubernetes source", podIP))
			continue
		}

		ipcache.IPIdentityCache.Delete(podIP, source.Kubernetes)
	}

	if len(errs) != 0 {
		return skipped, errors.New(strings.Join(errs, ", "))
	}

	return skipped, nil
}

func validIPs(ipStrs []string) error {
	if len(ipStrs) == 0 {
		return fmt.Errorf("empty PodIPs")
	}
	for _, ipStr := range ipStrs {
		podIP := net.ParseIP(ipStr)
		if podIP == nil {
			return fmt.Errorf("no/invalid PodIP: %s", ipStr)
		}
	}

	return nil
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
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "pod",
		}, name)
	}
	return podInterface.(*types.Pod).DeepCopy(), nil
}
