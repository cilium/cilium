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
	"sort"
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
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) createPodController(getter cache.Getter, fieldSelector fields.Selector) (cache.Store, cache.Controller) {
	return informer.NewInformer(
		cache.NewListWatchFromClient(getter,
			"pods", v1.NamespaceAll, fieldSelector),
		&slim_corev1.Pod{},
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
						if oldPod.DeepEqual(newPod) {
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
		nil,
	)
}

func (k *K8sWatcher) podsInit(k8sClient kubernetes.Interface, asyncControllers *sync.WaitGroup) {
	var once sync.Once
	watchNodePods := func() chan struct{} {
		// Only watch for pod events for our node.
		podStore, podController := k.createPodController(
			k8sClient.CoreV1().RESTClient(),
			fields.ParseSelectorOrDie("spec.nodeName="+nodeTypes.GetName()))
		isConnected := make(chan struct{})
		k.podStoreMU.Lock()
		k.podStore = podStore
		k.podStoreMU.Unlock()
		k.podStoreOnce.Do(func() {
			close(k.podStoreSet)
		})

		k.blockWaitGroupToSyncResources(isConnected, nil, podController, K8sAPIGroupPodV1Core)
		once.Do(func() {
			asyncControllers.Done()
			k.k8sAPIGroups.addAPI(K8sAPIGroupPodV1Core)
		})
		go podController.Run(isConnected)
		return isConnected
	}

	// We will watch for pods on th entire cluster to keep existing
	// functionality untouched. If we are running with CiliumEndpoint CRD
	// enabled then it means that we can simply watch for pods that are created
	// for this node.
	if !option.Config.DisableCiliumEndpointCRD {
		watchNodePods()
		return
	}

	// If CiliumEndpointCRD is disabled, we will fallback on watching all pods
	// and then watching on the pods created for this node if the
	// K8sEventHandover is enabled.
	for {
		podStore, podController := k.createPodController(
			k8sClient.CoreV1().RESTClient(),
			fields.Everything())

		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, nil, podController, K8sAPIGroupPodV1Core)
		once.Do(func() {
			asyncControllers.Done()
			k.k8sAPIGroups.addAPI(K8sAPIGroupPodV1Core)
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

		log.WithField(logfields.Node, nodeTypes.GetName()).Info("Connected to KVStore, watching for pod events on node")
		isConnected = watchNodePods()

		// Create a new pod controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()
		close(isConnected)
		log.Info("Disconnected from KVStore, watching for pod events all nodes")
	}
}

func (k *K8sWatcher) addK8sPodV1(pod *slim_corev1.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"podIPs":               pod.Status.PodIPs,
		"hostIP":               pod.Status.PodIP,
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

func (k *K8sWatcher) updateK8sPodV1(oldK8sPod, newK8sPod *slim_corev1.Pod) error {
	if oldK8sPod == nil || newK8sPod == nil {
		return nil
	}

	// The pod IP can never change, it can only switch from unassigned to
	// assigned
	// Process IP updates
	k.addK8sPodV1(newK8sPod)

	// Check annotation updates.
	oldAnno := oldK8sPod.ObjectMeta.Annotations
	newAnno := newK8sPod.ObjectMeta.Annotations
	annotationsChanged := !k8s.AnnotationsEqual([]string{annotation.ProxyVisibility}, oldAnno, newAnno)

	// Check label updates too.
	oldPodLabels := oldK8sPod.ObjectMeta.Labels
	newPodLabels := newK8sPod.ObjectMeta.Labels
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
			return p.ObjectMeta.Annotations[annotation.ProxyVisibility], nil
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

func (k *K8sWatcher) deleteK8sPodV1(pod *slim_corev1.Pod) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"podIPs":               pod.Status.PodIPs,
		"hostIP":               pod.Status.HostIP,
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

func (k *K8sWatcher) genServiceMappings(pod *slim_corev1.Pod, podIPs []string, logger *logrus.Entry) []loadbalancer.SVC {
	var svcs []loadbalancer.SVC
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.HostPort <= 0 {
				continue
			}

			if int(p.HostPort) >= option.Config.NodePortMin &&
				int(p.HostPort) <= option.Config.NodePortMax {
				logger.Warningf("The requested hostPort %d is colliding with the configured NodePort range [%d, %d]. Ignoring.",
					p.HostPort, option.Config.NodePortMin, option.Config.NodePortMax)
				continue
			}

			feIP := net.ParseIP(p.HostIP)
			if feIP != nil && feIP.IsLoopback() {
				logger.Warningf("The requested loopback address for hostIP (%s) is not supported. Ignoring.",
					feIP)
				continue
			}

			proto, err := loadbalancer.NewL4Type(string(p.Protocol))
			if err != nil {
				continue
			}

			var bes4 []loadbalancer.Backend
			var bes6 []loadbalancer.Backend

			for _, podIP := range podIPs {
				be := loadbalancer.Backend{
					L3n4Addr: loadbalancer.L3n4Addr{
						IP: net.ParseIP(podIP),
						L4Addr: loadbalancer.L4Addr{
							Protocol: proto,
							Port:     uint16(p.ContainerPort),
						},
					},
				}
				if be.L3n4Addr.IP.To4() != nil {
					bes4 = append(bes4, be)
				} else {
					bes6 = append(bes6, be)
				}
			}

			var nodeAddrAll [][]net.IP

			// When HostIP is explicitly set, then we need to expose *only*
			// on this address but not via other addresses. When it's not set,
			// then expose via all local addresses. Same when the user provides
			// an unspecified address (0.0.0.0 / [::]).
			if feIP != nil && !feIP.IsUnspecified() {
				nodeAddrAll = [][]net.IP{
					{feIP},
				}
			} else {
				nodeAddrAll = [][]net.IP{
					k.K8sSvcCache.GetNodeAddressing().IPv4().LoadBalancerNodeAddresses(),
					k.K8sSvcCache.GetNodeAddressing().IPv6().LoadBalancerNodeAddresses(),
				}
			}
			for _, addrs := range nodeAddrAll {
				for _, ip := range addrs {
					fe := loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							IP: ip,
							L4Addr: loadbalancer.L4Addr{
								Protocol: proto,
								Port:     uint16(p.HostPort),
							},
							Scope: loadbalancer.ScopeExternal,
						},
						ID: loadbalancer.ID(0),
					}

					// We don't have the node name available here, but in any
					// case in the BPF data path we drop any potential non-local
					// backends anyway (which should never exist in the first
					// place), hence we can just leave it at Cluster policy.
					if ip.To4() != nil {
						if option.Config.EnableIPv4 && len(bes4) > 0 {
							svcs = append(svcs,
								loadbalancer.SVC{
									Frontend:      fe,
									Backends:      bes4,
									Type:          loadbalancer.SVCTypeHostPort,
									TrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
								})
						}
					} else {
						if option.Config.EnableIPv6 && len(bes6) > 0 {
							svcs = append(svcs,
								loadbalancer.SVC{
									Frontend:      fe,
									Backends:      bes6,
									Type:          loadbalancer.SVCTypeHostPort,
									TrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
								})
						}
					}
				}
			}
		}
	}

	return svcs
}

func (k *K8sWatcher) UpsertHostPortMapping(pod *slim_corev1.Pod, podIPs []string) error {
	if option.Config.DisableK8sServices || !option.Config.EnableHostPort {
		return nil
	}

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIPs":               podIPs,
		"hostIP":               pod.Status.HostIP,
	})

	svcs := k.genServiceMappings(pod, podIPs, logger)
	if len(svcs) == 0 {
		return nil
	}

	for _, dpSvc := range svcs {
		if _, _, err := k.svcManager.UpsertService(dpSvc.Frontend, dpSvc.Backends, dpSvc.Type,
			dpSvc.TrafficPolicy, false, 0, dpSvc.HealthCheckNodePort,
			fmt.Sprintf("%s/host-port/%d", pod.ObjectMeta.Name, dpSvc.Frontend.L3n4Addr.Port),
			pod.ObjectMeta.Namespace); err != nil {
			logger.WithError(err).Error("Error while inserting service in LB map")
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) DeleteHostPortMapping(pod *slim_corev1.Pod, podIPs []string) error {
	if option.Config.DisableK8sServices || !option.Config.EnableHostPort {
		return nil
	}

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIPs":               podIPs,
		"hostIP":               pod.Status.HostIP,
	})

	svcs := k.genServiceMappings(pod, podIPs, logger)
	if len(svcs) == 0 {
		return nil
	}

	for _, dpSvc := range svcs {
		if _, err := k.svcManager.DeleteService(dpSvc.Frontend.L3n4Addr); err != nil {
			logger.WithError(err).Error("Error while deleting service in LB map")
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) updatePodHostData(pod *slim_corev1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIPs, err := validIPs(pod.Status)
	if err != nil {
		return true, err
	}

	err = k.UpsertHostPortMapping(pod, podIPs)
	if err != nil {
		return true, fmt.Errorf("cannot upsert hostPort for PodIPs: %s", podIPs)
	}

	hostIP := net.ParseIP(pod.Status.HostIP)
	if hostIP == nil {
		return true, fmt.Errorf("no/invalid HostIP: %s", pod.Status.HostIP)
	}

	hostKey := node.GetIPsecKeyIdentity()

	k8sMeta := &ipcache.K8sMetadata{
		Namespace: pod.Namespace,
		PodName:   pod.Name,
	}

	// Store Named ports, if any.
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}
			p, err := u8proto.ParseProtocol(string(port.Protocol))
			if err != nil {
				return true, fmt.Errorf("ContainerPort: invalid protocol: %s", port.Protocol)
			}
			if port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return true, fmt.Errorf("ContainerPort: invalid port: %d", port.ContainerPort)
			}
			if k8sMeta.NamedPorts == nil {
				k8sMeta.NamedPorts = make(policy.NamedPortMap)
			}
			k8sMeta.NamedPorts[port.Name] = policy.NamedPort{
				Proto: uint8(p),
				Port:  uint16(port.ContainerPort),
			}
		}
	}

	var errs []string
	for _, podIP := range podIPs {
		// Initial mapping of podIP <-> hostIP <-> identity. The mapping is
		// later updated once the allocator has determined the real identity.
		// If the endpoint remains unmanaged, the identity remains untouched.
		selfOwned, namedPortsChanged := ipcache.IPIdentityCache.Upsert(podIP, hostIP, hostKey, k8sMeta, ipcache.Identity{
			ID:     identity.ReservedIdentityUnmanaged,
			Source: source.Kubernetes,
		})
		// This happens at most once due to k8sMeta being the same for all podIPs in this loop
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports added or updated")
		}
		if !selfOwned {
			errs = append(errs, fmt.Sprintf("ipcache entry for podIP %s owned by kvstore or agent", podIP))
		}
	}
	if len(errs) != 0 {
		return true, errors.New(strings.Join(errs, ", "))
	}

	return false, nil
}

func (k *K8sWatcher) deletePodHostData(pod *slim_corev1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIPs, err := validIPs(pod.Status)
	if err != nil {
		return true, err
	}

	k.DeleteHostPortMapping(pod, podIPs)

	var (
		errs    []string
		skipped bool
	)

	for _, podIP := range podIPs {
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

func validIPs(podStatus slim_corev1.PodStatus) ([]string, error) {
	if len(podStatus.PodIPs) == 0 && len(podStatus.PodIP) == 0 {
		return nil, fmt.Errorf("empty PodIPs")
	}

	// make it a set first to avoid repeated IP addresses
	ipsMap := make(map[string]struct{}, 1+len(podStatus.PodIPs))
	if podStatus.PodIP != "" {
		ipsMap[podStatus.PodIP] = struct{}{}
	}
	for _, podIP := range podStatus.PodIPs {
		if podIP.IP != "" {
			ipsMap[podIP.IP] = struct{}{}
		}
	}

	ips := make([]string, 0, len(ipsMap))
	for ipStr := range ipsMap {
		ips = append(ips, ipStr)
	}
	sort.Strings(ips)
	return ips, nil
}

// GetCachedPod returns a pod from the local store. Depending if the Cilium
// agent flag `option.Config.K8sEventHandover` this function might only return
// local pods.
// If `option.Config.K8sEventHandover` is:
//  - true: returns only local pods received by the pod watcher.
//  - false: returns any pod in the cluster received by the pod watcher.
func (k *K8sWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	<-k.controllersStarted
	k.WaitForCacheSync(K8sAPIGroupPodV1Core)
	<-k.podStoreSet
	k.podStoreMU.RLock()
	defer k.podStoreMU.RUnlock()
	pName := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
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
	return podInterface.(*slim_corev1.Pod).DeepCopy(), nil
}
