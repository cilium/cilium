// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	hubblemetrics "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/k8s/watchers/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

const podApiGroup = resources.K8sAPIGroupPodV1Core

var ciliumEndpointSyncPodLabelsControllerGroup = controller.NewGroup("sync-pod-labels-with-cilium-endpoint")

// createAllPodsController is used in the rare configurations where CiliumEndpointCRD is disabled.
// If kvstore and K8sEventHandover is enabled then we fall back to watching only local pods when
// kvstore connects.
func (k *K8sWatcher) createAllPodsController(slimClient slimclientset.Interface) (cache.Store, cache.Controller) {
	return informer.NewInformer(
		k8sUtils.ListerWatcherWithFields(
			k8sUtils.ListerWatcherFromTyped[*slim_corev1.PodList](slimClient.CoreV1().Pods("")),
			fields.Everything()),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if pod := k8s.CastInformerEvent[slim_corev1.Pod](obj); pod != nil {
					err := k.addK8sPodV1(pod)
					k.K8sEventProcessed(metricPod, resources.MetricCreate, err == nil)
					k.K8sEventReceived(podApiGroup, metricPod, resources.MetricCreate, true, false)
				} else {
					k.K8sEventReceived(podApiGroup, metricPod, resources.MetricCreate, false, false)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldPod := k8s.CastInformerEvent[slim_corev1.Pod](oldObj); oldPod != nil {
					if newPod := k8s.CastInformerEvent[slim_corev1.Pod](newObj); newPod != nil {
						if oldPod.DeepEqual(newPod) {
							k.K8sEventReceived(podApiGroup, metricPod, resources.MetricUpdate, false, true)
						} else {
							err := k.updateK8sPodV1(oldPod, newPod)
							k.K8sEventProcessed(metricPod, resources.MetricUpdate, err == nil)
							k.K8sEventReceived(podApiGroup, metricPod, resources.MetricUpdate, true, false)
						}
					}
				} else {
					k.K8sEventReceived(podApiGroup, metricPod, resources.MetricUpdate, false, false)
				}
			},
			DeleteFunc: func(obj interface{}) {
				if pod := k8s.CastInformerEvent[slim_corev1.Pod](obj); pod != nil {
					err := k.deleteK8sPodV1(pod)
					k.K8sEventProcessed(metricPod, resources.MetricDelete, err == nil)
					k.K8sEventReceived(podApiGroup, metricPod, resources.MetricDelete, true, false)
				} else {
					k.K8sEventReceived(podApiGroup, metricPod, resources.MetricDelete, false, false)
				}
			},
		},
		nil,
	)
}

func (k *K8sWatcher) podsInit(slimClient slimclientset.Interface, asyncControllers *sync.WaitGroup) {
	var once sync.Once
	watchNodePods := func() context.CancelFunc {
		ctx, cancel := context.WithCancel(context.Background())
		var synced atomic.Bool
		go func() {
			pods := make(map[resource.Key]*slim_corev1.Pod)
			for ev := range k.resources.LocalPods.Events(ctx) {
				switch ev.Kind {
				case resource.Sync:
					// Set the pod store now that resource has synchronized. Only
					// error expected is if we're being stopped (context cancelled).
					podStore, err := k.resources.LocalPods.Store(ctx)
					if err == nil {
						k.podStoreMU.Lock()
						k.podStore = podStore.CacheStore()
						k.podStoreMU.Unlock()
						k.podStoreOnce.Do(func() {
							close(k.podStoreSet)
						})
					}
					synced.Store(true)
				case resource.Upsert:
					newPod := ev.Object
					oldPod := pods[ev.Key]
					if oldPod == nil {
						k.addK8sPodV1(newPod)
					} else {
						k.updateK8sPodV1(oldPod, newPod)
					}
					k.k8sResourceSynced.SetEventTimestamp(podApiGroup)
					pods[ev.Key] = newPod
				case resource.Delete:
					k.deleteK8sPodV1(ev.Object)
					k.k8sResourceSynced.SetEventTimestamp(podApiGroup)
					delete(pods, ev.Key)
				}

				ev.Done(nil)
			}
		}()

		k.blockWaitGroupToSyncResources(ctx.Done(), nil, synced.Load, resources.K8sAPIGroupPodV1Core)
		once.Do(func() {
			asyncControllers.Done()
			k.k8sAPIGroups.AddAPI(resources.K8sAPIGroupPodV1Core)
		})
		return cancel
	}

	// Disable watching pods if we are in high-scale mode. We don't need to
	// insert pod IPs into the ipcache.
	if option.Config.EnableHighScaleIPcache {
		asyncControllers.Done()
		return
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
		podStore, podController := k.createAllPodsController(slimClient)

		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, nil, podController.HasSynced, resources.K8sAPIGroupPodV1Core)
		once.Do(func() {
			asyncControllers.Done()
			k.k8sAPIGroups.AddAPI(resources.K8sAPIGroupPodV1Core)
		})
		go podController.Run(isConnected)

		k.podStoreMU.Lock()
		k.podStore = podStore
		k.podStoreMU.Unlock()
		k.podStoreOnce.Do(func() {
			close(k.podStoreSet)
		})

		if option.Config.LegacyTurnOffK8sEventHandover {
			return
		}

		// Replace pod controller by only receiving events from our own
		// node once we are connected to the kvstore.
		<-kvstore.Connected()
		close(isConnected)

		log.WithField(logfields.Node, nodeTypes.GetName()).Info("Connected to KVStore, watching for pod events on node")
		cancelWatchNodePods := watchNodePods()

		// Create a new pod controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()
		cancelWatchNodePods()
		log.Info("Disconnected from KVStore, watching for pod events all nodes")
	}
}

func (k *K8sWatcher) addK8sPodV1(pod *slim_corev1.Pod) error {
	var err error

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"podIPs":               pod.Status.PodIPs,
		"hostIP":               pod.Status.HostIP,
	})

	podNSName := k8sUtils.GetObjNamespaceName(&pod.ObjectMeta)

	// If ep is not nil then we have received the CNI event
	// first and the k8s event afterwards, if this happens it's
	// likely the Kube API Server is getting behind the event
	// handling.
	if eps := k.endpointManager.GetEndpointsByPodName(podNSName); len(eps) != 0 {
		var earliestEP time.Time
		for _, ep := range eps {
			createdAt := ep.GetCreatedAt()
			if earliestEP.IsZero() || createdAt.Before(earliestEP) {
				earliestEP = createdAt
			}
		}
		timeSinceEpCreated := time.Since(earliestEP)
		if timeSinceEpCreated <= 0 {
			metrics.EventLagK8s.Set(0)
		} else {
			metrics.EventLagK8s.Set(timeSinceEpCreated.Round(time.Second).Seconds())
		}
	} else {
		// If the ep is nil then we reset to zero, otherwise
		// the previous value set is kept forever.
		metrics.EventLagK8s.Set(0)
	}
	// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
	// is deleted. If the Job is never deleted, Cilium will never receive a Pod
	// delete event, causing the IP to be left in the ipcache.
	// For this reason we should delete the ipcache entries whenever the pod
	// status is either PodFailed or PodSucceeded as it means the IP address
	// is no longer in use.
	if !k8sUtils.IsPodRunning(pod.Status) {
		err = k.deleteK8sPodV1(pod)
		return err
	}

	if pod.Spec.HostNetwork && !option.Config.EnableLocalRedirectPolicy {
		logger.Debug("Skip pod event using host networking")
		return err
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) > 0 {
		err = k.updatePodHostData(nil, pod, nil, podIPs)

		if option.Config.EnableLocalRedirectPolicy {
			k.redirectPolicyManager.OnAddPod(pod)
		}
	}

	k.cgroupManager.OnAddPod(pod)

	if err != nil {
		logger.WithError(err).Warning("Unable to update ipcache map entry on pod add")
	}
	logger.Debug("Updated ipcache map entry on pod add")

	return err
}

func (k *K8sWatcher) updateK8sPodV1(oldK8sPod, newK8sPod *slim_corev1.Pod) error {
	var err error

	if oldK8sPod == nil || newK8sPod == nil {
		return err
	}

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   newK8sPod.ObjectMeta.Name,
		logfields.K8sNamespace: newK8sPod.ObjectMeta.Namespace,
		"new-podIP":            newK8sPod.Status.PodIP,
		"new-podIPs":           newK8sPod.Status.PodIPs,
		"new-hostIP":           newK8sPod.Status.HostIP,
		"old-podIP":            oldK8sPod.Status.PodIP,
		"old-podIPs":           oldK8sPod.Status.PodIPs,
		"old-hostIP":           oldK8sPod.Status.HostIP,
	})

	// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
	// is deleted. If the Job is never deleted, Cilium will never receive a Pod
	// delete event, causing the IP to be left in the ipcache.
	// For this reason we should delete the ipcache entries whenever the pod
	// status is either PodFailed or PodSucceeded as it means the IP address
	// is no longer in use.
	if !k8sUtils.IsPodRunning(newK8sPod.Status) {
		err = k.deleteK8sPodV1(newK8sPod)
		return err
	}

	if newK8sPod.Spec.HostNetwork && !option.Config.EnableLocalRedirectPolicy &&
		!option.Config.EnableSocketLBTracing {
		logger.Debug("Skip pod event using host networking")
		return err
	}

	k.cgroupManager.OnUpdatePod(oldK8sPod, newK8sPod)

	oldPodIPs := k8sUtils.ValidIPs(oldK8sPod.Status)
	newPodIPs := k8sUtils.ValidIPs(newK8sPod.Status)
	if len(oldPodIPs) != 0 || len(newPodIPs) != 0 {
		err = k.updatePodHostData(oldK8sPod, newK8sPod, oldPodIPs, newPodIPs)
		if err != nil {
			logger.WithError(err).Warning("Unable to update ipcache map entry on pod update")
		}
	}

	// Check annotation updates.
	oldAnno := oldK8sPod.ObjectMeta.Annotations
	newAnno := newK8sPod.ObjectMeta.Annotations
	annoChangedProxy := !k8s.AnnotationsEqual([]string{annotation.ProxyVisibility, annotation.ProxyVisibilityAlias}, oldAnno, newAnno)
	annoChangedBandwidth := !k8s.AnnotationsEqual([]string{bandwidth.EgressBandwidth}, oldAnno, newAnno)
	annoChangedNoTrack := !k8s.AnnotationsEqual([]string{annotation.NoTrack, annotation.NoTrackAlias}, oldAnno, newAnno)
	annotationsChanged := annoChangedProxy || annoChangedBandwidth || annoChangedNoTrack

	// Check label updates too.
	oldK8sPodLabels, _ := labelsfilter.Filter(labels.Map2Labels(oldK8sPod.ObjectMeta.Labels, labels.LabelSourceK8s))
	// old labels are stripped to avoid grandfathering in special labels
	oldPodLabels := k8sUtils.StripPodSpecialLabels(oldK8sPodLabels.K8sStringMap())

	strippedNewLabels := k8sUtils.StripPodSpecialLabels(newK8sPod.Labels)

	newK8sPodLabels, _ := labelsfilter.Filter(labels.Map2Labels(strippedNewLabels, labels.LabelSourceK8s))
	newPodLabels := newK8sPodLabels.K8sStringMap()
	labelsChanged := !comparator.MapStringEquals(oldPodLabels, newPodLabels)

	lrpNeedsReassign := false
	// The relevant updates are : podIPs and label updates.
	oldPodIPLen := len(oldK8sPod.Status.PodIP)
	newPodIPLen := len(newK8sPod.Status.PodIP)
	switch {
	case oldPodIPLen == 0 && newPodIPLen > 0:
		// PodIPs assigned update
		fallthrough
	case oldPodIPLen > 0 && newPodIPLen > 0 && oldPodIPLen != newPodIPLen:
		// PodIPs update
		fallthrough
	case labelsChanged:
		lrpNeedsReassign = true
	}

	if option.Config.EnableLocalRedirectPolicy {
		oldPodReady := k8sUtils.GetLatestPodReadiness(oldK8sPod.Status)
		newPodReady := k8sUtils.GetLatestPodReadiness(newK8sPod.Status)

		if lrpNeedsReassign || (oldPodReady != newPodReady) {
			k.redirectPolicyManager.OnUpdatePod(newK8sPod, lrpNeedsReassign, newPodReady == slim_corev1.ConditionTrue)
		}
	}

	// Nothing changed.
	if !annotationsChanged && !labelsChanged {
		log.WithFields(logrus.Fields{
			"old-labels":      oldK8sPod.GetObjectMeta().GetLabels(),
			"old-annotations": oldK8sPod.GetObjectMeta().GetAnnotations(),
			"new-labels":      newK8sPod.GetObjectMeta().GetLabels(),
			"new-annotations": newK8sPod.GetObjectMeta().GetAnnotations(),
		}).Debugf("Pod does not have any annotations nor labels changed")
		return err
	}

	podNSName := k8sUtils.GetObjNamespaceName(&newK8sPod.ObjectMeta)

	podEPs := k.endpointManager.GetEndpointsByPodName(podNSName)
	if len(podEPs) == 0 {
		log.WithField("pod", podNSName).Debugf("Endpoint not found running for the given pod")
		return err
	}

	for _, podEP := range podEPs {
		if labelsChanged {
			err := updateEndpointLabels(podEP, oldPodLabels, newPodLabels)
			if err != nil {
				return err
			}

			// Synchronize Pod labels with CiliumEndpoint labels if there is a change.
			updateCiliumEndpointLabels(k.clientset, podEP, newPodLabels)
		}

		if annotationsChanged {
			if annoChangedProxy {
				podEP.UpdateVisibilityPolicy(func(ns, podName string) (proxyVisibility string, err error) {
					p, err := k.GetCachedPod(ns, podName)
					if err != nil {
						return "", nil
					}
					value, _ := annotation.Get(p, annotation.ProxyVisibility, annotation.ProxyVisibilityAlias)
					return value, nil
				})
			}
			if annoChangedBandwidth {
				podEP.UpdateBandwidthPolicy(k.bandwidthManager, func(ns, podName string) (bandwidthEgress string, err error) {
					p, err := k.GetCachedPod(ns, podName)
					if err != nil {
						return "", nil
					}
					return p.ObjectMeta.Annotations[bandwidth.EgressBandwidth], nil
				})
			}
			if annoChangedNoTrack {
				podEP.UpdateNoTrackRules(func(ns, podName string) (noTrackPort string, err error) {
					p, err := k.GetCachedPod(ns, podName)
					if err != nil {
						return "", nil
					}
					value, _ := annotation.Get(p, annotation.NoTrack, annotation.NoTrackAlias)
					return value, nil
				})
			}
			realizePodAnnotationUpdate(podEP)
		}
	}

	return err
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

// updateCiliumEndpointLabels runs a controller associated with the endpoint that updates
// the Labels in CiliumEndpoint object by mirroring those of the associated Pod.
func updateCiliumEndpointLabels(clientset client.Clientset, ep *endpoint.Endpoint, labels map[string]string) {
	var (
		controllerName = fmt.Sprintf("sync-pod-labels-with-cilium-endpoint (%v)", ep.GetID())
		scopedLog      = log.WithField("controller", controllerName)
	)

	// The controller is executed only once and is associated with the underlying endpoint object.
	// This is to make sure that the controller is also deleted once the endpoint is gone.
	ep.UpdateController(controllerName,
		controller.ControllerParams{
			Group: ciliumEndpointSyncPodLabelsControllerGroup,
			DoFunc: func(ctx context.Context) (err error) {
				pod := ep.GetPod()
				if pod == nil {
					err := errors.New("Skipping CiliumEndpoint update because it has no k8s pod")
					scopedLog.WithFields(logrus.Fields{
						logfields.EndpointID: ep.GetID(),
						logfields.Labels:     logfields.Repr(labels),
					}).Debug(err)
					return err
				}
				ciliumClient := clientset.CiliumV2()

				replaceLabels := []k8s.JSONPatch{
					{
						OP:    "replace",
						Path:  "/metadata/labels",
						Value: labels,
					},
				}

				labelsPatch, err := json.Marshal(replaceLabels)
				if err != nil {
					scopedLog.WithError(err).Debug("Error marshalling Pod labels")
					return err
				}

				_, err = ciliumClient.CiliumEndpoints(pod.GetNamespace()).Patch(
					ctx, ep.GetK8sCEPName(),
					types.JSONPatchType,
					labelsPatch,
					meta_v1.PatchOptions{})
				if err != nil {
					scopedLog.WithError(err).Debug("Error while updating CiliumEndpoint object with new Pod labels")
					return err
				}

				scopedLog.WithFields(logrus.Fields{
					logfields.EndpointID: ep.GetID(),
					logfields.Labels:     logfields.Repr(labels),
				}).Debug("Updated CiliumEndpoint object with new Pod labels")

				return nil
			},
		})
}

func updateEndpointLabels(ep *endpoint.Endpoint, oldLbls, newLbls map[string]string) error {
	return ep.UpdateLabelsFrom(oldLbls, newLbls, labels.LabelSourceK8s)
}

func (k *K8sWatcher) deleteK8sPodV1(pod *slim_corev1.Pod) error {
	var err error

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   pod.ObjectMeta.Name,
		logfields.K8sNamespace: pod.ObjectMeta.Namespace,
		"podIP":                pod.Status.PodIP,
		"podIPs":               pod.Status.PodIPs,
		"hostIP":               pod.Status.HostIP,
	})

	if option.Config.EnableLocalRedirectPolicy {
		k.redirectPolicyManager.OnDeletePod(pod)
	}
	hubblemetrics.ProcessPodDeletion(pod)

	k.cgroupManager.OnDeletePod(pod)

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

var (
	_netnsCookieSupported     bool
	_netnsCookieSupportedOnce sync.Once
)

func netnsCookieSupported() bool {
	_netnsCookieSupportedOnce.Do(func() {
		_netnsCookieSupported = probes.HaveProgramHelper(ebpf.CGroupSock, asm.FnGetNetnsCookie) == nil &&
			probes.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetNetnsCookie) == nil
	})
	return _netnsCookieSupported
}

func (k *K8sWatcher) genServiceMappings(pod *slim_corev1.Pod, podIPs []string, logger *logrus.Entry) []loadbalancer.SVC {
	var (
		svcs       []loadbalancer.SVC
		containers []slim_corev1.Container
	)
	containers = append(containers, pod.Spec.InitContainers...)
	containers = append(containers, pod.Spec.Containers...)
	for _, c := range containers {
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
			if feIP != nil && feIP.IsLoopback() && !netnsCookieSupported() {
				logger.Warningf("The requested loopback address for hostIP (%s) is not supported for kernels which don't provide netns cookies. Ignoring.", feIP)
				continue
			}

			proto, err := loadbalancer.NewL4Type(string(p.Protocol))
			if err != nil {
				continue
			}

			var bes4 []*loadbalancer.Backend
			var bes6 []*loadbalancer.Backend

			for _, podIP := range podIPs {
				be := loadbalancer.Backend{
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(podIP),
						L4Addr: loadbalancer.L4Addr{
							Protocol: proto,
							Port:     uint16(p.ContainerPort),
						},
					},
				}
				if be.L3n4Addr.AddrCluster.Is4() {
					bes4 = append(bes4, &be)
				} else {
					bes6 = append(bes6, &be)
				}
			}

			var nodeAddrAll [][]net.IP
			loopbackHostport := false

			// When HostIP is explicitly set, then we need to expose *only*
			// on this address but not via other addresses. When it's not set,
			// then expose via all local addresses. Same when the user provides
			// an unspecified address (0.0.0.0 / [::]).
			if feIP != nil && !feIP.IsUnspecified() {
				// Migrate the loopback address into a 0.0.0.0 / [::]
				// surrogate, thus internal datapath handling can be
				// streamlined. It's not exposed for traffic from outside.
				if feIP.IsLoopback() {
					if feIP.To4() != nil {
						feIP = net.IPv4zero
					} else {
						feIP = net.IPv6zero
					}
					loopbackHostport = true
				}
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
							AddrCluster: cmtypes.MustParseAddrCluster(ip.String()),
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
									Frontend:         fe,
									Backends:         bes4,
									Type:             loadbalancer.SVCTypeHostPort,
									ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
									IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
									LoopbackHostport: loopbackHostport,
								})
						}
					} else {
						if option.Config.EnableIPv6 && len(bes6) > 0 {
							svcs = append(svcs,
								loadbalancer.SVC{
									Frontend:         fe,
									Backends:         bes6,
									Type:             loadbalancer.SVCTypeHostPort,
									ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
									IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
									LoopbackHostport: loopbackHostport,
								})
						}
					}
				}
			}
		}
	}

	return svcs
}

func (k *K8sWatcher) upsertHostPortMapping(oldPod, newPod *slim_corev1.Pod, oldPodIPs, newPodIPs []string) error {
	if !option.Config.EnableHostPort {
		return nil
	}

	var svcsAdded []loadbalancer.L3n4Addr

	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   newPod.ObjectMeta.Name,
		logfields.K8sNamespace: newPod.ObjectMeta.Namespace,
		"podIPs":               newPodIPs,
		"hostIP":               newPod.Status.HostIP,
	})

	svcs := k.genServiceMappings(newPod, newPodIPs, logger)

	if oldPod != nil {
		for _, dpSvc := range svcs {
			svcsAdded = append(svcsAdded, dpSvc.Frontend.L3n4Addr)
		}

		defer func() {
			// delete all IPs that were not added regardless if the insertion of
			// service in LB map was successful or not because we will not receive
			// any other event with these old IP addresses.
			oldSvcs := k.genServiceMappings(oldPod, oldPodIPs, logger)

			for _, dpSvc := range oldSvcs {
				var added bool
				for _, svcsAdded := range svcsAdded {
					if dpSvc.Frontend.L3n4Addr.DeepEqual(&svcsAdded) {
						added = true
						break
					}
				}
				if !added {
					if _, err := k.svcManager.DeleteService(dpSvc.Frontend.L3n4Addr); err != nil {
						logger.WithError(err).Error("Error while deleting service in LB map")
					}
				}
			}
		}()
	}

	if len(svcs) == 0 {
		return nil
	}

	for _, dpSvc := range svcs {
		p := &loadbalancer.SVC{
			Frontend:            dpSvc.Frontend,
			Backends:            dpSvc.Backends,
			Type:                dpSvc.Type,
			ExtTrafficPolicy:    dpSvc.ExtTrafficPolicy,
			IntTrafficPolicy:    dpSvc.IntTrafficPolicy,
			HealthCheckNodePort: dpSvc.HealthCheckNodePort,
			Name: loadbalancer.ServiceName{
				Name:      fmt.Sprintf("%s/host-port/%d", newPod.ObjectMeta.Name, dpSvc.Frontend.L3n4Addr.Port),
				Namespace: newPod.ObjectMeta.Namespace,
			},
			LoopbackHostport: dpSvc.LoopbackHostport,
		}

		if _, _, err := k.svcManager.UpsertService(p); err != nil {
			if errors.Is(err, service.NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
				logger.WithError(err).Debug("Error while inserting service in LB map")
			} else {
				logger.WithError(err).Error("Error while inserting service in LB map")
			}
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) deleteHostPortMapping(pod *slim_corev1.Pod, podIPs []string) error {
	if !option.Config.EnableHostPort {
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
		svc, _ := k.svcManager.GetDeepCopyServiceByFrontend(dpSvc.Frontend.L3n4Addr)
		// Check whether the service being deleted is in fact "owned" by the pod being deleted.
		// We want to make sure that the pod being deleted is in fact the "current" backend that
		// "owns" the hostPort service. Otherwise we might break hostPort connectivity for another
		// pod which may have since claimed ownership for the same hostPort service, which was previously
		// "owned" by the pod being deleted.
		// See: https://github.com/cilium/cilium/issues/22460.
		if svc != nil && !utils.DeepEqualBackends(svc.Backends, dpSvc.Backends) {
			continue
		}

		if _, err := k.svcManager.DeleteService(dpSvc.Frontend.L3n4Addr); err != nil {
			logger.WithError(err).Error("Error while deleting service in LB map")
			return err
		}
	}

	return nil
}

func (k *K8sWatcher) updatePodHostData(oldPod, newPod *slim_corev1.Pod, oldPodIPs, newPodIPs k8sTypes.IPSlice) error {
	logger := log.WithFields(logrus.Fields{
		logfields.K8sPodName:   newPod.ObjectMeta.Name,
		logfields.K8sNamespace: newPod.ObjectMeta.Namespace,
	})

	if newPod.Spec.HostNetwork {
		logger.Debug("Pod is using host networking")
		return nil
	}

	var namedPortsChanged bool

	ipSliceEqual := oldPodIPs != nil && oldPodIPs.DeepEqual(&newPodIPs)

	defer func() {
		if !ipSliceEqual {
			// delete all IPs that were not added regardless if the insertion of the
			// entry in the ipcache map was successful or not because we will not
			// receive any other event with these old IP addresses.
			for _, oldPodIP := range oldPodIPs {
				var found bool
				for _, newPodIP := range newPodIPs {
					if newPodIP == oldPodIP {
						found = true
						break
					}
				}
				if !found {
					npc := k.ipcache.Delete(oldPodIP, source.Kubernetes)
					if npc {
						namedPortsChanged = true
					}
				}
			}
		}

		// This happens at most once due to k8sMeta being the same for all podIPs in this loop
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports added or updated")
		}
	}()

	specEqual := oldPod != nil && newPod.Spec.DeepEqual(&oldPod.Spec)
	hostIPEqual := oldPod != nil && newPod.Status.HostIP != oldPod.Status.HostIP

	// only upsert HostPort Mapping if spec or ip slice is different
	if !specEqual || !ipSliceEqual {
		err := k.upsertHostPortMapping(oldPod, newPod, oldPodIPs, newPodIPs)
		if err != nil {
			return fmt.Errorf("cannot upsert hostPort for PodIPs: %s", newPodIPs)
		}
	}

	// is spec and hostIPs are the same there no need to perform the remaining
	// operations
	if specEqual && hostIPEqual {
		return nil
	}

	hostIP := net.ParseIP(newPod.Status.HostIP)
	if hostIP == nil {
		return fmt.Errorf("no/invalid HostIP: %s", newPod.Status.HostIP)
	}

	hostKey := node.GetIPsecKeyIdentity()

	k8sMeta := &ipcache.K8sMetadata{
		Namespace: newPod.Namespace,
		PodName:   newPod.Name,
	}

	// Store Named ports, if any.
	for _, container := range newPod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}
			p, err := u8proto.ParseProtocol(string(port.Protocol))
			if err != nil {
				return fmt.Errorf("ContainerPort: invalid protocol: %s", port.Protocol)
			}
			if port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return fmt.Errorf("ContainerPort: invalid port: %d", port.ContainerPort)
			}
			if k8sMeta.NamedPorts == nil {
				k8sMeta.NamedPorts = make(ciliumTypes.NamedPortMap)
			}
			k8sMeta.NamedPorts[port.Name] = ciliumTypes.PortProto{
				Port:  uint16(port.ContainerPort),
				Proto: uint8(p),
			}
		}
	}

	var errs []string
	for _, podIP := range newPodIPs {
		// Initial mapping of podIP <-> hostIP <-> identity. The mapping is
		// later updated once the allocator has determined the real identity.
		// If the endpoint remains unmanaged, the identity remains untouched.
		npc, err := k.ipcache.Upsert(podIP, hostIP, hostKey, k8sMeta, ipcache.Identity{
			ID:     identity.ReservedIdentityUnmanaged,
			Source: source.Kubernetes,
		})
		if npc {
			namedPortsChanged = true
		}
		if err != nil {
			// It is expected to receive an error overwrite where the existing
			// source is:
			// - KVStore, this can happen as KVStore event propagation can
			//   usually be faster than k8s event propagation.
			// - local since cilium-agent receives events for local pods.
			// - custom resource since Cilium CR are slimmer and might have
			//   faster propagation than Kubernetes resources.
			if !errors.Is(err, &ipcache.ErrOverwrite{
				ExistingSrc: source.KVStore,
				NewSrc:      source.Kubernetes,
			}) && !errors.Is(err, &ipcache.ErrOverwrite{
				ExistingSrc: source.Local,
				NewSrc:      source.Kubernetes,
			}) && !errors.Is(err, &ipcache.ErrOverwrite{
				ExistingSrc: source.CustomResource,
				NewSrc:      source.Kubernetes,
			}) {
				errs = append(errs, fmt.Sprintf("ipcache entry for podIP %s: %s", podIP, err))
			}
		}
	}
	if len(errs) != 0 {
		return errors.New(strings.Join(errs, ", "))
	}

	return nil
}

func (k *K8sWatcher) deletePodHostData(pod *slim_corev1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) == 0 {
		return true, nil
	}

	k.deleteHostPortMapping(pod, podIPs)

	var (
		errs    []string
		skipped bool
	)

	for _, podIP := range podIPs {
		// a small race condition exists here as deletion could occur in
		// parallel based on another event but it doesn't matter as the
		// identity is going away
		id, exists := k.ipcache.LookupByIP(podIP)
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

		k.ipcache.DeleteOnMetadataMatch(podIP, source.Kubernetes, pod.Namespace, pod.Name)
	}

	if len(errs) != 0 {
		return skipped, errors.New(strings.Join(errs, ", "))
	}

	return skipped, nil
}

// GetCachedPod returns a pod from the local store. Depending if the Cilium
// agent flag `option.Config.K8sEventHandover` this function might only return
// local pods.
// If `option.Config.K8sEventHandover` is:
//   - true: returns only local pods received by the pod watcher.
//   - false: returns any pod in the cluster received by the pod watcher.
func (k *K8sWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	<-k.controllersStarted
	k.WaitForCacheSync(resources.K8sAPIGroupPodV1Core)
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
