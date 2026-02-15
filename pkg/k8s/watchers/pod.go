// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	cgroup "github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const podApiGroup = resources.K8sAPIGroupPodV1Core

var ciliumEndpointSyncPodLabelsControllerGroup = controller.NewGroup("sync-pod-labels-with-cilium-endpoint")

type k8sPodWatcherParams struct {
	cell.In

	Logger *slog.Logger

	K8sEventReporter *K8sEventReporter

	Clientset          k8sClient.Clientset
	K8sResourceSynced  *k8sSynced.Resources
	K8sAPIGroups       *k8sSynced.APIGroups
	EndpointManager    endpointmanager.EndpointManager
	PolicyUpdater      *policy.Updater
	IPCache            *ipcache.IPCache
	DB                 *statedb.DB
	Pods               statedb.Table[agentK8s.LocalPod]
	NodeAddrs          statedb.Table[datapathTables.NodeAddress]
	CGroupManager      cgroup.CGroupManager
	LBConfig           loadbalancer.Config
	WgConfig           wgTypes.WireguardConfig
	IPSecConfig        datapath.IPsecConfig
	HostNetworkManager datapath.IptablesManager
	LocalNodeStore     *node.LocalNodeStore
}

func newK8sPodWatcher(params k8sPodWatcherParams) *K8sPodWatcher {
	return &K8sPodWatcher{
		logger:             params.Logger,
		clientset:          params.Clientset,
		k8sEventReporter:   params.K8sEventReporter,
		k8sResourceSynced:  params.K8sResourceSynced,
		k8sAPIGroups:       params.K8sAPIGroups,
		endpointManager:    params.EndpointManager,
		policyManager:      params.PolicyUpdater,
		ipcache:            params.IPCache,
		cgroupManager:      params.CGroupManager,
		db:                 params.DB,
		pods:               params.Pods,
		nodeAddrs:          params.NodeAddrs,
		lbConfig:           params.LBConfig,
		wgConfig:           params.WgConfig,
		ipsecConfig:        params.IPSecConfig,
		hostNetworkManager: params.HostNetworkManager,
		localNodeStore:     params.LocalNodeStore,

		controllersStarted: make(chan struct{}),
	}
}

type K8sPodWatcher struct {
	logger    *slog.Logger
	clientset k8sClient.Clientset

	k8sEventReporter *K8sEventReporter

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources
	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups       *k8sSynced.APIGroups
	endpointManager    endpointManager
	policyManager      policyManager
	ipcache            ipcacheManager
	cgroupManager      cgroupManager
	db                 *statedb.DB
	pods               statedb.Table[agentK8s.LocalPod]
	nodeAddrs          statedb.Table[datapathTables.NodeAddress]
	lbConfig           loadbalancer.Config
	wgConfig           wgTypes.WireguardConfig
	ipsecConfig        datapath.IPsecConfig
	hostNetworkManager hostNetworkManager
	localNodeStore     *node.LocalNodeStore

	// controllersStarted is a channel that is closed when all watchers that do not depend on
	// local node configuration have been started
	controllersStarted chan struct{}
}

func (k *K8sPodWatcher) podsInit(ctx context.Context) {
	var synced atomic.Bool

	go func() {
		_, initWatch := k.pods.Initialized(k.db.ReadTxn())
		select {
		case <-ctx.Done():
		case <-initWatch:
		}
		synced.Store(true)
	}()

	go func() {
		pods := make(map[types.NamespacedName]*slim_corev1.Pod)
		wtxn := k.db.WriteTxn(k.pods)
		changeIter, err := k.pods.Changes(wtxn)
		wtxn.Commit()
		if err != nil {
			return
		}

		for {
			changes, watch := changeIter.Next(k.db.ReadTxn())
			for change := range changes {
				pod := change.Object.Pod
				name := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
				if !change.Deleted {
					oldPod := pods[name]
					if oldPod == nil {
						k.addK8sPodV1(ctx, pod)
					} else {
						k.updateK8sPodV1(ctx, oldPod, pod)
					}
					k.k8sResourceSynced.SetEventTimestamp(podApiGroup)
					pods[name] = pod
				} else {
					k.deleteK8sPodV1(pod)
					k.k8sResourceSynced.SetEventTimestamp(podApiGroup)
					delete(pods, name)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(ctx.Done(), nil, synced.Load, resources.K8sAPIGroupPodV1Core)
	k.k8sAPIGroups.AddAPI(resources.K8sAPIGroupPodV1Core)
}

func (k *K8sPodWatcher) addK8sPodV1(ctx context.Context, pod *slim_corev1.Pod) error {
	var err error

	scopedLog := k.logger.With(
		logfields.K8sPodName, pod.ObjectMeta.Name,
		logfields.K8sNamespace, pod.ObjectMeta.Namespace,
		logfields.PodIP, pod.Status.PodIP,
		logfields.PodIPs, pod.Status.PodIPs,
		logfields.HostIP, pod.Status.HostIP,
	)

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

	hostPorts, ok := annotation.Get(pod, annotation.NoTrackHostPorts)
	if ok && !pod.Spec.HostNetwork {
		scopedLog.Warn(fmt.Sprintf("%s annotation present but pod does not have hostNetwork: true. ignoring", annotation.NoTrackHostPorts))
	}

	if pod.Spec.HostNetwork {
		hostPorts = strings.ReplaceAll(hostPorts, " ", "")
		k.hostNetworkManager.AddNoTrackHostPorts(pod.Namespace, pod.Name, strings.Split(hostPorts, ","))
	}

	if pod.Spec.HostNetwork && !option.Config.EnableLocalRedirectPolicy {
		scopedLog.Debug("Skip pod event using host networking")
		return err
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) > 0 {
		err = k.updatePodHostData(ctx, nil, pod, nil, podIPs)
	}

	k.cgroupManager.OnAddPod(pod)

	if err != nil {
		scopedLog.Warn("Unable to update ipcache map entry on pod add", logfields.Error, err)
	}
	scopedLog.Debug("Updated ipcache map entry on pod add")

	return err
}

func (k *K8sPodWatcher) updateK8sPodV1(ctx context.Context, oldK8sPod, newK8sPod *slim_corev1.Pod) error {
	var err error

	if oldK8sPod == nil || newK8sPod == nil {
		return err
	}

	scopedLog := k.logger.With(
		logfields.K8sPodName, newK8sPod.ObjectMeta.Name,
		logfields.K8sNamespace, newK8sPod.ObjectMeta.Namespace,
		logfields.NewPodIP, newK8sPod.Status.PodIP,
		logfields.NewPodIPs, newK8sPod.Status.PodIPs,
		logfields.NewHostIP, newK8sPod.Status.HostIP,
		logfields.OldPodIP, oldK8sPod.Status.PodIP,
		logfields.OldPodIPs, oldK8sPod.Status.PodIPs,
		logfields.OldHostIP, oldK8sPod.Status.HostIP,
	)

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

	hostPorts, ok := annotation.Get(newK8sPod, annotation.NoTrackHostPorts)
	if ok && !newK8sPod.Spec.HostNetwork {
		scopedLog.Warn(fmt.Sprintf("%s annotation present but pod does not have hostNetwork: true. ignoring", annotation.NoTrackHostPorts))
	}

	if newK8sPod.Spec.HostNetwork {
		hostPorts = strings.ReplaceAll(hostPorts, " ", "")
		k.hostNetworkManager.AddNoTrackHostPorts(newK8sPod.Namespace, newK8sPod.Name, strings.Split(hostPorts, ","))
	}

	if newK8sPod.Spec.HostNetwork && !option.Config.EnableLocalRedirectPolicy &&
		!option.Config.UnsafeDaemonConfigOption.EnableSocketLBTracing {
		scopedLog.Debug("Skip pod event using host networking")
		return err
	}

	k.cgroupManager.OnUpdatePod(oldK8sPod, newK8sPod)

	oldPodIPs := k8sUtils.ValidIPs(oldK8sPod.Status)
	newPodIPs := k8sUtils.ValidIPs(newK8sPod.Status)
	if len(oldPodIPs) != 0 || len(newPodIPs) != 0 {
		err = k.updatePodHostData(ctx, oldK8sPod, newK8sPod, oldPodIPs, newPodIPs)
		if err != nil {
			scopedLog.Warn("Unable to update ipcache map entry on pod update", logfields.Error, err)
		}
	}

	// Check annotation updates.
	oldAnno := oldK8sPod.ObjectMeta.Annotations
	newAnno := newK8sPod.ObjectMeta.Annotations
	annoChangedBandwidth := !k8s.AnnotationsEqual([]string{bandwidth.EgressBandwidth}, oldAnno, newAnno) || !k8s.AnnotationsEqual([]string{bandwidth.IngressBandwidth}, oldAnno, newAnno)
	annoChangedPriority := !k8s.AnnotationsEqual([]string{bandwidth.Priority}, oldAnno, newAnno)
	annoChangedNoTrack := !k8s.AnnotationsEqual([]string{annotation.NoTrack, annotation.NoTrackAlias}, oldAnno, newAnno)
	annoChangedFIBTableID := !k8s.AnnotationsEqual([]string{annotation.FIBTableID}, oldAnno, newAnno)
	annotationsChanged := annoChangedBandwidth || annoChangedPriority || annoChangedNoTrack || annoChangedFIBTableID

	// Check label updates too.
	oldK8sPodLabels, _ := labelsfilter.Filter(labels.Map2Labels(oldK8sPod.ObjectMeta.Labels, labels.LabelSourceK8s))
	// old labels are stripped to avoid grandfathering in special labels
	oldPodLabels := k8sUtils.StripPodSpecialLabels(oldK8sPodLabels.K8sStringMap())

	strippedNewLabels := k8sUtils.StripPodSpecialLabels(newK8sPod.Labels)

	newK8sPodLabels, _ := labelsfilter.Filter(labels.Map2Labels(strippedNewLabels, labels.LabelSourceK8s))
	newPodLabels := newK8sPodLabels.K8sStringMap()
	labelsChanged := !maps.Equal(oldPodLabels, newPodLabels)
	uidChanged := oldK8sPod.UID != newK8sPod.UID

	// Nothing changed.
	if !annotationsChanged && !labelsChanged {
		scopedLog.Debug(
			"Pod does not have any annotations nor labels changed",
			logfields.OldLabels, oldK8sPod.GetObjectMeta().GetLabels(),
			logfields.OldAnnotations, oldK8sPod.GetObjectMeta().GetAnnotations(),
			logfields.NewLabels, newK8sPod.GetObjectMeta().GetLabels(),
			logfields.NewAnnotations, newK8sPod.GetObjectMeta().GetAnnotations(),
		)
		return err
	}

	podNSName := k8sUtils.GetObjNamespaceName(&newK8sPod.ObjectMeta)

	podEPs := k.endpointManager.GetEndpointsByPodName(podNSName)
	if len(podEPs) == 0 {
		scopedLog.Debug(
			"Endpoint not found running for the given pod",
			logfields.Pod, podNSName,
		)
		return err
	}

	for _, podEP := range podEPs {
		if labelsChanged || uidChanged {
			// Consider a UID change the same as a label change in case the pod's
			// identity needs to be updated, see GH-30409. Annotations are not
			// checked for because annotations don't impact identities.
			err := podEP.UpdateLabelsFrom(oldPodLabels, newPodLabels, labels.LabelSourceK8s)
			if err != nil {
				scopedLog.Warn(
					"Unable to update endpoint labels on pod update",
					logfields.Error, err,
					logfields.K8sPodName, newK8sPod.ObjectMeta.Name,
					logfields.K8sNamespace, newK8sPod.ObjectMeta.Namespace,
					logfields.EndpointID, podEP.GetID(),
					logfields.Labels, newPodLabels,
				)
				return err
			}

			// Synchronize Pod labels with CiliumEndpoint labels if there is a change.
			if !option.Config.DisableCiliumEndpointCRD {
				updateCiliumEndpointLabels(k.logger, k.clientset, podEP, newK8sPod.Labels)
			}
		}

		if annotationsChanged {
			if annoChangedBandwidth {
				podEP.UpdateBandwidthPolicy(newK8sPod.Annotations[bandwidth.EgressBandwidth],
					newK8sPod.Annotations[bandwidth.IngressBandwidth],
					newK8sPod.Annotations[bandwidth.Priority])
			}
			if annoChangedNoTrack {
				podEP.UpdateNoTrackRules(func() string {
					value, _ := annotation.Get(newK8sPod, annotation.NoTrack, annotation.NoTrackAlias)
					return value
				}())
			}
			if annoChangedFIBTableID {
				if tid, ok := newK8sPod.Annotations[annotation.FIBTableID]; ok {
					if tidInt, err := strconv.ParseUint(tid, 10, 32); err == nil {
						podEP.SetFibTableID(uint32(tidInt))
					} else {
						scopedLog.Warn("Unable to parse fib-table-id annotation as uint32, pod will use default routing table.",
							logfields.Annotation, annotation.FIBTableID,
							logfields.Error, err,
						)
					}
				} else {
					podEP.SetFibTableID(0)
				}
				regenMetadata := &regeneration.ExternalRegenerationMetadata{
					Reason:            "fib-table-id annotation updated",
					RegenerationLevel: regeneration.RegenerateWithDatapath,
				}
				if regen, _ := podEP.SetRegenerateStateIfAlive(regenMetadata); regen {
					podEP.Regenerate(regenMetadata)
				}
			} else {
				realizePodAnnotationUpdate(podEP)
			}
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
func updateCiliumEndpointLabels(logger *slog.Logger, clientset k8sClient.Clientset, ep *endpoint.Endpoint, labels map[string]string) {
	var (
		controllerName = fmt.Sprintf("sync-pod-labels-with-cilium-endpoint (%v)", ep.GetID())
		scopedLog      = logger.With(logfields.Controller, controllerName)
	)

	// The controller is executed only once and is associated with the underlying endpoint object.
	// This is to make sure that the controller is also deleted once the endpoint is gone.
	ep.UpdateController(controllerName,
		controller.ControllerParams{
			Group: ciliumEndpointSyncPodLabelsControllerGroup,
			DoFunc: func(ctx context.Context) (err error) {
				cepOwner := ep.GetCEPOwner()
				if cepOwner.IsNil() {
					err := errors.New("Skipping CiliumEndpoint update because it has no k8s pod")
					scopedLog.Debug(
						"",
						logfields.Error, err,
						logfields.EndpointID, ep.GetID(),
						logfields.Labels, labels,
					)
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
					scopedLog.Debug(
						"Error marshalling Pod labels",
						logfields.Error, err,
					)
					return err
				}

				_, err = ciliumClient.CiliumEndpoints(cepOwner.GetNamespace()).Patch(
					ctx, ep.GetK8sCEPName(),
					types.JSONPatchType,
					labelsPatch,
					meta_v1.PatchOptions{})
				if err != nil {
					scopedLog.Debug(
						"Error while updating CiliumEndpoint object with new Pod labels",
						logfields.Error, err,
					)
					return err
				}

				scopedLog.Debug(
					"Updated CiliumEndpoint object with new Pod labels",
					logfields.EndpointID, ep.GetID(),
					logfields.Labels, labels,
				)
				return nil
			},
		})
}

func (k *K8sPodWatcher) deleteK8sPodV1(pod *slim_corev1.Pod) error {
	var err error

	scopedLog := k.logger.With(
		logfields.K8sPodName, pod.ObjectMeta.Name,
		logfields.K8sNamespace, pod.ObjectMeta.Namespace,
		logfields.PodIP, pod.Status.PodIP,
		logfields.PodIPs, pod.Status.PodIPs,
		logfields.HostIP, pod.Status.HostIP,
	)

	if pod.Spec.HostNetwork {
		k.hostNetworkManager.RemoveNoTrackHostPorts(pod.Namespace, pod.Name)
	}

	k.cgroupManager.OnDeletePod(pod)

	skipped, err := k.deletePodHostData(pod)
	switch {
	case skipped:
		scopedLog.Debug(
			"Skipped ipcache map delete on pod delete",
			logfields.Error, err,
		)
	case err != nil:
		scopedLog.Warn(
			"Unable to delete ipcache map entry on pod delete",
			logfields.Error, err,
		)
	default:
		scopedLog.Debug(
			"Deleted ipcache map entry on pod delete",
		)
	}
	return err
}

func (k *K8sPodWatcher) updatePodHostData(ctx context.Context, oldPod, newPod *slim_corev1.Pod, oldPodIPs, newPodIPs k8sTypes.IPSlice) error {
	if newPod.Spec.HostNetwork {
		k.logger.Debug("Pod is using host networking",
			logfields.K8sPodName, newPod.ObjectMeta.Name,
			logfields.K8sNamespace, newPod.ObjectMeta.Namespace,
		)
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
				if slices.Contains(newPodIPs, oldPodIP) {
					found = true
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
			k.policyManager.TriggerPolicyUpdates("Named ports added or updated")
		}
	}()

	specEqual := oldPod != nil && newPod.Spec.DeepEqual(&oldPod.Spec)
	hostIPEqual := oldPod != nil && newPod.Status.HostIP == oldPod.Status.HostIP

	// if spec, host IPs, and pod IPs are the same there no need to perform the remaining
	// operations
	if specEqual && hostIPEqual && ipSliceEqual {
		return nil
	}

	hostIP := net.ParseIP(newPod.Status.HostIP)
	if hostIP == nil {
		return fmt.Errorf("no/invalid HostIP: %s", newPod.Status.HostIP)
	}

	ln, err := k.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	hostKey := node.GetEndpointEncryptKeyIndex(ln, k.wgConfig.Enabled(), k.ipsecConfig.Enabled())

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
			if k8sMeta.NamedPorts == nil {
				k8sMeta.NamedPorts = make(ciliumTypes.NamedPortMap)
			}
			k8sMeta.NamedPorts[port.Name] = ciliumTypes.PortProto{
				Port:  uint16(port.ContainerPort),
				Proto: p,
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

func (k *K8sPodWatcher) deletePodHostData(pod *slim_corev1.Pod) (bool, error) {
	if pod.Spec.HostNetwork {
		return true, fmt.Errorf("pod is using host networking")
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	if len(podIPs) == 0 {
		return true, nil
	}

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

// GetCachedPod returns a pod from the local store.
func (k *K8sPodWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	<-k.controllersStarted
	k.k8sResourceSynced.WaitForCacheSync(resources.K8sAPIGroupPodV1Core)

	pod, _, found := k.pods.Get(k.db.ReadTxn(), agentK8s.PodByName(namespace, name))
	if !found {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "pod",
		}, name)
	}
	return pod.Pod, nil
}
