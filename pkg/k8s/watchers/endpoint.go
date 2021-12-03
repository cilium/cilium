// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package watchers

import (
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) endpointsInit(k8sClient kubernetes.Interface, swgEps *lock.StoppableWaitGroup, optsModifier func(*v1meta.ListOptions)) {
	epOptsModifier := func(options *v1meta.ListOptions) {
		options.FieldSelector = fields.ParseSelectorOrDie(option.Config.K8sWatcherEndpointSelector).String()
		optsModifier(options)
	}

	_, endpointController := informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"endpoints", v1.NamespaceAll,
			epOptsModifier,
		),
		&slim_corev1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricEndpoint, metricCreate, valid, equal) }()
				if k8sEP := k8s.ObjToV1Endpoints(obj); k8sEP != nil {
					valid = true
					err := k.addK8sEndpointV1(k8sEP, swgEps)
					k.K8sEventProcessed(metricEndpoint, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricEndpoint, metricUpdate, valid, equal) }()
				if oldk8sEP := k8s.ObjToV1Endpoints(oldObj); oldk8sEP != nil {
					if newk8sEP := k8s.ObjToV1Endpoints(newObj); newk8sEP != nil {
						valid = true
						if oldk8sEP.DeepEqual(newk8sEP) {
							equal = true
							return
						}

						err := k.updateK8sEndpointV1(oldk8sEP, newk8sEP, swgEps)
						k.K8sEventProcessed(metricEndpoint, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricEndpoint, metricDelete, valid, equal) }()
				k8sEP := k8s.ObjToV1Endpoints(obj)
				if k8sEP == nil {
					return
				}
				valid = true
				err := k.deleteK8sEndpointV1(k8sEP, swgEps)
				k.K8sEventProcessed(metricEndpoint, metricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(wait.NeverStop, swgEps, endpointController.HasSynced, K8sAPIGroupEndpointV1Core)
	go endpointController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(K8sAPIGroupEndpointV1Core)
}

func (k *K8sWatcher) addK8sEndpointV1(ep *slim_corev1.Endpoints, swg *lock.StoppableWaitGroup) error {
	return k.updateK8sEndpointV1(nil, ep, swg)
}

func (k *K8sWatcher) updateK8sEndpointV1(oldEP, newEP *slim_corev1.Endpoints, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.UpdateEndpoints(newEP, swg)
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateEndpoints(newEP)
	}
	k.addKubeAPIServerServiceEPs(newEP)
	return nil
}

func (k *K8sWatcher) deleteK8sEndpointV1(ep *slim_corev1.Endpoints, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.DeleteEndpoints(ep, swg)
	return nil
}

// handleKubeAPIServerServiceEPChanges associates the set of 'desiredIPs' with
// the 'reserved:kube-apiserver' label in the IPCache. This allows policy
// selectors for the kube-apiserver entity to match these peers.
//
// Any IPs currently associated with the apiserver that are not part of
// 'desiredIPs' will be disassociated from the apiserver following a call to
// this function.
//
// The actual implementation of this logic down to the datapath is handled
// asynchronously.
func (k *K8sWatcher) handleKubeAPIServerServiceEPChanges(desiredIPs map[string]struct{}) {
	// Use CustomResource as the source similar to the way the CiliumNode
	// (pkg/node/manager.Manager) handler does because the ipcache entry needs
	// to be overwrite-able by this handler and the CiliumNode handler. If we
	// used Kubernetes as the source, then the ipcache entries inserted (first)
	// by the CN handler wouldn't be overwrite-able by the entries inserted
	// from this handler.
	src := source.CustomResource

	// We must perform a diff on the ipcache.identityMetadata map in order to
	// figure out which IPs are stale and should be removed, before we inject
	// new IPs into the ipcache. The reason is because kube-apiserver will
	// constantly reconcile this specific object, even when it's been deleted;
	// effectively, this means we can avoid listening for the delete event.
	// Therefore, any changes to this specific object can be handled in a
	// "flattened" manner, since the most up-to-date form of it will be an add
	// or update event. The former is sent when Cilium is syncing with K8s and
	// the latter is sent anytime after.
	//
	// For example:
	//   * if a backend is removed or updated, then this will be in the form of
	//     an update event.
	//   * if the entire object is deleted, then it will quickly be recreated
	//     and this will be in the form of an add event.
	ipcache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer,
		desiredIPs,
		src,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)

	for ip := range desiredIPs {
		ipcache.UpsertMetadata(ip, labels.LabelKubeAPIServer)
	}

	ipcache.IPIdentityCache.TriggerLabelInjection(
		src,
		k.policyRepository.GetSelectorCache(),
		k.policyManager,
	)
}

// TODO(christarazi): Convert to subscriber model along with the corresponding
// EndpointSlice version.
func (k *K8sWatcher) addKubeAPIServerServiceEPs(ep *slim_corev1.Endpoints) {
	if ep == nil || ep.Name != "kubernetes" || ep.Namespace != "default" {
		return
	}

	desiredIPs := make(map[string]struct{})
	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			desiredIPs[addr.IP] = struct{}{}
		}
	}

	k.handleKubeAPIServerServiceEPChanges(desiredIPs)
}
