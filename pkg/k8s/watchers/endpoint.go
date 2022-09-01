// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"net/netip"

	"github.com/sirupsen/logrus"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

func (k *K8sWatcher) endpointsInit(slimClient slimclientset.Interface, swgEps *lock.StoppableWaitGroup, optsModifier func(*v1meta.ListOptions)) {
	epOptsModifier := func(options *v1meta.ListOptions) {
		options.FieldSelector = fields.ParseSelectorOrDie(option.Config.K8sWatcherEndpointSelector).String()
		optsModifier(options)
	}
	apiGroup := resources.K8sAPIGroupEndpointV1Core
	_, endpointController := informer.NewInformer(
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped[*slim_corev1.EndpointsList](slimClient.CoreV1().Endpoints("")),
			epOptsModifier),
		&slim_corev1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() {
					k.K8sEventReceived(apiGroup, resources.MetricEndpoint, resources.MetricCreate, valid, equal)
				}()
				if k8sEP := k8s.ObjToV1Endpoints(obj); k8sEP != nil {
					valid = true
					err := k.addK8sEndpointV1(k8sEP, swgEps)
					k.K8sEventProcessed(resources.MetricEndpoint, resources.MetricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricEndpoint, resources.MetricUpdate, valid, equal) }()
				if oldk8sEP := k8s.ObjToV1Endpoints(oldObj); oldk8sEP != nil {
					if newk8sEP := k8s.ObjToV1Endpoints(newObj); newk8sEP != nil {
						valid = true
						if oldk8sEP.DeepEqual(newk8sEP) {
							equal = true
							return
						}

						err := k.updateK8sEndpointV1(oldk8sEP, newk8sEP, swgEps)
						k.K8sEventProcessed(resources.MetricEndpoint, resources.MetricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(apiGroup, resources.MetricEndpoint, resources.MetricDelete, valid, equal) }()
				k8sEP := k8s.ObjToV1Endpoints(obj)
				if k8sEP == nil {
					return
				}
				valid = true
				err := k.deleteK8sEndpointV1(k8sEP, swgEps)
				k.K8sEventProcessed(resources.MetricEndpoint, resources.MetricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(k.stop, swgEps, endpointController.HasSynced, resources.K8sAPIGroupEndpointV1Core)
	go endpointController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(apiGroup)
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
func (k *K8sWatcher) handleKubeAPIServerServiceEPChanges(desiredIPs map[netip.Prefix]struct{}, rid ipcacheTypes.ResourceID) {
	src := source.KubeAPIServer

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
	k.ipcache.RemoveLabelsExcluded(
		labels.LabelKubeAPIServer,
		desiredIPs,
		rid,
	)

	for ip := range desiredIPs {
		k.ipcache.UpsertLabels(ip, labels.LabelKubeAPIServer, src, rid)
	}
}

func insertK8sPrefix(desiredIPs map[netip.Prefix]struct{}, addr string, resource ipcacheTypes.ResourceID) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.IPAddr:   addr,
			logfields.Resource: resource,
		}).Warning("Received malformatted IP address from kube-apiserver. This IP will not be used to determine kube-apiserver policy.")
		return
	}
	desiredIPs[netip.PrefixFrom(a, a.BitLen())] = struct{}{}
}

// TODO(christarazi): Convert to subscriber model along with the corresponding
// EndpointSlice version.
func (k *K8sWatcher) addKubeAPIServerServiceEPs(ep *slim_corev1.Endpoints) {
	if ep == nil || ep.Name != "kubernetes" || ep.Namespace != "default" {
		return
	}

	resource := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindEndpoint,
		ep.ObjectMeta.GetNamespace(),
		ep.ObjectMeta.GetName(),
	)

	desiredIPs := make(map[netip.Prefix]struct{})
	for _, sub := range ep.Subsets {
		for _, addr := range sub.Addresses {
			insertK8sPrefix(desiredIPs, addr.IP, resource)
		}
	}
	k.handleKubeAPIServerServiceEPChanges(desiredIPs, resource)
}
