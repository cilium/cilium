// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	v1 "k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

func (k *K8sWatcher) servicesInit(k8sClient kubernetes.Interface, swgSvcs *lock.StoppableWaitGroup, optsModifier func(*v1meta.ListOptions)) {
	_, svcController := informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8sClient.CoreV1().RESTClient(),
			"services", v1.NamespaceAll, optsModifier),
		&slim_corev1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricCreate, valid, equal) }()
				if k8sSvc := k8s.ObjToV1Services(obj); k8sSvc != nil {
					valid = true
					err := k.addK8sServiceV1(k8sSvc, swgSvcs)
					k.K8sEventProcessed(metricService, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricUpdate, valid, equal) }()
				if oldk8sSvc := k8s.ObjToV1Services(oldObj); oldk8sSvc != nil {
					if newk8sSvc := k8s.ObjToV1Services(newObj); newk8sSvc != nil {
						valid = true
						if k8s.EqualV1Services(oldk8sSvc, newk8sSvc, k.datapath.LocalNodeAddressing()) {
							equal = true
							return
						}

						err := k.updateK8sServiceV1(oldk8sSvc, newk8sSvc, swgSvcs)
						k.K8sEventProcessed(metricService, metricUpdate, err == nil)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricService, metricDelete, valid, equal) }()
				k8sSvc := k8s.ObjToV1Services(obj)
				if k8sSvc == nil {
					return
				}

				valid = true
				err := k.deleteK8sServiceV1(k8sSvc, swgSvcs)
				k.K8sEventProcessed(metricService, metricDelete, err == nil)
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(k.stop, swgSvcs, svcController.HasSynced, K8sAPIGroupServiceV1Core)
	go svcController.Run(k.stop)
	k.k8sAPIGroups.AddAPI(K8sAPIGroupServiceV1Core)
}

func (k *K8sWatcher) addK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	svcID := k.K8sSvcCache.UpdateService(svc, swg)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			// The local redirect policies currently support services of type
			// clusterIP only.
			k.redirectPolicyManager.OnAddService(svcID)
		}
	}
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnUpdateService(svc)
	}
	return nil
}

func (k *K8sWatcher) updateK8sServiceV1(oldSvc, newSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	return k.addK8sServiceV1(newSvc, swg)
}

func (k *K8sWatcher) deleteK8sServiceV1(svc *slim_corev1.Service, swg *lock.StoppableWaitGroup) error {
	k.K8sSvcCache.DeleteService(svc, swg)
	svcID := k8s.ParseServiceID(svc)
	if option.Config.EnableLocalRedirectPolicy {
		if svc.Spec.Type == slim_corev1.ServiceTypeClusterIP {
			k.redirectPolicyManager.OnDeleteService(svcID)
		}
	}
	if option.Config.BGPAnnounceLBIP {
		k.bgpSpeakerManager.OnDeleteService(svc)
	}
	return nil
}
