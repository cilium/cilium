// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type serviceAddedEvent struct {
	service *slim_corev1.Service
}

type serviceUpdatedEvent struct {
	oldService *slim_corev1.Service
	newService *slim_corev1.Service
}

type serviceDeletedEvent struct {
	service *slim_corev1.Service
}

type serviceManager struct {
	informer cache.Controller
	store    cache.Store

	queue      workqueue.RateLimitingInterface
	maxRetries int

	ingressQueue workqueue.RateLimitingInterface
}

func newServiceManager(ingressQueue workqueue.RateLimitingInterface, maxRetries int) (*serviceManager, error) {
	manager := &serviceManager{
		queue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ingressQueue: ingressQueue,
		maxRetries:   maxRetries,
	}

	manager.store, manager.informer = informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8s.WatcherClient().CoreV1().RESTClient(), "services",
			v1.NamespaceAll, func(options *metav1.ListOptions) {
				options.LabelSelector = ciliumIngressLabelKey
			}),
		&slim_corev1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    manager.handleAddService,
			UpdateFunc: manager.handleUpdateService,
			DeleteFunc: manager.handleDeleteService,
		},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync service")
	}
	log.WithField("existing-services", manager.store.ListKeys()).Debug("services synced")
	return manager, nil
}

// Run kicks off the control loop
func (sm *serviceManager) Run() {
	for sm.processEvent() {
	}
}

// getByKey is a wrapper of Store.GetByKey but with concrete Service object
func (sm *serviceManager) getByKey(key string) (*slim_corev1.Service, bool, error) {
	objFromCache, exists, err := sm.store.GetByKey(key)
	if !exists || err != nil || objFromCache == nil {
		return nil, exists, err
	}

	service, ok := objFromCache.(*slim_corev1.Service)
	if !ok {
		return nil, exists, fmt.Errorf("unexpected type found in service cache: %T", objFromCache)
	}
	return service, exists, err
}

func (sm *serviceManager) handleAddService(obj interface{}) {
	if service := k8s.ObjToV1Services(obj); service != nil {
		sm.queue.Add(serviceAddedEvent{service: service})
	}
}

func (sm *serviceManager) handleUpdateService(oldObj, newObj interface{}) {
	oldService := k8s.ObjToV1Services(oldObj)
	if oldService == nil {
		return
	}
	newService := k8s.ObjToV1Services(newObj)
	if newService == nil {
		return
	}
	if oldService.DeepEqual(newService) {
		return
	}
	sm.queue.Add(serviceUpdatedEvent{oldService: oldService, newService: newService})
}

func (sm *serviceManager) handleDeleteService(obj interface{}) {
	if service := k8s.ObjToV1Services(obj); service != nil {
		sm.queue.Add(serviceDeletedEvent{service: service})
	}
}

func (sm *serviceManager) processEvent() bool {
	event, shutdown := sm.queue.Get()
	if shutdown {
		return false
	}
	defer sm.queue.Done(event)
	err := sm.handleEvent(event)
	if err == nil {
		sm.queue.Forget(event)
	} else if sm.queue.NumRequeues(event) < sm.maxRetries {
		sm.queue.AddRateLimited(event)
	} else {
		log.Errorf("failed to process event: %s", event)
		sm.queue.Forget(event)
	}
	return true
}

func (sm *serviceManager) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case serviceAddedEvent:
		log.WithField(logfields.ServiceKey, ev.service.Name).Debug("Handling service added event")
		err = sm.handleServiceAddedEvent(ev)
	case serviceUpdatedEvent:
		log.WithField(logfields.ServiceKey, ev.newService.Name).Debug("Handling service updated event")
		err = sm.handleServiceUpdatedEvent(ev)
	case serviceDeletedEvent:
		//doing nothing right now
	default:
		err = fmt.Errorf("received an unknown event: %s", ev)
	}
	return err
}

func (sm *serviceManager) handleServiceAddedEvent(event serviceAddedEvent) error {
	sm.notify(event.service)
	return nil
}

func (sm *serviceManager) handleServiceUpdatedEvent(event serviceUpdatedEvent) error {
	if event.newService.ObjectMeta.GetDeletionTimestamp() != nil {
		// This means the service is in the process of being deleted, cleaning up load balancers
		// and such. Nothing to do in this case.
		log.WithFields(logrus.Fields{
			logfields.ServiceNamespace: event.newService.Namespace,
			logfields.ServiceKey:       event.newService.Name,
		}).Debug("Service is being deleted")
		return nil
	}
	log.WithField("old", event.oldService).WithField("new", event.newService).Debug("Handling service update")
	sm.notify(event.newService)
	return nil
}

// notify informs parent ingress about load balancer details
func (sm *serviceManager) notify(service *slim_corev1.Service) {
	if len(service.Status.LoadBalancer.Ingress) > 0 {
		log.Info("Notify ingress controller for service ingress")
		sm.ingressQueue.Add(ingressServiceUpdatedEvent{ingressService: service})
	}
}

func getServiceForIngress(ingress *slim_networkingv1.Ingress) *v1.Service {
	ports := []v1.ServicePort{
		{
			Name:     "http",
			Protocol: "TCP",
			Port:     80,
		},
	}
	if tlsEnabled(ingress) {
		ports = append(ports, v1.ServicePort{
			Name:     "https",
			Protocol: "TCP",
			Port:     443,
		})
	}
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getServiceNameForIngress(ingress),
			Namespace: ingress.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Name:       ingress.Name,
					UID:        ingress.UID,
				},
			},
		},
		Spec: v1.ServiceSpec{
			Ports: ports,
			Type:  v1.ServiceTypeLoadBalancer,
		},
	}
}
