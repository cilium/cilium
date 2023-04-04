// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ingressClassAddedEvent struct {
	ingressClass *slim_networkingv1.IngressClass
}

type ingressClassUpdatedEvent struct {
	oldIngressClass *slim_networkingv1.IngressClass
	newIngressClass *slim_networkingv1.IngressClass
}

type ingressClassDeletedEvent struct {
	ingressClass *slim_networkingv1.IngressClass
}

type ingressClassManager struct {
	informer cache.Controller
	store    cache.Store

	queue      workqueue.RateLimitingInterface
	maxRetries int

	ingressQueue workqueue.RateLimitingInterface
}

// type used to signal changes to the ingress controller queue
type ciliumIngressClassUpdatedEvent struct {
	ingressClass *slim_networkingv1.IngressClass
}

type ciliumIngressClassDeletedEvent struct {
	ingressClass *slim_networkingv1.IngressClass
}

func newIngressClassManager(clientset k8sClient.Clientset, ingressQueue workqueue.RateLimitingInterface, maxRetries int) (*ingressClassManager, error) {
	manager := &ingressClassManager{
		queue:        workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ingressQueue: ingressQueue,
		maxRetries:   maxRetries,
	}

	manager.store, manager.informer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_networkingv1.IngressClassList](clientset.Slim().NetworkingV1().IngressClasses()),
		&slim_networkingv1.IngressClass{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    manager.handleAddIngressClass,
			UpdateFunc: manager.handleUpdateIngressClass,
			DeleteFunc: manager.handleDeleteIngressClass,
		},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync service")
	}
	log.WithField("existing-ingressclasses", manager.store.ListKeys()).Debug("ingress classes synced")
	return manager, nil
}

// Run kicks off the control loop
func (i *ingressClassManager) Run() {
	for i.processEvent() {
	}
}

func (i *ingressClassManager) handleAddIngressClass(obj interface{}) {
	if ic := k8s.ObjToV1IngressClass(obj); ic != nil {
		i.queue.Add(ingressClassAddedEvent{ingressClass: ic})
	}
}

func (i *ingressClassManager) handleUpdateIngressClass(oldObj, newObj interface{}) {
	oldIngressClass := k8s.ObjToV1IngressClass(oldObj)
	if oldIngressClass == nil {
		return
	}
	newIngressClass := k8s.ObjToV1IngressClass(newObj)
	if newIngressClass == nil {
		return
	}
	if oldIngressClass.DeepEqual(newIngressClass) {
		return
	}
	i.queue.Add(ingressClassUpdatedEvent{oldIngressClass: oldIngressClass, newIngressClass: newIngressClass})
}

func (i *ingressClassManager) handleDeleteIngressClass(obj interface{}) {
	if ic := k8s.ObjToV1IngressClass(obj); ic != nil {
		i.queue.Add(ingressClassDeletedEvent{ingressClass: ic})
	}
}

func (i *ingressClassManager) processEvent() bool {
	event, shutdown := i.queue.Get()
	if shutdown {
		return false
	}
	defer i.queue.Done(event)
	err := i.handleEvent(event)
	if err == nil {
		i.queue.Forget(event)
	} else if i.queue.NumRequeues(event) < i.maxRetries {
		i.queue.AddRateLimited(event)
	} else {
		log.Errorf("failed to process event: %s", event)
		i.queue.Forget(event)
	}
	return true
}

func (i *ingressClassManager) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case ingressClassAddedEvent:
		log.WithField(logfields.IngressClass, ev.ingressClass.Name).Debug("Handling ingress class added event")
		err = i.handleIngressClassAddedEvent(ev)
	case ingressClassUpdatedEvent:
		log.WithField(logfields.IngressClass, ev.newIngressClass.Name).Debug("Handling ingress class updated event")
		err = i.handleIngressClassUpdatedEvent(ev)
	case ingressClassDeletedEvent:
		log.WithField(logfields.IngressClass, ev.ingressClass.Name).Debug("Handling ingress class deleted event")
		err = i.handleIngressClassDeletedEvent(ev)
	default:
		err = fmt.Errorf("received an unknown event: %s", ev)
	}
	return err
}

func (i *ingressClassManager) handleIngressClassAddedEvent(event ingressClassAddedEvent) error {
	log.WithField(logfields.IngressClass, event.ingressClass).Debug("Handling ingress class add")
	i.notify(event.ingressClass)
	return nil
}

func (i *ingressClassManager) handleIngressClassUpdatedEvent(event ingressClassUpdatedEvent) error {
	log.WithField("old", event.oldIngressClass).WithField("new", event.newIngressClass).Debug("Handling ingress class update")
	i.notify(event.newIngressClass)
	return nil
}

func (i *ingressClassManager) handleIngressClassDeletedEvent(event ingressClassDeletedEvent) error {
	log.WithField(logfields.IngressClass, event.ingressClass).Debug("Handling ingress class delete")

	if event.ingressClass.GetName() == ciliumIngressClassName {
		i.ingressQueue.Add(ciliumIngressClassDeletedEvent{ingressClass: event.ingressClass})
	}
	return nil
}

// notify informs parent ingress about change in our ingress class configuration
func (i *ingressClassManager) notify(ic *slim_networkingv1.IngressClass) {
	if ic.GetName() == ciliumIngressClassName {
		i.ingressQueue.Add(ciliumIngressClassUpdatedEvent{ingressClass: ic})
	}
}
