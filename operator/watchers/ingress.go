// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	v12 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	selection2 "k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	IngressSubsys          = "ingress-controller"
	ciliumIngressPrefix    = "cilium-ingress-"
	ciliumIngressLabelKey  = "cilium.io/ingress"
	ciliumIngressClassName = "cilium"
)

// event types
type ingressAddedEvent struct {
	ingress *slim_networkingv1.Ingress
}
type ingressUpdatedEvent struct {
	oldIngress *slim_networkingv1.Ingress
	newIngress *slim_networkingv1.Ingress
}

type ingressDeletedEvent struct {
	ingress *slim_networkingv1.Ingress
}

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

type ingressController struct {
	logger              logrus.FieldLogger
	ingressInformer     cache.Controller
	ingressStore        cache.Store
	serviceInformer     cache.Controller
	serviceStore        cache.Store
	endpointsInformer   cache.Controller
	endpointsStore      cache.Store
	envoyConfigInformer cache.Controller
	envoyConfigStore    cache.Store
	queue               workqueue.RateLimitingInterface
	maxRetries          int
}

func (ic ingressController) handleAddService(obj interface{}) {
	service, ok := obj.(*slim_corev1.Service)
	if !ok {
		return
	}
	ic.queue.Add(serviceAddedEvent{service: service})
}

func (ic ingressController) handleUpdateService(oldObj, newObj interface{}) {
	oldService, ok := oldObj.(*slim_corev1.Service)
	if !ok {
		return
	}
	newService, ok := newObj.(*slim_corev1.Service)
	if !ok {
		return
	}
	ic.queue.Add(serviceUpdatedEvent{oldService: oldService, newService: newService})
}

func (ic ingressController) handleDeleteService(obj interface{}) {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Service:
		ic.queue.Add(serviceDeletedEvent{service: concreteObj})
	case cache.DeletedFinalStateUnknown:
		service, ok := concreteObj.Obj.(*slim_corev1.Service)
		if ok {
			ic.queue.Add(serviceDeletedEvent{service: service})
		}
	default:
		return
	}
}

func NewIngressController(options ...IngressOption) (*ingressController, error) {
	opts := DefaultIngressOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	ic := ingressController{
		logger:     opts.Logger,
		queue:      workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries: opts.MaxRetries,
	}
	ic.ingressStore, ic.ingressInformer = informer.NewInformer(
		cache.NewListWatchFromClient(k8s.WatcherClient().NetworkingV1().RESTClient(), "ingresses", v1.NamespaceAll, fields.Everything()),
		&slim_networkingv1.Ingress{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    ic.handleAddIngress,
			UpdateFunc: ic.handleUpdateIngress,
			DeleteFunc: ic.handleDeleteIngress,
		},
		nil,
	)

	labelSelector := labels.NewSelector()
	req, err := labels.NewRequirement(ciliumIngressLabelKey, selection2.Exists, []string{})
	if err != nil {
		return nil, err
	}
	selectorFunc := func(options *v1meta.ListOptions) {
		labelSelector = labelSelector.Add(*req)
		options.LabelSelector = labelSelector.String()
	}
	ic.serviceStore, ic.serviceInformer = informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8s.WatcherClient().CoreV1().RESTClient(), "services", v1.NamespaceAll, selectorFunc),
		&slim_corev1.Service{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    ic.handleAddService,
			UpdateFunc: ic.handleUpdateService,
			DeleteFunc: ic.handleDeleteService,
		},
		nil,
	)
	ic.endpointsStore, ic.endpointsInformer = informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8s.WatcherClient().CoreV1().RESTClient(), "endpoints", v1.NamespaceAll, selectorFunc),
		&slim_corev1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	ic.envoyConfigStore, ic.envoyConfigInformer = informer.NewInformer(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2alpha1().RESTClient(), "ciliumenvoyconfigs", v1.NamespaceAll, fields.Everything()),
		&v2alpha1.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)
	return &ic, nil
}

func (ic *ingressController) Run() {
	defer ic.queue.ShutDown()
	go ic.ingressInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.ingressInformer.HasSynced) {
		return
	}
	go ic.serviceInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.serviceInformer.HasSynced) {
		return
	}
	go ic.endpointsInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.endpointsInformer.HasSynced) {
		return
	}
	go ic.envoyConfigInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.envoyConfigInformer.HasSynced) {
		return
	}
	ic.logger.WithField("existing-ingresses", ic.ingressStore.ListKeys()).Info("ingresses synced")
	ic.logger.WithField("existing-services", ic.serviceStore.ListKeys()).Info("services synced")
	ic.logger.WithField("existing-endpoints", ic.endpointsStore.ListKeys()).Info("endpoints synced")
	ic.logger.WithField("existing-envoy-config", ic.envoyConfigStore.ListKeys()).Info("envoy-config synced")
	wait.Until(ic.controlLoop, time.Second, wait.NeverStop)
}

func (ic *ingressController) controlLoop() {
	for ic.processEvent() {
	}
}

func (ic *ingressController) processEvent() bool {
	event, shutdown := ic.queue.Get()
	if shutdown {
		return false
	}
	defer ic.queue.Done(event)
	err := ic.handleEvent(event)
	if err == nil {
		ic.queue.Forget(event)
	} else if ic.queue.NumRequeues(event) < ic.maxRetries {
		ic.queue.AddRateLimited(event)
	} else {
		ic.queue.Forget(event)
	}
	return true
}

func (ic *ingressController) handleIngressAddedEvent(event ingressAddedEvent) error {
	ingressClass := event.ingress.Spec.IngressClassName
	if ingressClass == nil || *ingressClass != ciliumIngressClassName {
		return nil
	}
	if err := ic.createEnvoyConfig(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to create CiliumEnvoyConfig")
		return err
	}
	if err := ic.createEndpoints(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to create endpoints")
		return err
	}
	if err := ic.createLoadBalancer(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to create load balancer")
		return err
	}
	return nil
}

func (ic *ingressController) handleIngressDeletedEvent(event ingressDeletedEvent) error {
	ic.logger.WithField("ingress", event.ingress.Name).Info("Deleting Service for ingress")
	if err := ic.deleteLoadBalancer(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to delete load balancer")
		return err
	}
	ic.logger.WithField("ingress", event.ingress.Name).Info("Deleting Endpoints for ingress")
	if err := ic.deleteEndpoints(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to delete endpoints")
		return err
	}
	ic.logger.WithField("ingress", event.ingress.Name).Info("Deleting CiliumEnvoyConfig for ingress")
	if err := ic.deleteCiliumEnvoyConfig(event.ingress); err != nil {
		ic.logger.WithError(err).Warn("failed to delete cilium-envoy-config")
		return err
	}
	return nil
}

func toV1TypeMeta(in slim_metav1.TypeMeta) metav1.TypeMeta {
	return metav1.TypeMeta{
		Kind:       in.Kind,
		APIVersion: in.APIVersion,
	}
}

func toV1ObjectMeta(in slim_metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:            in.Name,
		Namespace:       in.Namespace,
		ResourceVersion: in.ResourceVersion,
		UID:             in.UID,
		Labels:          in.Labels,
		Annotations:     in.Annotations,
	}
}

func toV1IngressStatus(in slim_corev1.LoadBalancerStatus) v12.IngressStatus {
	var ingresses []v1.LoadBalancerIngress
	for _, ingress := range in.Ingress {
		ingresses = append(ingresses, v1.LoadBalancerIngress{
			IP: ingress.IP,
			// TODO: handle host/port fields
		})
	}
	return v12.IngressStatus{
		LoadBalancer: v1.LoadBalancerStatus{
			Ingress: ingresses,
		},
	}
}

func getIngressForStatusUpdate(slimIngress *slim_networkingv1.Ingress, lb slim_corev1.LoadBalancerStatus) *v12.Ingress {
	slimIngressCopy := slimIngress.DeepCopy()
	return &v12.Ingress{
		TypeMeta:   toV1TypeMeta(slimIngressCopy.TypeMeta),
		ObjectMeta: toV1ObjectMeta(slimIngressCopy.ObjectMeta),
		Status:     toV1IngressStatus(lb),
	}
}

func (ic *ingressController) syncLoadBalancerIPs(service *slim_corev1.Service) error {
	serviceKey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		return err
	}
	ingressKey := getIngressKeyForService(service)
	ingress, err := ic.getIngressFromCache(ingressKey)
	if err != nil {
		ic.logger.WithError(err).WithField("service", serviceKey).Warn("Failed to lookup ingress for service")
		return err
	}
	ic.logger.WithField("ingress", ingressKey).WithField("service", serviceKey).
		WithField("svc-status", service.Status.LoadBalancer).
		WithField("ingress-status", ingress.Status.LoadBalancer).
		Info("Checking ingress status")
	if reflect.DeepEqual(service.Status.LoadBalancer, ingress.Status.LoadBalancer) {
		ic.logger.Info("No change in load balancer status")
		return nil
	}

	newIngressStatus := getIngressForStatusUpdate(ingress, service.Status.LoadBalancer)
	ic.logger.WithField("ingress", ingressKey).WithField("service", serviceKey).
		WithField("svc-status", service.Status.LoadBalancer).
		WithField("new-status", newIngressStatus).
		Info("Updating ingress status")
	_, err = k8s.Client().NetworkingV1().Ingresses(ingress.Namespace).UpdateStatus(context.Background(), newIngressStatus, metav1.UpdateOptions{})
	if err != nil {
		ic.logger.WithError(err).Warn("Failed to update ingress status")
	}
	ic.logger.WithError(err).WithFields(logrus.Fields{
		"service":       serviceKey,
		"ingress":       ingressKey,
		"load-balancer": service.Status.LoadBalancer,
	}).Info("Updated ingress status")
	return err
}

func (ic *ingressController) handleServiceAddedEvent(event serviceAddedEvent) error {
	return ic.syncLoadBalancerIPs(event.service)
}

func (ic *ingressController) handleServiceUpdatedEvent(event serviceUpdatedEvent) error {
	if event.newService.ObjectMeta.GetDeletionTimestamp() != nil {
		// This means the service is in the process of being deleted, cleaning up load balancers
		// and such. Nothing to do in this case.
		ic.logger.WithFields(logrus.Fields{
			"svc-namespace": event.newService.Namespace,
			"svc-name":      event.newService.Name,
		}).Debug("Service is being deleted")
		return nil
	}
	ic.logger.WithField("old", event.oldService).WithField("new", event.newService).Info("Handling service update")
	return ic.syncLoadBalancerIPs(event.newService)
}

func (ic *ingressController) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case ingressAddedEvent:
		ic.logger.Info("handling ingress added event")
		err = ic.handleIngressAddedEvent(ev)
		break
	case ingressUpdatedEvent:
		ic.logger.Info("handling ingress updated event")
		break
	case ingressDeletedEvent:
		ic.logger.Info("handling ingress deleted event")
		err = ic.handleIngressDeletedEvent(ev)
		break
	case serviceAddedEvent:
		ic.logger.Info("handling service added event")
		err = ic.handleServiceAddedEvent(ev)
		break
	case serviceUpdatedEvent:
		ic.logger.Info("handling service updated event")
		err = ic.handleServiceUpdatedEvent(ev)
		break
	case serviceDeletedEvent:
		ic.logger.Info("handling service deleted event")
		break
	default:
		err = fmt.Errorf("received an unknown event: %s", ev)
	}
	return err
}

func (ic *ingressController) getIngressFromCache(key string) (*slim_networkingv1.Ingress, error) {
	objFromCache, exists, err := ic.ingressStore.GetByKey(key)
	if err != nil {
		ic.logger.WithError(err).Warn("Ingress cache lookup failed")
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("ingress '%s' not found", key)
	}
	ingress, ok := objFromCache.(*slim_networkingv1.Ingress)
	if !ok {
		return nil, fmt.Errorf("got an invalid object from ingress cache")
	}
	return ingress, nil
}

func getServiceNameForIngress(ingress *slim_networkingv1.Ingress) string {
	return ciliumIngressPrefix + ingress.Name
}

func getIngressKeyForService(service *slim_corev1.Service) string {
	ingressName := strings.TrimPrefix(service.Name, ciliumIngressPrefix)
	return fmt.Sprintf("%s/%s", service.Namespace, ingressName)
}

func getServiceForIngress(ingress *slim_networkingv1.Ingress) *v1.Service {
	ports := []v1.ServicePort{
		{
			Name:     "http",
			Protocol: "TCP",
			Port:     80,
			// TODO(michi) how do we deal with multiple target ports?
			TargetPort: intstr.IntOrString{IntVal: ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number},
		},
	}
	if len(ingress.Spec.TLS) > 0 {
		ports = []v1.ServicePort{
			{
				Name:     "https",
				Protocol: "TCP",
				Port:     443,
				// TODO(michi) how do we deal with multiple target ports?
				TargetPort: intstr.IntOrString{IntVal: ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number},
			},
		}
	}
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getServiceNameForIngress(ingress),
			Namespace: ingress.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
		},
		Spec: v1.ServiceSpec{
			Ports: ports,
			Type:  v1.ServiceTypeLoadBalancer,
		},
	}
}

func getEndpointsForIngress(ingress *slim_networkingv1.Ingress) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getServiceNameForIngress(ingress),
			Namespace: ingress.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{{IP: "192.192.192.192"}}, // dummy
				Ports:     []v1.EndpointPort{{Port: ingress.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number}},
			},
		},
	}
}

func (ic *ingressController) createLoadBalancer(ingress *slim_networkingv1.Ingress) error {
	svc := getServiceForIngress(ingress)
	svcKey, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		ic.logger.Warn("failed to get service key for ingress")
		return err
	}
	objFromCache, exists, err := ic.serviceStore.GetByKey(svcKey)
	if err != nil {
		ic.logger.WithError(err).Warn("service lookup returned an error")
		return err
	}
	if exists {
		_, ok := objFromCache.(*slim_corev1.Service)
		if !ok {
			return fmt.Errorf("got invalid object from cache")
		}
		// Service already exists in the cache. For now assume that it was created by the ingress
		// controller.
		log.WithField("service", svcKey).Info("Service already exists. Continuing...")
		return nil
	}
	_, err = k8s.Client().CoreV1().Services(ingress.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField("ingress", ingress.Name).Error("Failed to create a service for ingress")
	} else {
		log.WithField("service", svcKey).Info("Created Service for Ingress")
	}
	return err
}

func (ic *ingressController) createEndpoints(ingress *slim_networkingv1.Ingress) error {
	endpoints := getEndpointsForIngress(ingress)
	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		ic.logger.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}

	// check if the endpoints resource already exists
	objFromCache, exists, err := ic.endpointsStore.GetByKey(key)
	if err != nil {
		ic.logger.WithError(err).Warn("endpoints lookup returned an error")
		return err
	}
	if exists {
		_, ok := objFromCache.(*slim_corev1.Endpoints)
		if !ok {
			return fmt.Errorf("got invalid object from cache")
		}
		// Endpoints already exists in the cache. For now assume that it was created by the ingress
		// controller.
		log.WithField("endpoints", key).Info("Endpoints already exists. Continuing...")
		return nil
	}
	_, err = k8s.Client().CoreV1().Endpoints(ingress.Namespace).Create(context.Background(), endpoints, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField("ingress", ingress.Name).Error("Failed to create endpoints for ingress")
	} else {
		log.WithField("endpoints", key).Info("Created Endpoints for Ingress")
	}
	return err
}

func (ic *ingressController) createEnvoyConfig(ingress *slim_networkingv1.Ingress) error {
	envoyConfig, err := ic.amazingIngressControllerBusinessLogic(ingress)
	if err != nil {
		return err
	}

	// check if the CiliumEnvoyConfig resource already exists
	key, err := cache.MetaNamespaceKeyFunc(envoyConfig)
	if err != nil {
		ic.logger.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	objFromCache, exists, err := ic.envoyConfigStore.GetByKey(key)
	if err != nil {
		ic.logger.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}
	if exists {
		_, ok := objFromCache.(*v2alpha1.CiliumEnvoyConfig)
		if !ok {
			return fmt.Errorf("got invalid object from cache")
		}
		// CiliumEnvoyConfig already exists in the cache. For now assume that it was created by the ingress
		// controller.
		log.WithField("cilium-envoy-config", key).Info("CiliumEnvoyConfig already exists. Continuing...")
		return nil
	}
	_, err = k8s.CiliumClient().CiliumV2alpha1().CiliumEnvoyConfigs().Create(context.Background(), envoyConfig, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField("ingress", ingress.Name).Error("Failed to create CiliumEnvoyConfig for ingress")
	}
	return err
}

func (ic *ingressController) deleteEndpoints(ingress *slim_networkingv1.Ingress) error {
	endpoints := getEndpointsForIngress(ingress)
	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		ic.logger.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	// check if the endpoints resource exists.
	_, exists, err := ic.endpointsStore.GetByKey(key)
	if err != nil {
		ic.logger.WithError(err).Warn("endpoints lookup returned an error")
		return err
	}
	if !exists {
		log.WithField("endpoints", key).Info("Endpoints already deleted. Continuing...")
		return nil
	}
	err = k8s.Client().CoreV1().Endpoints(ingress.Namespace).Delete(context.Background(), endpoints.Name, metav1.DeleteOptions{})
	if err != nil {
		log.WithError(err).WithField("ingress", ingress.Name).Error("Failed to delete endpoints for ingress")
	}
	return err
}

func (ic *ingressController) deleteLoadBalancer(ingress *slim_networkingv1.Ingress) error {
	service := getServiceForIngress(ingress)
	key, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		ic.logger.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	// check if the service resource exists.
	_, exists, err := ic.serviceStore.GetByKey(key)
	if err != nil {
		ic.logger.WithError(err).Warn("service lookup returned an error")
		return err
	}
	if !exists {
		ic.logger.WithField("service", key).Info("Service already deleted. Continuing...")
		return nil
	}
	err = k8s.Client().CoreV1().Services(ingress.Namespace).Delete(context.Background(), getServiceNameForIngress(ingress), metav1.DeleteOptions{})
	if err != nil {
		ic.logger.WithError(err).WithField("ingress", ingress.Name).Error("Failed to delete a service for ingress")
	} else {
		ic.logger.WithField("service", key).Info("Deleted Service")
	}
	return err
}

func (ic *ingressController) handleAddIngress(obj interface{}) {
	ic.logger.Info("Received ingress added event from k8s")
	ingress, ok := obj.(*slim_networkingv1.Ingress)
	if !ok {
		ic.logger.Warn("failed to cast to slim ingress")
		return
	}
	ic.queue.Add(ingressAddedEvent{ingress: ingress})
}

func (ic *ingressController) handleUpdateIngress(oldObj, newObj interface{}) {
	oldIngress, ok := oldObj.(*slim_networkingv1.Ingress)
	if !ok {
		return
	}
	newIngress, ok := newObj.(*slim_networkingv1.Ingress)
	if !ok {
		return
	}
	ic.queue.Add(ingressUpdatedEvent{oldIngress: oldIngress, newIngress: newIngress})
}

func (ic *ingressController) handleDeleteIngress(obj interface{}) {
	switch concreteObj := obj.(type) {
	case *slim_networkingv1.Ingress:
		ic.queue.Add(ingressDeletedEvent{ingress: concreteObj})
	case cache.DeletedFinalStateUnknown:
		ingress, ok := concreteObj.Obj.(*slim_networkingv1.Ingress)
		if ok {
			ic.queue.Add(ingressDeletedEvent{ingress: ingress})
		}
	default:
		return
	}
}

func (ic *ingressController) deleteCiliumEnvoyConfig(ingress *slim_networkingv1.Ingress) error {
	// check if the CiliumEnvoyConfig resource exists.
	_, exists, err := ic.envoyConfigStore.GetByKey(ingress.Name)
	if err != nil {
		ic.logger.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}
	if !exists {
		log.WithField("cilium-envoy-config", ingress.Name).Info("CiliumEnvoyConfig already deleted. Continuing...")
		return nil
	}
	err = k8s.CiliumClient().CiliumV2alpha1().CiliumEnvoyConfigs().Delete(context.Background(), ingress.Name, v1meta.DeleteOptions{})
	if err != nil {
		log.WithError(err).WithField("cilium-envoy-config", ingress.Name).Error("Failed to delete CiliumEnvoyConfig for ingress")
	} else {
		log.WithField("cilium-envoy-config", ingress.Name).Info("Deleted CiliumEnvoyConfig")
	}
	return err
}
