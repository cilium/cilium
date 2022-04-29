// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
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

type ingressServiceUpdatedEvent struct {
	ingressService *slim_corev1.Service
}

// IngressController is a simple pattern that allows to perform the following
// tasks:
//   - Watch cilium Ingress object
//   - Manage related child resources for this Ingress
//   	- Service
//      - Endpoint
//      - CiliumEnvoyConfig
//   - Manage synced TLS secrets in given namespace
//		- TLS secrets
type IngressController struct {
	ingressInformer cache.Controller
	ingressStore    cache.Store

	serviceManager     *serviceManager
	endpointManager    *endpointManager
	envoyConfigManager *envoyConfigManager
	secretManager      secretManager

	queue      workqueue.RateLimitingInterface
	maxRetries int

	enforcedHTTPS      bool
	enabledSecretsSync bool
	secretsNamespace   string
}

// NewIngressController returns a controller for ingress objects having ingressClassName as cilium
func NewIngressController(options ...Option) (*IngressController, error) {
	opts := DefaultIngressOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}

	ic := &IngressController{
		queue:              workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries:         opts.MaxRetries,
		enforcedHTTPS:      opts.EnforcedHTTPS,
		enabledSecretsSync: opts.EnabledSecretsSync,
		secretsNamespace:   opts.SecretsNamespace,
	}
	ic.ingressStore, ic.ingressInformer = informer.NewInformer(
		cache.NewListWatchFromClient(k8s.WatcherClient().NetworkingV1().RESTClient(), "ingresses", corev1.NamespaceAll, fields.Everything()),
		&slim_networkingv1.Ingress{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    ic.handleAddIngress,
			UpdateFunc: ic.handleUpdateIngress,
			DeleteFunc: ic.handleDeleteIngress,
		},
		nil,
	)

	serviceManager, err := newServiceManager(ic.queue, opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.serviceManager = serviceManager

	endpointManager, err := newEndpointManager(opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.endpointManager = endpointManager

	envoyConfigManager, err := newEnvoyConfigManager(opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.envoyConfigManager = envoyConfigManager

	ic.secretManager = newNoOpsSecretManager()
	if ic.enabledSecretsSync {
		secretManager, err := newSyncSecretsManager(opts.SecretsNamespace, opts.MaxRetries)
		if err != nil {
			return nil, err
		}
		ic.secretManager = secretManager
	}

	return ic, nil
}

// Run kicks off the controlled loop
func (ic *IngressController) Run() {
	defer ic.queue.ShutDown()
	go ic.ingressInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.ingressInformer.HasSynced) {
		return
	}

	go ic.serviceManager.Run()
	go ic.secretManager.Run()

	for ic.processEvent() {
	}
}

func (ic *IngressController) processEvent() bool {
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
		log.Errorf("Failed to process Ingress event, skipping: %s", event)
		ic.queue.Forget(event)
	}
	return true
}

func (ic *IngressController) handleIngressAddedEvent(event ingressAddedEvent) error {
	ingressClass := event.ingress.Spec.IngressClassName
	if ingressClass == nil || *ingressClass != ciliumIngressClassName {
		return nil
	}

	ic.secretManager.Add(event)
	if err := ic.createEnvoyConfig(event.ingress); err != nil {
		log.WithError(err).Warn("Failed to create CiliumEnvoyConfig")
		return err
	}
	if err := ic.createEndpoints(event.ingress); err != nil {
		log.WithError(err).Warn("Failed to create endpoints")
		return err
	}
	if err := ic.createLoadBalancer(event.ingress); err != nil {
		log.WithError(err).Warn("Failed to create load balancer")
		return err
	}
	return nil
}

func (ic *IngressController) handleIngressUpdatedEvent(event ingressUpdatedEvent) error {
	ingressClass := event.newIngress.Spec.IngressClassName
	if ingressClass == nil || *ingressClass != ciliumIngressClassName {
		return nil
	}
	ic.secretManager.Add(event)
	if err := ic.createEnvoyConfig(event.newIngress); err != nil {
		log.WithError(err).Warn("Failed to update CiliumEnvoyConfig")
		return err
	}
	if err := ic.createEndpoints(event.newIngress); err != nil {
		log.WithError(err).Warn("Failed to update endpoints")
		return err
	}
	if err := ic.createLoadBalancer(event.newIngress); err != nil {
		log.WithError(err).Warn("Failed to update load balancer")
		return err
	}
	return nil
}

func (ic *IngressController) handleIngressDeletedEvent(event ingressDeletedEvent) error {
	log.WithField(logfields.Ingress, event.ingress.Name).Debug("Deleting CiliumEnvoyConfig for ingress")
	ic.secretManager.Add(event)
	if err := ic.deleteCiliumEnvoyConfig(event.ingress); err != nil {
		log.WithError(err).Warn("Failed to delete cilium-envoy-config")
		return err
	}
	return nil
}

func (ic *IngressController) handleIngressServiceUpdatedEvent(ingressServiceUpdated ingressServiceUpdatedEvent) error {
	service := ingressServiceUpdated.ingressService
	serviceKey, err := cache.MetaNamespaceKeyFunc(service)
	if err != nil {
		return err
	}
	ingressKey := getIngressKeyForService(service)
	ingress, err := ic.getByKey(ingressKey)
	if err != nil {
		return err
	}
	scopedLog := log.WithFields(map[string]interface{}{
		logfields.Ingress:    ingressKey,
		logfields.ServiceKey: serviceKey,
		"svc-status":         service.Status.LoadBalancer,
		"ingress-status":     ingress.Status.LoadBalancer,
	})

	if service.Status.LoadBalancer.DeepEqual(&ingress.Status.LoadBalancer) {
		return nil
	}

	newIngressStatus := getIngressForStatusUpdate(ingress, service.Status.LoadBalancer)
	_, err = k8s.Client().NetworkingV1().Ingresses(ingress.Namespace).UpdateStatus(context.Background(), newIngressStatus, metav1.UpdateOptions{})
	if err != nil {
		scopedLog.WithError(err).Warn("Failed to update ingress status")
		return err
	}
	scopedLog.Debug("Updated ingress status")
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

func getIngressForStatusUpdate(slimIngress *slim_networkingv1.Ingress, lb slim_corev1.LoadBalancerStatus) *networkingv1.Ingress {
	slimIngressCopy := slimIngress.DeepCopy()
	return &networkingv1.Ingress{
		TypeMeta:   toV1TypeMeta(slimIngressCopy.TypeMeta),
		ObjectMeta: toV1ObjectMeta(slimIngressCopy.ObjectMeta),
		Status: networkingv1.IngressStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: k8s.ConvertToK8sV1LoadBalancerIngress(lb.Ingress),
			},
		},
	}
}

func (ic *IngressController) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case ingressAddedEvent:
		log.WithField(logfields.Ingress, ev.ingress.Name).Debug("Handling ingress added event")
		err = ic.handleIngressAddedEvent(ev)
	case ingressUpdatedEvent:
		log.WithField(logfields.Ingress, ev.newIngress.Name).Debug("Handling ingress updated event")
		err = ic.handleIngressUpdatedEvent(ev)
	case ingressDeletedEvent:
		log.WithField(logfields.Ingress, ev.ingress.Name).Debug("Handling ingress deleted event")
		err = ic.handleIngressDeletedEvent(ev)
	case ingressServiceUpdatedEvent:
		log.WithField(logfields.ServiceKey, ev.ingressService.Name).Debug("Handling ingress service updated event")
		err = ic.handleIngressServiceUpdatedEvent(ev)
	default:
		err = fmt.Errorf("received an unknown event: %t", ev)
	}
	return err
}

func (ic *IngressController) getByKey(key string) (*slim_networkingv1.Ingress, error) {
	objFromCache, exists, err := ic.ingressStore.GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("ingress '%s' not found", key)
	}
	ingress, ok := objFromCache.(*slim_networkingv1.Ingress)
	if !ok {
		return nil, fmt.Errorf("unexpected type found in service cache: %T", objFromCache)
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

func (ic *IngressController) createLoadBalancer(ingress *slim_networkingv1.Ingress) error {
	svc := getServiceForIngress(ingress)
	svcKey, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.Warn("Failed to get service key for ingress")
		return err
	}

	_, exists, err := ic.serviceManager.getByKey(svcKey)
	if err != nil {
		log.WithError(err).Warn("Service lookup returned an error")
		return err
	}
	if exists {
		// Service already exists in the cache. For now assume that it was created by the ingress
		// controller.
		log.WithField(logfields.ServiceKey, svcKey).Debug("Service already exists. Continuing...")
		return nil
	}

	_, err = k8s.Client().CoreV1().Services(ingress.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField(logfields.Ingress, ingress.Name).Error("Failed to create a service for ingress")
		return err
	}
	log.WithField(logfields.ServiceKey, svcKey).Debug("Created Service for Ingress")
	return nil
}

func (ic *IngressController) createEndpoints(ingress *slim_networkingv1.Ingress) error {
	endpoints := getEndpointsForIngress(ingress)
	key, err := cache.MetaNamespaceKeyFunc(endpoints)
	if err != nil {
		return err
	}

	// check if the endpoints resource already exists
	_, exists, err := ic.endpointManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("Endpoints lookup returned an error")
		return err
	}
	if exists {
		// Endpoints already exists in the cache. For now assume that it was created by the ingress
		// controller.
		log.WithField(logfields.Endpoint, key).Debug("Endpoints already exists. Continuing...")
		return nil
	}

	_, err = k8s.Client().CoreV1().Endpoints(ingress.Namespace).Create(context.Background(), endpoints, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField(logfields.Ingress, ingress.Name).Error("Failed to create endpoints for ingress")
		return err
	}

	log.WithField(logfields.Endpoint, key).Debug("Created Endpoints for Ingress")
	return nil
}

func (ic *IngressController) createEnvoyConfig(ingress *slim_networkingv1.Ingress) error {
	desired, err := getEnvoyConfigForIngress(ingress, ic.secretsNamespace, ic.enforcedHTTPS)
	if err != nil {
		return err
	}

	// check if the CiliumEnvoyConfig resource already exists
	key, err := cache.MetaNamespaceKeyFunc(desired)
	if err != nil {
		log.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	existingEnvoyConfig, exists, err := ic.envoyConfigManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.Ingress, ingress.Name)
	if exists {
		if desired.DeepEqual(existingEnvoyConfig) {
			log.WithField(logfields.CiliumEnvoyConfigName, key).Debug("No change for existing CiliumEnvoyConfig")
			return nil
		}
		// Update existing CEC
		newEnvoyConfig := existingEnvoyConfig.DeepCopy()
		newEnvoyConfig.Spec = desired.Spec
		_, err = k8s.CiliumClient().CiliumV2().CiliumEnvoyConfigs(ingress.Namespace).Update(context.Background(), newEnvoyConfig, metav1.UpdateOptions{})
		if err != nil {
			scopedLog.WithError(err).Error("Failed to update CiliumEnvoyConfig for ingress")
			return err
		}
		scopedLog.Debug("Updated CiliumEnvoyConfig for ingress")
		return nil
	}
	_, err = k8s.CiliumClient().CiliumV2().CiliumEnvoyConfigs(ingress.Namespace).Create(context.Background(), desired, metav1.CreateOptions{})
	if err != nil {
		scopedLog.WithError(err).Error("Failed to create CiliumEnvoyConfig for ingress")
		return err
	}
	scopedLog.Debug("Created CiliumEnvoyConfig for ingress")
	return nil
}

func (ic *IngressController) handleAddIngress(obj interface{}) {
	if ingress := k8s.ObjToV1Ingress(obj); ingress != nil {
		ic.queue.Add(ingressAddedEvent{ingress: ingress})
	}
}

func (ic *IngressController) handleUpdateIngress(oldObj, newObj interface{}) {
	oldIngress := k8s.ObjToV1Ingress(oldObj)
	if oldIngress == nil {
		return
	}
	newIngress := k8s.ObjToV1Ingress(newObj)
	if newIngress == nil {
		return
	}
	if oldIngress.DeepEqual(newIngress) {
		return
	}
	ic.queue.Add(ingressUpdatedEvent{oldIngress: oldIngress, newIngress: newIngress})
}

func (ic *IngressController) handleDeleteIngress(obj interface{}) {
	if ingress := k8s.ObjToV1Ingress(obj); ingress != nil {
		ic.queue.Add(ingressDeletedEvent{ingress: ingress})
	}
}

func (ic *IngressController) deleteCiliumEnvoyConfig(ingress *slim_networkingv1.Ingress) error {
	// check if the CiliumEnvoyConfig resource exists.
	resourceName := getCECNameForIngress(ingress)
	_, exists, err := ic.envoyConfigManager.getByKey(resourceName)
	if err != nil {
		log.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.CiliumEnvoyConfigName, resourceName)
	if !exists {
		scopedLog.Debug("CiliumEnvoyConfig already deleted. Continuing...")
		return nil
	}
	err = k8s.CiliumClient().CiliumV2().CiliumEnvoyConfigs(ingress.Namespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		scopedLog.Error("Failed to delete CiliumEnvoyConfig for ingress")
		return err
	}
	scopedLog.Debug("Deleted CiliumEnvoyConfig")
	return nil
}
