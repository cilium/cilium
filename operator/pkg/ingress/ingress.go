// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	ciliumIngressPrefix    = "cilium-ingress-"
	ciliumIngressLabelKey  = "cilium.io/ingress"
	ciliumIngressClassName = "cilium"

	dedicatedLoadbalancerMode = "dedicated"
	sharedLoadbalancerMode    = "shared"
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

// Controller is a simple pattern that allows to perform the following
// tasks:
//  1. Watch cilium Ingress object
//  2. Manage related child resources for this Ingress
//     - Service
//     - Endpoint
//     - CiliumEnvoyConfig
//  3. Manage synced TLS secrets in given namespace
//     - TLS secrets
type Controller struct {
	clientset k8sClient.Clientset

	ingressInformer cache.Controller
	ingressStore    cache.Store

	serviceManager      *serviceManager
	endpointManager     *endpointManager
	envoyConfigManager  *envoyConfigManager
	ingressClassManager *ingressClassManager
	secretManager       secretManager

	queue      workqueue.RateLimitingInterface
	maxRetries int

	sharedTranslator    translation.Translator
	dedicatedTranslator translation.Translator

	enforcedHTTPS           bool
	enabledSecretsSync      bool
	secretsNamespace        string
	lbAnnotationPrefixes    []string
	sharedLBServiceName     string
	ciliumNamespace         string
	defaultLoadbalancerMode string
	isDefaultIngressClass   bool

	sharedLBStatus *slim_corev1.LoadBalancerStatus
}

// NewController returns a controller for ingress objects having ingressClassName as cilium
func NewController(clientset k8sClient.Clientset, options ...Option) (*Controller, error) {
	opts := DefaultIngressOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}

	ic := &Controller{
		clientset:               clientset,
		queue:                   workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries:              opts.MaxRetries,
		enforcedHTTPS:           opts.EnforcedHTTPS,
		enabledSecretsSync:      opts.EnabledSecretsSync,
		secretsNamespace:        opts.SecretsNamespace,
		lbAnnotationPrefixes:    opts.LBAnnotationPrefixes,
		sharedLBServiceName:     opts.SharedLBServiceName,
		ciliumNamespace:         opts.CiliumNamespace,
		defaultLoadbalancerMode: opts.DefaultLoadbalancerMode,
		sharedTranslator:        ingressTranslation.NewSharedIngressTranslator(opts.SharedLBServiceName, opts.CiliumNamespace, opts.SecretsNamespace, opts.EnforcedHTTPS, opts.IdleTimeoutSeconds),
		dedicatedTranslator:     ingressTranslation.NewDedicatedIngressTranslator(opts.SecretsNamespace, opts.EnforcedHTTPS, opts.IdleTimeoutSeconds),
	}
	ic.ingressStore, ic.ingressInformer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_networkingv1.IngressList](clientset.Slim().NetworkingV1().Ingresses(corev1.NamespaceAll)),
		&slim_networkingv1.Ingress{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if ingress := k8s.ObjToV1Ingress(obj); ingress != nil {
					ic.queue.Add(ingressAddedEvent{ingress: ingress})
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
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
			},
			DeleteFunc: func(obj interface{}) {
				if ingress := k8s.ObjToV1Ingress(obj); ingress != nil {
					ic.queue.Add(ingressDeletedEvent{ingress: ingress})
				}
			},
		},
		nil,
	)

	ingressClassManager, err := newIngressClassManager(clientset, ic.queue, opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.ingressClassManager = ingressClassManager

	serviceManager, err := newServiceManager(clientset, ic.queue, opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.serviceManager = serviceManager

	endpointManager, err := newEndpointManager(clientset, opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.endpointManager = endpointManager

	envoyConfigManager, err := newEnvoyConfigManager(clientset, opts.MaxRetries)
	if err != nil {
		return nil, err
	}
	ic.envoyConfigManager = envoyConfigManager

	ic.secretManager = newNoOpsSecretManager()
	if ic.enabledSecretsSync {
		secretManager, err := newSyncSecretsManager(clientset, opts.SecretsNamespace, opts.MaxRetries)
		if err != nil {
			return nil, err
		}
		ic.secretManager = secretManager
	}
	ic.sharedLBStatus = ic.retrieveSharedLBServiceStatus()

	return ic, nil
}

// Run kicks off the controlled loop
func (ic *Controller) Run() {
	defer ic.queue.ShutDown()
	go ic.ingressInformer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, ic.ingressInformer.HasSynced) {
		return
	}

	go ic.ingressClassManager.Run()
	go ic.serviceManager.Run()
	go ic.secretManager.Run()

	for ic.processEvent() {
	}
}

func (ic *Controller) processEvent() bool {
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
		log.WithError(err).Errorf("Failed to process Ingress event, skipping: %s", event)
		ic.queue.Forget(event)
	}
	return true
}

func getIngressClassName(ingress *slim_networkingv1.Ingress) *string {
	annotations := ingress.GetAnnotations()
	if className, ok := annotations["kubernetes.io/ingress.class"]; ok {
		return &className
	}

	return ingress.Spec.IngressClassName
}

func hasEmptyIngressClass(ingress *slim_networkingv1.Ingress) bool {
	className := getIngressClassName(ingress)

	return className == nil || *className == ""
}

func (ic *Controller) isCiliumIngressEntry(ingress *slim_networkingv1.Ingress) bool {
	className := getIngressClassName(ingress)

	if (className == nil || *className == "") && ic.isDefaultIngressClass {
		return true
	}

	return className != nil && *className == ciliumIngressClassName
}

func (ic *Controller) handleIngressAddedEvent(event ingressAddedEvent) error {
	if !ic.isCiliumIngressEntry(event.ingress) {
		// this could have been our class before we should clean up
		err := ic.garbageCollectOwnedResources(event.ingress)
		if err != nil {
			return err
		}

		log.WithField(logfields.Ingress, event.ingress.Name).WithField(logfields.K8sNamespace, event.ingress.Namespace).Debug("Skipping ingress as it is not the cilium class or default")
		return nil
	}

	ic.secretManager.Add(event)
	return ic.ensureResources(event.ingress, false)
}

func (ic *Controller) handleIngressUpdatedEvent(event ingressUpdatedEvent) error {
	if !ic.isCiliumIngressEntry(event.newIngress) {
		return nil
	}
	ic.secretManager.Add(event)

	// Perform clean up if there is change in LB mode
	oldLBMode := ic.isEffectiveLoadbalancerModeDedicated(event.oldIngress)
	newLBMode := ic.isEffectiveLoadbalancerModeDedicated(event.newIngress)

	// If the ingress is being switched from dedicated to shared, we need to
	// clean up the dedicated resources (service, endpoints, envoy config)
	if oldLBMode && !newLBMode {
		if err := ic.deleteResources(event.oldIngress); err != nil {
			log.WithError(err).Warn("Failed to delete resources for ingress")
			return err
		}
	}

	// If the ingress is being switched from shared to dedicated, we need to update
	// shared CiliumEnvoyConfig.
	if !oldLBMode && newLBMode {
		err := ic.ensureResources(event.newIngress, true)
		if err != nil {
			return err
		}
	}

	err := ic.ensureResources(event.newIngress, false)
	if err != nil {
		return err
	}
	return nil
}

func (ic *Controller) handleIngressDeletedEvent(event ingressDeletedEvent) error {
	log.WithField(logfields.Ingress, event.ingress.Name).WithField(logfields.K8sNamespace, event.ingress.Namespace).Debug("Deleting CiliumEnvoyConfig for ingress")
	ic.secretManager.Add(event)

	if ic.isEffectiveLoadbalancerModeDedicated(event.ingress) {
		if err := ic.deleteResources(event.ingress); err != nil {
			log.WithError(err).Warn("Failed to delete resources for ingress")
			return err
		}
		return nil
	}
	return ic.ensureResources(event.ingress, true)
}

func (ic *Controller) handleIngressServiceUpdatedEvent(ingressServiceUpdated ingressServiceUpdatedEvent) error {
	service := ingressServiceUpdated.ingressService

	var keys []string
	if service.GetName() == ic.sharedLBServiceName && service.GetNamespace() == ic.ciliumNamespace {
		ic.sharedLBStatus = &service.Status.LoadBalancer
		for _, ing := range ic.ingressStore.ListKeys() {
			item, _ := ic.getByKey(ing)
			if !ic.isCiliumIngressEntry(item) ||
				item.GetDeletionTimestamp() != nil {
				continue
			}
			if ic.isEffectiveLoadbalancerModeDedicated(item) {
				continue
			}
			keys = append(keys, ing)
		}
	} else {
		ingressKey := getIngressKeyForService(service)
		keys = append(keys, ingressKey)
	}

	for _, k := range keys {
		ing, err := ic.getByKey(k)
		if err != nil {
			return err
		}
		err = ic.updateIngressStatus(ing, &service.Status.LoadBalancer)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ic *Controller) handleCiliumIngressClassUpdatedEvent(event ciliumIngressClassUpdatedEvent) error {
	log.Debugf("Cilium IngressClass updated")
	previousValue := ic.isDefaultIngressClass
	if val, ok := event.ingressClass.GetAnnotations()[slim_networkingv1.AnnotationIsDefaultIngressClass]; ok {
		isDefault, err := strconv.ParseBool(val)
		if err != nil {
			log.WithError(err).Warnf("Failed to parse annotation value for %q", slim_networkingv1.AnnotationIsDefaultIngressClass)
			return err
		}
		ic.isDefaultIngressClass = isDefault
	} else {
		// if the annotation is not set we are not the default ingress class
		ic.isDefaultIngressClass = false
	}

	if previousValue != ic.isDefaultIngressClass {
		log.Debugf("Cilium IngressClass default value changed, re-syncing ingresses")
		// ensure that all ingresses are in the correct state
		for _, k := range ic.ingressStore.ListKeys() {
			ing, err := ic.getByKey(k)
			if err != nil {
				return err
			}

			if ic.isCiliumIngressEntry(ing) {
				// make sure that the ingress is in the correct state
				if err := ic.ensureResources(ing, false); err != nil {
					return err
				}
			} else if hasEmptyIngressClass(ing) && !ic.isDefaultIngressClass {
				// if we are no longer the default ingress class, we need to clean up
				// the resources that we created for the ingress
				if err := ic.deleteResources(ing); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (ic *Controller) handleCiliumIngressClassDeletedEvent(event ciliumIngressClassDeletedEvent) error {
	log.Debug("Cilium IngressClass deleted")

	if ic.isDefaultIngressClass {
		// if we were the default ingress class, we need to clean up all ingresses
		for _, k := range ic.ingressStore.ListKeys() {
			ing, err := ic.getByKey(k)
			if err != nil {
				return err
			}

			if hasEmptyIngressClass(ing) {
				// if we are no longer the default ingress class, we need to clean up
				// the resources that we created for the ingress
				if err := ic.deleteResources(ing); err != nil {
					return err
				}
			}
		}

		// disable the default ingress class behavior
		ic.isDefaultIngressClass = false
	}
	return nil
}

func (ic *Controller) ensureResources(ing *slim_networkingv1.Ingress, forceShared bool) error {
	cec, svc, ep, err := ic.regenerate(ing, forceShared)
	if err != nil {
		log.WithError(err).Warn("Failed to generate resources")
		return err
	}

	if err = ic.createEnvoyConfig(cec); err != nil {
		log.WithError(err).Warn("Failed to create CiliumEnvoyConfig")
		return err
	}

	if err := ic.createLoadBalancer(svc); err != nil {
		log.WithError(err).Warn("Failed to create load balancer")
		return err
	}

	if err := ic.createEndpoints(ep); err != nil {
		log.WithError(err).Warn("Failed to create endpoints")
		return err
	}

	if !ic.isEffectiveLoadbalancerModeDedicated(ing) {
		err = ic.updateIngressStatus(ing, ic.sharedLBStatus)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ic *Controller) updateIngressStatus(ing *slim_networkingv1.Ingress, status *slim_corev1.LoadBalancerStatus) error {
	if ing == nil || status == nil || k8s.ConvertToSlimIngressLoadBalancerStatus(status).DeepEqual(&ing.Status.LoadBalancer) {
		return nil
	}

	newIngressStatus := getIngressForStatusUpdate(ing, *status)
	_, err := ic.clientset.NetworkingV1().Ingresses(ing.GetNamespace()).
		UpdateStatus(context.Background(), newIngressStatus, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warn("Failed to update ingress status")
		return err
	}
	return nil
}

func getIngressForStatusUpdate(slimIngress *slim_networkingv1.Ingress, lb slim_corev1.LoadBalancerStatus) *networkingv1.Ingress {
	slimIngressCopy := slimIngress.DeepCopy()
	return &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			Kind:       slimIngress.Kind,
			APIVersion: slimIngress.APIVersion,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            slimIngressCopy.GetName(),
			Namespace:       slimIngressCopy.GetNamespace(),
			ResourceVersion: slimIngressCopy.GetResourceVersion(),
			UID:             slimIngressCopy.GetUID(),
			Labels:          slimIngressCopy.GetLabels(),
			Annotations:     slimIngressCopy.GetAnnotations(),
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: k8s.ConvertToNetworkV1IngressLoadBalancerIngress(lb.Ingress),
			},
		},
	}
}

func (ic *Controller) handleEvent(event interface{}) error {
	var err error
	switch ev := event.(type) {
	case ingressAddedEvent:
		log.WithField(logfields.Ingress, ev.ingress.Name).WithField(logfields.K8sNamespace, ev.ingress.Namespace).Debug("Handling ingress added event")
		err = ic.handleIngressAddedEvent(ev)
	case ingressUpdatedEvent:
		log.WithField(logfields.Ingress, ev.newIngress.Name).WithField(logfields.K8sNamespace, ev.newIngress.Namespace).Debug("Handling ingress updated event")
		err = ic.handleIngressUpdatedEvent(ev)
	case ingressDeletedEvent:
		log.WithField(logfields.Ingress, ev.ingress.Name).WithField(logfields.K8sNamespace, ev.ingress.Namespace).Debug("Handling ingress deleted event")
		err = ic.handleIngressDeletedEvent(ev)
	case ingressServiceUpdatedEvent:
		log.WithField(logfields.ServiceKey, ev.ingressService.Name).WithField(logfields.K8sNamespace, ev.ingressService.Namespace).Debug("Handling ingress service updated event")
		err = ic.handleIngressServiceUpdatedEvent(ev)
	case ciliumIngressClassUpdatedEvent:
		log.WithField(logfields.IngressClass, ev.ingressClass.Name).Debug("Handling cilium ingress class updated event")
		err = ic.handleCiliumIngressClassUpdatedEvent(ev)
	case ciliumIngressClassDeletedEvent:
		log.WithField(logfields.IngressClass, ev.ingressClass.Name).Debug("Handling cilium ingress class deleted event")
		err = ic.handleCiliumIngressClassDeletedEvent(ev)
	default:
		err = fmt.Errorf("received an unknown event: %t", ev)
	}
	return err
}

func (ic *Controller) getByKey(key string) (*slim_networkingv1.Ingress, error) {
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

func getIngressKeyForService(service *slim_corev1.Service) string {
	ingressName := strings.TrimPrefix(service.Name, ciliumIngressPrefix)
	return fmt.Sprintf("%s/%s", service.Namespace, ingressName)
}

func (ic *Controller) createEnvoyConfig(cec *ciliumv2.CiliumEnvoyConfig) error {
	if cec == nil {
		return nil
	}
	// check if the CiliumEnvoyConfig resource already exists
	key, err := cache.MetaNamespaceKeyFunc(cec)
	if err != nil {
		log.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	existingEnvoyConfig, exists, err := ic.envoyConfigManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}

	if exists {
		if cec.DeepEqual(existingEnvoyConfig) {
			log.WithField(logfields.CiliumEnvoyConfigName, key).Debug("No change for existing CiliumEnvoyConfig")
			return nil
		}
		// Update existing CEC
		newEnvoyConfig := existingEnvoyConfig.DeepCopy()
		newEnvoyConfig.Spec = cec.Spec
		newEnvoyConfig.OwnerReferences = cec.OwnerReferences
		_, err = ic.clientset.CiliumV2().CiliumEnvoyConfigs(cec.GetNamespace()).Update(context.Background(), newEnvoyConfig, metav1.UpdateOptions{})
		if err != nil {
			log.WithError(err).Error("Failed to update CiliumEnvoyConfig for ingress")
			return err
		}
		log.Debug("Updated CiliumEnvoyConfig for ingress")
		return nil
	}
	_, err = ic.clientset.CiliumV2().CiliumEnvoyConfigs(cec.GetNamespace()).Create(context.Background(), cec, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to create CiliumEnvoyConfig for ingress")
		return err
	}
	log.Debug("Created CiliumEnvoyConfig for ingress")
	return nil
}

// regenerate regenerates the desired stage for all related resources.
// This internally leverage different Ingress translators (e.g. shared vs dedicated).
// If forceShared is true, only the shared translator will be used.
func (ic *Controller) regenerate(ing *slim_networkingv1.Ingress, forceShared bool) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: ing.GetNamespace(),
		logfields.Ingress:      ing.GetName(),
	})

	var translator translation.Translator
	m := &model.Model{}
	if !forceShared && ic.isEffectiveLoadbalancerModeDedicated(ing) {
		translator = ic.dedicatedTranslator
		m.HTTP = ingestion.Ingress(*ing)
	} else {
		translator = ic.sharedTranslator
		for _, k := range ic.ingressStore.ListKeys() {
			item, _ := ic.getByKey(k)
			if !ic.isCiliumIngressEntry(item) || ic.isEffectiveLoadbalancerModeDedicated(item) ||
				ing.GetDeletionTimestamp() != nil {
				continue
			}
			m.HTTP = append(m.HTTP, ingestion.Ingress(*item)...)
		}
	}

	scopedLog.WithFields(logrus.Fields{
		"forcedShared": forceShared,
		"model":        m,
	}).Debug("Generated model for ingress")
	cec, svc, ep, err := translator.Translate(m)
	// Propagate Ingress annotation if required. This is applicable only for dedicated LB mode.
	// For shared LB mode, the service annotation is defined in other higher level (e.g. helm).
	if svc != nil {
		for key, value := range ing.GetAnnotations() {
			for _, prefix := range ic.lbAnnotationPrefixes {
				if strings.HasPrefix(key, prefix) {
					if svc.Annotations == nil {
						svc.Annotations = make(map[string]string)
					}
					svc.Annotations[key] = value
				}
			}
		}
	}
	scopedLog.WithFields(logrus.Fields{
		"ciliumEnvoyConfig": cec,
		"service":           svc,
		logfields.Endpoint:  ep,
	}).Debugf("Translated resources for ingress")
	return cec, svc, ep, err
}

func (ic *Controller) retrieveSharedLBServiceStatus() *slim_corev1.LoadBalancerStatus {
	key := fmt.Sprintf("%s/%s", ic.ciliumNamespace, ic.sharedLBServiceName)
	svc, exists, err := ic.serviceManager.getByKey(key)
	if err != nil || !exists {
		return nil
	}
	return &svc.Status.LoadBalancer
}

func (ic *Controller) isEffectiveLoadbalancerModeDedicated(ing *slim_networkingv1.Ingress) bool {
	value := annotations.GetAnnotationIngressLoadbalancerMode(ing)
	switch value {
	case dedicatedLoadbalancerMode:
		return true
	case sharedLoadbalancerMode:
		return false
	default:
		return ic.defaultLoadbalancerMode == dedicatedLoadbalancerMode
	}
}

func (ic *Controller) garbageCollectOwnedResources(ing *slim_networkingv1.Ingress) error {
	cec, svc, ep, err := ic.regenerate(ing, false)
	if err != nil {
		return err
	}

	if cec != nil {
		if err := deleteObjectIfExists(cec, ic.envoyConfigManager.getByKey, ic.clientset.CiliumV2().CiliumEnvoyConfigs(cec.GetNamespace()).Delete); err != nil {
			return err
		}
	}

	if svc != nil {
		if err := deleteObjectIfExists(svc, ic.serviceManager.getByKey, ic.clientset.CoreV1().Services(svc.GetNamespace()).Delete); err != nil {
			return err
		}
	}

	if ep != nil {
		if err := deleteObjectIfExists(ep, ic.endpointManager.getByKey, ic.clientset.CoreV1().Endpoints(ep.GetNamespace()).Delete); err != nil {
			return err
		}
	}

	return nil

}

// deleteObjectIfExists checks the caches to see if the object exists and if so, deletes it. It uses caches as to limit API server requests for objects may have never existed.
func deleteObjectIfExists[T any](obj metav1.Object, getByKey func(string) (T, bool, error), deleter func(ctx context.Context, name string, opts metav1.DeleteOptions) error) error {
	if obj == nil {
		return nil
	}
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		log.WithError(err).Warn("MetaNamespaceKeyFunc returned an error")
		return err
	}
	_, exists, err := getByKey(key)
	if err != nil {
		log.WithError(err).WithField(logfields.Object, obj).Warn("Cache lookup failed")
		return err
	}

	if exists {
		err = deleter(context.Background(), obj.GetName(), metav1.DeleteOptions{})
		if err != nil {
			log.WithError(err).WithField(logfields.Object, obj).Warn("Failed to delete object")
			return err
		}
		log.WithField(logfields.Object, obj).Debug("Deleted object which was no longer tracked")
		return nil
	}
	return nil
}
