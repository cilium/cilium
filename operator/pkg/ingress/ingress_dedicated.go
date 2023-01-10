// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (ic *Controller) createLoadBalancer(svc *corev1.Service) error {
	if svc == nil {
		return nil
	}
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

	_, err = ic.clientset.CoreV1().Services(svc.GetNamespace()).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to create a service for ingress")
		return err
	}
	log.WithField(logfields.ServiceKey, svcKey).Debug("Created Service for Ingress")
	return nil
}

func (ic *Controller) createEndpoints(endpoints *corev1.Endpoints) error {
	if endpoints == nil {
		return nil
	}
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

	_, err = ic.clientset.CoreV1().Endpoints(endpoints.GetNamespace()).Create(context.Background(), endpoints, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to create endpoints for ingress")
		return err
	}

	log.WithField(logfields.Endpoint, key).Debug("Created Endpoints for Ingress")
	return nil
}

func (ic *Controller) deleteResources(ing *slim_networkingv1.Ingress) error {
	cec, svc, ep, err := ic.regenerate(ing, false)
	if err != nil {
		log.WithError(err).Warn("Failed to generate resources")
		return err
	}

	if err = ic.deleteCiliumEnvoyConfig(cec); err != nil {
		log.WithError(err).Warn("Failed to delete CiliumEnvoyConfig")
		return err
	}

	if err = ic.deleteService(svc); err != nil {
		log.WithError(err).Warn("Failed to delete load balancer")
		return err
	}

	if err = ic.deleteEndpoint(ep); err != nil {
		log.WithError(err).Warn("Failed to delete endpoints")
		return err
	}
	return nil
}

func (ic *Controller) deleteCiliumEnvoyConfig(cec *ciliumv2.CiliumEnvoyConfig) error {
	if cec == nil {
		return nil
	}
	// check if the CiliumEnvoyConfig resource exists.
	key, err := cache.MetaNamespaceKeyFunc(cec)
	if err != nil {
		return err
	}
	_, exists, err := ic.envoyConfigManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("CiliumEnvoyConfig lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.CiliumEnvoyConfigName, cec.GetName())
	if !exists {
		scopedLog.Debug("CiliumEnvoyConfig already deleted. Continuing...")
		return nil
	}
	err = ic.clientset.CiliumV2().CiliumEnvoyConfigs(cec.GetNamespace()).Delete(context.Background(), cec.GetName(), metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		scopedLog.Error("Failed to delete CiliumEnvoyConfig for ingress")
		return err
	}
	scopedLog.Debug("Deleted CiliumEnvoyConfig")
	return nil
}

func (ic *Controller) deleteService(svc *corev1.Service) error {
	if svc == nil {
		return nil
	}
	// check if the Service resource exists.
	key, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		return err
	}
	_, exists, err := ic.serviceManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("Service lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.CiliumEnvoyConfigName, svc.GetName())
	if !exists {
		scopedLog.Debug("Service already deleted. Continuing...")
		return nil
	}
	err = ic.clientset.CoreV1().Services(svc.GetNamespace()).Delete(context.Background(), svc.GetName(), metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		scopedLog.Error("Failed to delete service for ingress")
		return err
	}
	scopedLog.Debug("Deleted service")
	return nil
}

func (ic *Controller) deleteEndpoint(ep *corev1.Endpoints) error {
	if ep == nil {
		return nil
	}
	// check if the Endpoint resource exists.
	key, err := cache.MetaNamespaceKeyFunc(ep)
	if err != nil {
		return err
	}
	_, exists, err := ic.serviceManager.getByKey(key)
	if err != nil {
		log.WithError(err).Warn("Endpoint lookup failed")
		return err
	}

	scopedLog := log.WithField(logfields.CiliumEnvoyConfigName, ep.GetName())
	if !exists {
		scopedLog.Debug("Endpoint already deleted. Continuing...")
		return nil
	}
	err = ic.clientset.CoreV1().Endpoints(ep.GetNamespace()).Delete(context.Background(), ep.GetName(), metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		scopedLog.Error("Failed to delete endpoint for ingress")
		return err
	}
	scopedLog.Debug("Deleted endpoint")
	return nil
}
