// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (ic *Controller) createLoadBalancer(ingress *slim_networkingv1.Ingress) error {
	svc := getServiceForIngress(ingress, ic.lbAnnotationPrefixes)
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

	_, err = ic.clientset.CoreV1().Services(ingress.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField(logfields.Ingress, ingress.Name).Error("Failed to create a service for ingress")
		return err
	}
	log.WithField(logfields.ServiceKey, svcKey).Debug("Created Service for Ingress")
	return nil
}

func (ic *Controller) createEndpoints(ingress *slim_networkingv1.Ingress) error {
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

	_, err = ic.clientset.CoreV1().Endpoints(ingress.Namespace).Create(context.Background(), endpoints, metav1.CreateOptions{})
	if err != nil {
		log.WithError(err).WithField(logfields.Ingress, ingress.Name).Error("Failed to create endpoints for ingress")
		return err
	}

	log.WithField(logfields.Endpoint, key).Debug("Created Endpoints for Ingress")
	return nil
}

func (ic *Controller) deleteCiliumEnvoyConfig(ingress *slim_networkingv1.Ingress) error {
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
	err = ic.clientset.CiliumV2().CiliumEnvoyConfigs(ingress.Namespace).Delete(context.Background(), resourceName, metav1.DeleteOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		scopedLog.Error("Failed to delete CiliumEnvoyConfig for ingress")
		return err
	}
	scopedLog.Debug("Deleted CiliumEnvoyConfig")
	return nil
}
