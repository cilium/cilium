// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

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
