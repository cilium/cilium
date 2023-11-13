// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	ciliumEnvoyLBPrefix = "cilium-envoy-lb"
)

func (r *ciliumEnvoyConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
		logfields.Controller: "ciliumenvoyconfig",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Starting reconciliation")

	svc := &corev1.Service{}
	if err := r.client.Get(ctx, req.NamespacedName, svc); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.WithError(err).Debug("Unable to get service - either deleted or not yet available")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if isLBProtocolAnnotationEnabled(svc) || hasAnyPort(svc, r.ports) {
		if err := r.createOrUpdateEnvoyConfig(ctx, svc); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.deleteEnvoyConfig(ctx, svc); err != nil {
			return ctrl.Result{}, err
		}
	}

	scopedLog.Info("Successfully reconciled")
	return ctrl.Result{}, nil
}

func hasAnyPort(svc *corev1.Service, ports []string) bool {
	for _, p := range ports {
		for _, port := range svc.Spec.Ports {
			if p == getServiceFrontendPort(port) {
				return true
			}
		}
	}
	return false
}

func getServiceFrontendPort(port corev1.ServicePort) string {
	if port.Port != 0 {
		return strconv.Itoa(int(port.Port))
	}
	if port.NodePort != 0 {
		return strconv.Itoa(int(port.NodePort))
	}
	return port.Name
}

func (r *ciliumEnvoyConfigReconciler) createOrUpdateEnvoyConfig(ctx context.Context, svc *corev1.Service) error {
	desired, err := r.getEnvoyConfigForService(svc)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEnvoyConfig for service: %w", err)
	}

	if err := controllerutil.SetControllerReference(svc, desired, r.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}

	exists := true
	existing := ciliumv2.CiliumEnvoyConfig{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: desired.Namespace, Name: desired.Name}, &existing); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf(" failed to lookup CiliumEnvoyConfig: %w", err)
		}
		exists = false
	}

	scopedLog := r.logger.WithField(logfields.ServiceKey, getName(svc))
	if exists {
		if desired.DeepEqual(&existing) {
			r.logger.WithField(logfields.CiliumEnvoyConfigName, fmt.Sprintf("%s/%s", desired.Namespace, desired.Name)).Debug("No change for existing CiliumEnvoyConfig")
			return nil
		}

		// Update existing CEC
		updated := existing.DeepCopy()
		updated.Spec = desired.Spec

		scopedLog.Debug("Updating CiliumEnvoyConfig")
		if err := r.client.Update(ctx, updated); err != nil {
			return fmt.Errorf("failed to update CiliumEnvoyConfig for service: %w", err)
		}

		scopedLog.Debug("Updated CiliumEnvoyConfig for service")
		return nil
	}

	scopedLog.Debug("Creating CiliumEnvoyConfig")
	if err := r.client.Create(ctx, desired); err != nil {
		return fmt.Errorf("failed to create CiliumEnvoyConfig for service: %w", err)
	}

	scopedLog.Debug("Created CiliumEnvoyConfig for service")
	return nil
}

func (r *ciliumEnvoyConfigReconciler) deleteEnvoyConfig(ctx context.Context, svc *corev1.Service) error {
	existing := ciliumv2.CiliumEnvoyConfig{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: svc.Namespace, Name: fmt.Sprintf("%s-%s", ciliumEnvoyLBPrefix, svc.Name)}, &existing); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to lookup CiliumEnvoyConfig: %w", err)
		}
		return nil
	}

	r.logger.Debug("Deleting CiliumEnvoyConfig")
	if err := r.client.Delete(ctx, &existing); err != nil {
		return fmt.Errorf("failed to delete CiliumEnvoyConfig for service: %w", err)
	}

	return nil
}
