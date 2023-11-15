// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (r *ingressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "ingress",
		logfields.Resource:   req.NamespacedName,
	})

	scopedLog.Info("Reconciling Ingress")
	ingress := &networkingv1.Ingress{}
	if err := r.client.Get(ctx, req.NamespacedName, ingress); err != nil {
		if !k8serrors.IsNotFound(err) {
			return controllerruntime.Fail(fmt.Errorf("failed to get Ingress: %w", err))
		}
		// Ingress deleted -> try to cleanup shared CiliumEnvoyConfig
		// Resources from LB mode dedicated are deleted via K8s Garbage Collection (OwnerReferences)
		if err := r.tryCleanupSharedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		return controllerruntime.Success()
	}

	// Ingress gets deleted via foreground deletion (DeletionTimestamp set)
	// -> abort and wait for the actual deletion to trigger a reconcile
	if ingress.GetDeletionTimestamp() != nil {
		scopedLog.Debug("Ingress is marked for deletion - waiting for actual deletion")
		return controllerruntime.Success()
	}

	// Ingress is no longer managed by Cilium.
	// Trying to cleanup resources.
	if !isCiliumManagedIngress(ctx, r.client, *ingress) {
		if err := r.tryCleanupSharedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		if err := r.tryCleanupDedicatedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		scopedLog.Info("Successfully cleaned Ingress resources")
		return controllerruntime.Success()
	}

	if r.isEffectiveLoadbalancerModeDedicated(ingress) {
		if err := r.createOrUpdateDedicatedResources(ctx, ingress); err != nil {
			return controllerruntime.Fail(err)
		}

		// Trying to cleanup shared resources (potential change of LB mode)
		if err := r.tryCleanupSharedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}
	} else {
		if err := r.createOrUpdateSharedResources(ctx, ingress); err != nil {
			return controllerruntime.Fail(err)
		}

		// Trying to cleanup dedicated resources (potential change of LB mode)
		if err := r.tryCleanupDedicatedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}
	}

	// Update status
	if err := r.client.Status().Update(ctx, ingress); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Ingress status: %w", err))
	}

	scopedLog.Info("Successfully reconciled Ingress")
	return controllerruntime.Success()
}

func (r *ingressReconciler) createOrUpdateDedicatedResources(ctx context.Context, ingress *networkingv1.Ingress) error {
	return nil
}

func (r *ingressReconciler) createOrUpdateSharedResources(ctx context.Context, ingress *networkingv1.Ingress) error {
	return nil
}

func (r *ingressReconciler) tryCleanupDedicatedResources(ctx context.Context, namespacedName types.NamespacedName) error {
	return nil
}

func (r *ingressReconciler) tryCleanupSharedResources(ctx context.Context, namespacedName types.NamespacedName) error {
	return nil
}

// regenerate regenerates the desired stage for all related resources.
// This internally leverage different Ingress translators (e.g. shared vs dedicated).
// If forceShared is true, only the shared translator will be used.
func (r *ingressReconciler) regenerate(ctx context.Context, ing *networkingv1.Ingress, forceShared bool) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sNamespace: ing.GetNamespace(),
		logfields.Ingress:      ing.GetName(),
	})

	// Used for logging the effective LB mode for this Ingress.
	loadbalancerMode := "shared"

	var translator translation.Translator
	m := &model.Model{}
	if !forceShared && r.isEffectiveLoadbalancerModeDedicated(ing) {
		loadbalancerMode = "dedicated"
		translator = r.dedicatedTranslator
		if annotations.GetAnnotationTLSPassthroughEnabled(ing) {
			m.TLS = append(m.TLS, ingestion.IngressPassthrough(*ing, r.defaultSecretNamespace, r.defaultSecretName)...)
		} else {
			m.HTTP = append(m.HTTP, ingestion.Ingress(*ing, r.defaultSecretNamespace, r.defaultSecretName)...)
		}

	} else {
		translator = r.sharedTranslator
		ingressList := networkingv1.IngressList{}
		if err := r.client.List(ctx, &ingressList); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to list Ingresses: %w", err)
		}

		for _, item := range ingressList.Items {
			if !isCiliumManagedIngress(ctx, r.client, item) || r.isEffectiveLoadbalancerModeDedicated(&item) || ing.GetDeletionTimestamp() != nil {
				continue
			}
			if annotations.GetAnnotationTLSPassthroughEnabled(&item) {
				m.TLS = append(m.TLS, ingestion.IngressPassthrough(item, r.defaultSecretNamespace, r.defaultSecretName)...)
			} else {
				m.HTTP = append(m.HTTP, ingestion.Ingress(item, r.defaultSecretNamespace, r.defaultSecretName)...)
			}
		}
	}

	scopedLog.WithFields(logrus.Fields{
		"forcedShared": forceShared,
		"model":        m,
		"loadbalancer": loadbalancerMode,
	}).Debug("Generated model for ingress")
	cec, svc, ep, err := translator.Translate(m)
	// Propagate Ingress annotation and label if required. This is applicable only for dedicated LB mode.
	// For shared LB mode, the service annotation and label are defined in other higher level (e.g. helm).
	if svc != nil {
		for key, value := range ing.GetAnnotations() {
			for _, prefix := range r.lbAnnotationPrefixes {
				if strings.HasPrefix(key, prefix) {
					if svc.Annotations == nil {
						svc.Annotations = make(map[string]string)
					}
					svc.Annotations[key] = value
				}
			}
		}
		// Same lbAnnotationPrefixes config option is used for label propagation
		for key, value := range ing.GetLabels() {
			for _, prefix := range r.lbAnnotationPrefixes {
				if strings.HasPrefix(key, prefix) {
					if svc.Labels == nil {
						svc.Labels = make(map[string]string)
					}
					svc.Labels[key] = value
				}
			}
		}
	}
	scopedLog.WithFields(logrus.Fields{
		"ciliumEnvoyConfig": cec,
		"service":           svc,
		logfields.Endpoint:  ep,
		"loadbalancer":      loadbalancerMode,
	}).Debugf("Translated resources for ingress")
	return cec, svc, ep, err
}

func (r *ingressReconciler) isEffectiveLoadbalancerModeDedicated(ing *networkingv1.Ingress) bool {
	value := annotations.GetAnnotationIngressLoadbalancerMode(ing)
	switch value {
	case dedicatedLoadbalancerMode:
		return true
	case sharedLoadbalancerMode:
		return false
	default:
		return r.defaultLoadbalancerMode == dedicatedLoadbalancerMode
	}
}
