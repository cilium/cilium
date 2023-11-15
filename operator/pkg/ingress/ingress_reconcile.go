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
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}

	if err := r.client.Status().Update(ctx, ingress); err != nil {
		scopedLog.WithError(err).Error("Failed to update Ingress status")
		return controllerruntime.Fail(err)
	}

	scopedLog.Info("Successfully reconciled Ingress")
	return controllerruntime.Success()
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
