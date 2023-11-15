// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (r *ingressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
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
	if !isCiliumManagedIngress(ctx, r.client, r.logger, *ingress) {
		if err := r.tryCleanupSharedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		if err := r.tryCleanupDedicatedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		if err := r.tryCleanupIngressStatus(ctx, ingress); err != nil {
			// One attempt to cleanup the status of the Ingress.
			// Don't fail (and retry) on an error, as this might result in
			// interferences with the new responsible Ingress controller.
			scopedLog.WithError(err).Warn("Failed to cleanup Ingress status")
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
	if err := r.updateIngressLoadbalancerStatus(ctx, ingress); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Ingress loadbalancer status: %w", err))
	}

	scopedLog.Info("Successfully reconciled Ingress")
	return controllerruntime.Success()
}

func (r *ingressReconciler) createOrUpdateDedicatedResources(ctx context.Context, ingress *networkingv1.Ingress) error {
	desiredCiliumEnvoyConfig, desiredService, desiredEndpoints, err := r.regenerate(ctx, ingress, false)
	if err != nil {
		return fmt.Errorf("failed to generate Ingress model: %w", err)
	}

	// Explicitly set the controlling OwnerReference on the CiliumEnvoyConfig
	if err := controllerutil.SetControllerReference(ingress, desiredCiliumEnvoyConfig, r.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference on CiliumEnvoyConfig: %w", err)
	}

	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredCiliumEnvoyConfig); err != nil {
		return err
	}

	if err := r.createOrUpdateService(ctx, desiredService); err != nil {
		return err
	}

	if err := r.createOrUpdateEndpoints(ctx, desiredEndpoints); err != nil {
		return err
	}

	return nil
}

func (r *ingressReconciler) createOrUpdateSharedResources(ctx context.Context, ingress *networkingv1.Ingress) error {
	// In shared loadbalancing mode, only the CiliumEnvoyConfig is managed by the Operator.
	// Service and Endpoints are created by the Helm Chart.
	desiredCiliumEnvoyConfig, _, _, err := r.regenerate(ctx, ingress, false)
	if err != nil {
		return fmt.Errorf("failed to generate Ingress model: %w", err)
	}

	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredCiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

func (r *ingressReconciler) tryCleanupDedicatedResources(ctx context.Context, ingressNamespacedName types.NamespacedName) error {
	resources := map[client.Object]types.NamespacedName{
		&corev1.Service{}:             {Namespace: ingressNamespacedName.Namespace, Name: fmt.Sprintf("%s-%s", ciliumIngressPrefix, ingressNamespacedName.Name)},
		&corev1.Endpoints{}:           {Namespace: ingressNamespacedName.Namespace, Name: fmt.Sprintf("%s-%s", ciliumIngressPrefix, ingressNamespacedName.Name)},
		&ciliumv2.CiliumEnvoyConfig{}: {Namespace: ingressNamespacedName.Namespace, Name: fmt.Sprintf("%s-%s-%s", ciliumIngressPrefix, ingressNamespacedName.Namespace, ingressNamespacedName.Name)},
	}

	for k, v := range resources {
		if err := r.tryDeletingResource(ctx, k, v); err != nil {
			return err
		}
	}

	return nil
}

func (r *ingressReconciler) tryCleanupSharedResources(ctx context.Context, ingressNamespacedName types.NamespacedName) error {
	// Ingress isn't used when using enforced shared mode.
	// Its only purpose is to get the namespace and name.
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ingressNamespacedName.Namespace,
			Name:      ingressNamespacedName.Name,
		},
	}

	// In shared loadbalancing mode, only the CiliumEnvoyConfig is managed by the Operator.
	// Service and Endpoints are created by the Helm Chart.
	desiredCiliumEnvoyConfig, _, _, err := r.regenerate(ctx, &ingress, true)
	if err != nil {
		return fmt.Errorf("failed to generate Ingress model: %w", err)
	}

	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredCiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

// regenerate regenerates the desired stage for all related resources.
// This internally leverage different Ingress translators (e.g. shared vs dedicated).
// If forceShared is true, only the shared translator will be used.
func (r *ingressReconciler) regenerate(ctx context.Context, ing *networkingv1.Ingress, forceShared bool) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	scopedLog := r.logger.WithFields(logrus.Fields{
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
			if !isCiliumManagedIngress(ctx, r.client, r.logger, item) || r.isEffectiveLoadbalancerModeDedicated(&item) || item.GetDeletionTimestamp() != nil {
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

func (r *ingressReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, cec, func() error {
		cec.Spec = desiredCEC.Spec
		cec.OwnerReferences = desiredCEC.OwnerReferences
		cec.Annotations = mergeMap(cec.Annotations, desiredCEC.Annotations)
		cec.Labels = mergeMap(cec.Annotations, desiredCEC.Annotations)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update CiliumEnvoyConfig: %w", err)
	}

	r.logger.Debugf("CiliumEnvoyConfig %s has been %s", client.ObjectKeyFromObject(cec), result)

	return nil
}

func (r *ingressReconciler) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	svc := desiredService.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, svc, func() error {
		// Save and restore loadBalancerClass
		// e.g. if a mutating webhook writes this field
		lbClass := svc.Spec.LoadBalancerClass
		svc.Spec = desiredService.Spec
		svc.Spec.LoadBalancerClass = lbClass

		svc.OwnerReferences = desiredService.OwnerReferences
		svc.Annotations = mergeMap(svc.Annotations, desiredService.Annotations)
		svc.Labels = mergeMap(svc.Annotations, desiredService.Annotations)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update Service: %w", err)
	}

	r.logger.Debugf("Service %s has been %s", client.ObjectKeyFromObject(svc), result)

	return nil
}

func (r *ingressReconciler) createOrUpdateEndpoints(ctx context.Context, desiredEndpoints *corev1.Endpoints) error {
	ep := desiredEndpoints.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, ep, func() error {
		ep.Subsets = desiredEndpoints.Subsets
		ep.OwnerReferences = desiredEndpoints.OwnerReferences
		ep.Annotations = mergeMap(ep.Annotations, desiredEndpoints.Annotations)
		ep.Labels = mergeMap(ep.Labels, desiredEndpoints.Labels)

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update Endpoints: %w", err)
	}

	r.logger.Debugf("Endpoints %s has been %s", client.ObjectKeyFromObject(ep), result)

	return nil
}

func mergeMap(dst, src map[string]string) map[string]string {
	if dst == nil {
		return src
	}

	maps.Copy(dst, src)
	return dst
}

func (r *ingressReconciler) tryDeletingResource(ctx context.Context, object client.Object, namespacedName types.NamespacedName) error {
	if err := r.client.Get(ctx, namespacedName, object); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get existing %T: %w", object, err)
		}
		return nil
	}

	if err := r.client.Delete(ctx, object); err != nil {
		return fmt.Errorf("failed to delete existing %T: %w", object, err)
	}

	return nil
}

func (r *ingressReconciler) updateIngressLoadbalancerStatus(ctx context.Context, ingress *networkingv1.Ingress) error {
	serviceNamespacedName := types.NamespacedName{}
	if r.isEffectiveLoadbalancerModeDedicated(ingress) {
		serviceNamespacedName.Namespace = ingress.Namespace
		serviceNamespacedName.Name = fmt.Sprintf("%s-%s", ciliumIngressPrefix, ingress.Name)
	} else {
		serviceNamespacedName.Namespace = r.ciliumNamespace
		serviceNamespacedName.Name = r.sharedLBServiceName
	}

	loadbalancerService := corev1.Service{}
	if err := r.client.Get(ctx, serviceNamespacedName, &loadbalancerService); err != nil {
		if !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to get loadbalancer Service: %w", err)
		}

		// Reconcile will be triggered if the loadbalancer Service is updated
		return nil
	}

	ingress.Status.LoadBalancer.Ingress = convertToNetworkV1IngressLoadBalancerIngress(loadbalancerService.Status.LoadBalancer.Ingress)

	if err := r.client.Status().Update(ctx, ingress); err != nil {
		return fmt.Errorf("failed to write Ingress status: %w", err)
	}

	return nil
}

func (r *ingressReconciler) tryCleanupIngressStatus(ctx context.Context, ingress *networkingv1.Ingress) error {
	ingress.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{}

	if err := r.client.Status().Update(ctx, ingress); err != nil {
		return fmt.Errorf("failed to update Ingress status: %w", err)
	}

	return nil
}

func convertToNetworkV1IngressLoadBalancerIngress(lbIngresses []corev1.LoadBalancerIngress) []networkingv1.IngressLoadBalancerIngress {
	if lbIngresses == nil {
		return nil
	}

	ingLBIngs := make([]networkingv1.IngressLoadBalancerIngress, 0, len(lbIngresses))
	for _, lbIng := range lbIngresses {
		ports := make([]networkingv1.IngressPortStatus, 0, len(lbIng.Ports))
		for _, port := range lbIng.Ports {
			ports = append(ports, networkingv1.IngressPortStatus{
				Port:     port.Port,
				Protocol: corev1.Protocol(port.Protocol),
				Error:    port.Error,
			})
		}
		ingLBIngs = append(ingLBIngs,
			networkingv1.IngressLoadBalancerIngress{
				IP:       lbIng.IP,
				Hostname: lbIng.Hostname,
				Ports:    ports,
			})
	}

	return ingLBIngs
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
