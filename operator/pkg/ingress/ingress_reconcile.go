// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"cmp"
	"context"
	"fmt"
	"slices"
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
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	defaultPassthroughPort  = uint32(443)
	defaultInsecureHTTPPort = uint32(80)
	defaultSecureHTTPPort   = uint32(443)
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
		scopedLog.Debug("Trying to cleanup potentially existing resources of deleted Ingress")
		if err := r.tryCleanupSharedResources(ctx); err != nil {
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
		scopedLog.Debug("Trying to cleanup potentially existing resources of unmanaged Ingress")
		if err := r.tryCleanupSharedResources(ctx); err != nil {
			return controllerruntime.Fail(err)
		}

		if err := r.tryCleanupDedicatedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}

		scopedLog.Debug("Trying to cleanup Ingress status of unmanaged Ingress")
		if err := r.tryCleanupIngressStatus(ctx, ingress); err != nil {
			// One attempt to cleanup the status of the Ingress.
			// Don't fail (and retry) on an error, as this might result in
			// interferences with the new responsible Ingress controller.
			scopedLog.WithError(err).Warn("Failed to cleanup Ingress status")
		}

		scopedLog.Info("Successfully cleaned Ingress resources")
		return controllerruntime.Success()
	}

	// Creation / Update of Ingress resources depending on the loadbalancer mode
	// Trying to cleanup the resources of the "other" mode (potential change of mode)
	if r.isEffectiveLoadbalancerModeDedicated(ingress) {
		scopedLog.Debug("Updating dedicated resources")
		if err := r.createOrUpdateDedicatedResources(ctx, ingress); err != nil {
			if k8serrors.IsForbidden(err) && k8serrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
				// The creation of one of the resources failed because the
				// namespace is terminating. The ingress itself is also expected
				// to be marked for deletion, but we haven't yet received the
				// corresponding event, so let's not print an error message.
				scopedLog.Info("Aborting reconciliation because namespace is being terminated")
				return controllerruntime.Success()
			}

			return controllerruntime.Fail(err)
		}

		// Trying to cleanup shared resources (potential change of LB mode)
		scopedLog.Debug("Trying to cleanup potentially existing shared resources")
		if err := r.tryCleanupSharedResources(ctx); err != nil {
			return controllerruntime.Fail(err)
		}
	} else {
		scopedLog.Debug("Updating shared resources")
		if err := r.createOrUpdateSharedResources(ctx); err != nil {
			return controllerruntime.Fail(err)
		}

		// Trying to cleanup dedicated resources (potential change of LB mode)
		scopedLog.Debug("Trying to cleanup potentially existing dedicated resources")
		if err := r.tryCleanupDedicatedResources(ctx, req.NamespacedName); err != nil {
			return controllerruntime.Fail(err)
		}
	}

	// Update status
	scopedLog.Debug("Updating Ingress status")
	if err := r.updateIngressLoadbalancerStatus(ctx, ingress); err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to update Ingress loadbalancer status: %w", err))
	}

	scopedLog.Info("Successfully reconciled Ingress")
	return controllerruntime.Success()
}

func (r *ingressReconciler) createOrUpdateDedicatedResources(ctx context.Context, ingress *networkingv1.Ingress) error {
	desiredCiliumEnvoyConfig, desiredService, desiredEndpoints, err := r.buildDedicatedResources(ctx, ingress)
	if err != nil {
		return fmt.Errorf("failed to build dedicated resources: %w", err)
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

// propagateIngressAnnotationsAndLabels propagates Ingress annotation and label if required.
// This is applicable only for dedicated LB mode.
// For shared LB mode, the service annotation and label are defined in other higher level (e.g. helm).
func (r *ingressReconciler) propagateIngressAnnotationsAndLabels(ingress *networkingv1.Ingress, objectMeta *metav1.ObjectMeta) {
	// Same lbAnnotationPrefixes config option is used for annotation and label propagation
	if len(r.lbAnnotationPrefixes) > 0 {
		objectMeta.Annotations = mergeMap(objectMeta.Annotations, ingress.Annotations, r.lbAnnotationPrefixes...)
		objectMeta.Labels = mergeMap(objectMeta.Labels, ingress.Labels, r.lbAnnotationPrefixes...)
	}
}

func (r *ingressReconciler) createOrUpdateSharedResources(ctx context.Context) error {
	// In shared loadbalancing mode, only the CiliumEnvoyConfig is managed by the Operator.
	// Service and Endpoints are created by the Helm Chart.
	desiredCiliumEnvoyConfig, err := r.buildSharedResources(ctx)
	if err != nil {
		return fmt.Errorf("failed to build shared resources: %w", err)
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

func (r *ingressReconciler) tryCleanupSharedResources(ctx context.Context) error {
	// In shared loadbalancing mode, only the CiliumEnvoyConfig is managed by the Operator.
	// Service and Endpoints are created by the Helm Chart.
	desiredCiliumEnvoyConfig, err := r.buildSharedResources(ctx)
	if err != nil {
		return fmt.Errorf("failed to build shared resources: %w", err)
	}

	if err := r.createOrUpdateCiliumEnvoyConfig(ctx, desiredCiliumEnvoyConfig); err != nil {
		return err
	}

	return nil
}

func (r *ingressReconciler) buildSharedResources(ctx context.Context) (*ciliumv2.CiliumEnvoyConfig, error) {
	ingressList := networkingv1.IngressList{}
	if err := r.client.List(ctx, &ingressList); err != nil {
		return nil, fmt.Errorf("failed to list Ingresses: %w", err)
	}

	passthroughPort, insecureHTTPPort, secureHTTPPort := r.getSharedListenerPorts()

	m := &model.Model{}
	allSharedIngresses := ingressList.Items
	slices.SortStableFunc(allSharedIngresses, func(a, b networkingv1.Ingress) int {
		return cmp.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	for _, item := range allSharedIngresses {
		if !isCiliumManagedIngress(ctx, r.client, r.logger, item) || r.isEffectiveLoadbalancerModeDedicated(&item) || item.GetDeletionTimestamp() != nil {
			continue
		}
		if annotations.GetAnnotationTLSPassthroughEnabled(&item) {
			m.TLS = append(m.TLS, ingestion.IngressPassthrough(item, passthroughPort)...)
		} else {
			m.HTTP = append(m.HTTP, ingestion.Ingress(item, r.defaultSecretNamespace, r.defaultSecretName, r.enforcedHTTPS, insecureHTTPPort, secureHTTPPort)...)
		}
	}

	return r.cecTranslator.Translate(r.ciliumNamespace, r.sharedResourcesName, m)
}

func (r *ingressReconciler) getSharedListenerPorts() (uint32, uint32, uint32) {
	if !r.hostNetworkEnabled {
		return defaultPassthroughPort, defaultInsecureHTTPPort, defaultSecureHTTPPort
	}

	passthroughListenerPort := defaultPassthroughPort
	if r.hostNetworkSharedTLSPassthroughPort > 0 {
		passthroughListenerPort = r.hostNetworkSharedTLSPassthroughPort
	}

	insecureHTTPListenerPort := defaultInsecureHTTPPort
	secureHTTPListenerPort := defaultSecureHTTPPort
	if r.hostNetworkSharedHTTPPort > 0 {
		insecureHTTPListenerPort = r.hostNetworkSharedHTTPPort
		secureHTTPListenerPort = r.hostNetworkSharedHTTPPort
	}

	return passthroughListenerPort, insecureHTTPListenerPort, secureHTTPListenerPort
}

func (r *ingressReconciler) buildDedicatedResources(ctx context.Context, ingress *networkingv1.Ingress) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	passthroughPort, insecureHTTPPort, secureHTTPPort := r.getDedicatedListenerPorts(ingress)

	m := &model.Model{}

	if annotations.GetAnnotationTLSPassthroughEnabled(ingress) {
		m.TLS = append(m.TLS, ingestion.IngressPassthrough(*ingress, passthroughPort)...)
	} else {
		m.HTTP = append(m.HTTP, ingestion.Ingress(*ingress, r.defaultSecretNamespace, r.defaultSecretName, r.enforcedHTTPS, insecureHTTPPort, secureHTTPPort)...)
	}

	cec, svc, ep, err := r.dedicatedTranslator.Translate(m)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to translate model into resources: %w", err)
	}

	r.propagateIngressAnnotationsAndLabels(ingress, &svc.ObjectMeta)

	// Explicitly set the controlling OwnerReference on the CiliumEnvoyConfig
	if err := controllerutil.SetControllerReference(ingress, cec, r.client.Scheme()); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to set controller reference on CiliumEnvoyConfig: %w", err)
	}

	return cec, svc, ep, err
}

func (r *ingressReconciler) getDedicatedListenerPorts(ingress *networkingv1.Ingress) (uint32, uint32, uint32) {
	if !r.hostNetworkEnabled {
		return defaultPassthroughPort, defaultInsecureHTTPPort, defaultSecureHTTPPort
	}

	passthroughListenerPort := defaultPassthroughPort
	insecureHTTPListenerPort := defaultInsecureHTTPPort
	secureHTTPListenerPort := defaultSecureHTTPPort

	tlsPort, err := annotations.GetAnnotationTLSHostPort(ingress)
	if err != nil {
		r.logger.WithError(err).Warnf("Failed to parse TLS host port - using default listener port")
	} else if tlsPort == nil || *tlsPort == 0 {
		r.logger.Warnf("No TLS host port defined in annotation - using default listener port")
	} else {
		passthroughListenerPort = *tlsPort
	}

	httpPort, err := annotations.GetAnnotationHTTPHostPort(ingress)
	if err != nil {
		r.logger.WithError(err).Warnf("Failed to parse HTTP host port - using default listener port")
	} else if httpPort == nil || *httpPort == 0 {
		r.logger.Warnf("No HTTP host port defined in annotation - using default listener port")
	} else {
		insecureHTTPListenerPort = *httpPort
		secureHTTPListenerPort = *httpPort
	}

	return passthroughListenerPort, insecureHTTPListenerPort, secureHTTPListenerPort
}

func (r *ingressReconciler) createOrUpdateCiliumEnvoyConfig(ctx context.Context, desiredCEC *ciliumv2.CiliumEnvoyConfig) error {
	cec := desiredCEC.DeepCopy()

	result, err := controllerutil.CreateOrUpdate(ctx, r.client, cec, func() error {
		cec.Spec = desiredCEC.Spec
		cec.OwnerReferences = desiredCEC.OwnerReferences
		cec.Annotations = mergeMap(cec.Annotations, desiredCEC.Annotations)
		cec.Labels = mergeMap(cec.Labels, desiredCEC.Labels)

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
		svc.Labels = mergeMap(svc.Labels, desiredService.Labels)

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

// mergeMap merges the content from src into dst. Existing entries are overwritten.
// If keyPrefixes are provided, only keys matching one of the prefixes are merged.
func mergeMap(dst, src map[string]string, keyPrefixes ...string) map[string]string {
	if src == nil {
		return dst
	}

	if dst == nil {
		dst = map[string]string{}
	}

	for key, value := range src {
		if len(keyPrefixes) == 0 || atLeastOnePrefixMatches(key, keyPrefixes) {
			dst[key] = value
		}
	}

	return dst
}

func atLeastOnePrefixMatches(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}

	return false
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
		serviceNamespacedName.Name = r.sharedResourcesName
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

func (r *ingressReconciler) isEffectiveLoadbalancerModeDedicated(ingress *networkingv1.Ingress) bool {
	value := annotations.GetAnnotationIngressLoadbalancerMode(ingress)
	switch value {
	case annotations.LoadbalancerModeDedicated:
		return true
	case annotations.LoadbalancerModeShared:
		return false
	default:
		return r.defaultLoadbalancerMode == annotations.LoadbalancerModeDedicated
	}
}
