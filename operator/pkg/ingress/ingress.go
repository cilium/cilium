// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	ciliumIngressPrefix    = "cilium-ingress"
	ciliumIngressClassName = "cilium"
)

// ingressReconciler reconciles a Ingress object
type ingressReconciler struct {
	logger logrus.FieldLogger
	client client.Client

	maxRetries              int
	enforcedHTTPS           bool
	useProxyProtocol        bool
	secretsNamespace        string
	lbAnnotationPrefixes    []string
	sharedLBServiceName     string
	ciliumNamespace         string
	defaultLoadbalancerMode string
	defaultSecretNamespace  string
	defaultSecretName       string
	idleTimeoutSeconds      int

	sharedTranslator    translation.Translator
	dedicatedTranslator translation.Translator
}

func newIngressReconciler(
	logger logrus.FieldLogger,
	c client.Client,
	ciliumNamespace string,
	enforceHTTPS bool,
	useProxyProtocol bool,
	secretsNamespace string,
	lbAnnotationPrefixes []string,
	sharedLBServiceName string,
	defaultLoadbalancerMode string,
	defaultSecretNamespace string,
	defaultSecretName string,
	proxyIdleTimeoutSeconds int,
) *ingressReconciler {
	return &ingressReconciler{
		logger: logger,
		client: c,

		sharedTranslator:    ingressTranslation.NewSharedIngressTranslator(sharedLBServiceName, ciliumNamespace, secretsNamespace, enforceHTTPS, useProxyProtocol, proxyIdleTimeoutSeconds),
		dedicatedTranslator: ingressTranslation.NewDedicatedIngressTranslator(secretsNamespace, enforceHTTPS, useProxyProtocol, proxyIdleTimeoutSeconds),

		maxRetries:              10,
		enforcedHTTPS:           enforceHTTPS,
		useProxyProtocol:        useProxyProtocol,
		secretsNamespace:        secretsNamespace,
		lbAnnotationPrefixes:    lbAnnotationPrefixes,
		sharedLBServiceName:     sharedLBServiceName,
		ciliumNamespace:         ciliumNamespace,
		defaultLoadbalancerMode: defaultLoadbalancerMode,
		defaultSecretNamespace:  defaultSecretNamespace,
		defaultSecretName:       defaultSecretName,
		idleTimeoutSeconds:      proxyIdleTimeoutSeconds,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ingressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changed Ingresses that are managed by the Cilium Ingress controller
		// It's important that this includes cases where the IngressClassName gets changed from `cilium`
		// to something else. In these cases the controller has to cleanup the resources.
		For(&networkingv1.Ingress{}, r.forCiliumManagedIngress()).
		// (LoadBalancer) Service resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&corev1.Service{}).
		// Endpoints resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&corev1.Endpoints{}).
		// CiliumEnvoyConfig resource with OwnerReference to the Ingress with dedicated loadbalancing mode
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// Watching shared loadbalancer Service and reconcile all shared Cilium Ingresses.
		// It's necessary to reconcile all shared Cilium Ingresses as they all have to potentially update their LoadBalancer status.
		Watches(&corev1.Service{}, r.enqueueSharedCiliumIngresses(), r.forSharedLoadbalancerService()).
		// Watching shared CiliumEnvoyConfig and reconcile a non-existing pseudo Cilium Ingress.
		// Its not necessary to reconcile all shared Cilium Ingresses as they all will update the
		// shared CEC with the complete model that includes all shared Cilium Ingresses.
		// This will cover the following cases
		// - Manual deletion of shared CEC
		//   -> Pseudo Cilium Ingress reconciliation will re-create it
		// - Manual update of shared CEC
		//   -> Pseudo Cilium Ingress reconciliation will enforce an update of the shared CEC
		// - Deletion of shared Cilium Ingresses during downtime of the Cilium Operator
		//   -> pseudo Cilium Ingress reconciliation will enforce an update of the shared CEC after the restart
		Watches(&ciliumv2.CiliumEnvoyConfig{}, r.enqueuePseudoIngress(), r.forSharedCiliumEnvoyConfig()).
		// Watching Cilium IngressClass for changes being the default Ingress controller
		// (changed annotation `ingressclass.kubernetes.io/is-default-class`)
		Watches(&networkingv1.IngressClass{}, r.enqueueIngressesWithoutExplicitClass(), r.forCiliumIngressClass(), withDefaultIngressClassAnnotation()).
		Complete(r)
}

func (r *ingressReconciler) enqueueSharedCiliumIngresses() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		ingressList := networkingv1.IngressList{}
		if err := r.client.List(ctx, &ingressList); err != nil {
			r.logger.WithError(err).Warn("Failed to list Ingresses")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range ingressList.Items {
			// Skip Ingresses that aren't managed by Cilium
			if !isCiliumManagedIngress(ctx, r.client, r.logger, i) {
				continue
			}

			// Skip Ingresses with dedicated loadbalancer mode
			if r.isEffectiveLoadbalancerModeDedicated(&i) {
				continue
			}

			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (r *ingressReconciler) enqueueIngressesWithoutExplicitClass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		ingressList := networkingv1.IngressList{}
		if err := r.client.List(ctx, &ingressList); err != nil {
			r.logger.WithError(err).Warn("Failed to list Ingresses")
			return nil
		}

		result := []reconcile.Request{}

		for _, i := range ingressList.Items {
			if i.Spec.IngressClassName != nil {
				continue
			}
			result = append(result, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: i.Namespace,
					Name:      i.Name,
				},
			})
		}

		return result
	})
}

func (r *ingressReconciler) enqueuePseudoIngress() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: r.ciliumNamespace,
					Name:      "pseudo-ingress",
				},
			},
		}
	})
}

func (r *ingressReconciler) forSharedLoadbalancerService() builder.WatchesOption {
	return builder.WithPredicates(&matchesInstancePredicate{namespace: r.ciliumNamespace, name: r.sharedLBServiceName})
}

func (r *ingressReconciler) forSharedCiliumEnvoyConfig() builder.WatchesOption {
	return builder.WithPredicates(&matchesInstancePredicate{namespace: r.ciliumNamespace, name: r.sharedLBServiceName})
}

func (r *ingressReconciler) forCiliumIngressClass() builder.WatchesOption {
	return builder.WithPredicates(&matchesInstancePredicate{namespace: "", name: ciliumIngressClassName})
}

func withDefaultIngressClassAnnotation() builder.WatchesOption {
	return builder.WithPredicates(&defaultIngressClassPredicate{})
}

func (r *ingressReconciler) forCiliumManagedIngress() builder.ForOption {
	return builder.WithPredicates(&matchesCiliumRelevantIngressPredicate{client: r.client, logger: r.logger})
}

var _ predicate.Predicate = &matchesInstancePredicate{}

type matchesInstancePredicate struct {
	namespace string
	name      string
}

func (r *matchesInstancePredicate) Create(event event.CreateEvent) bool {
	return event.Object.GetNamespace() == r.namespace && event.Object.GetName() == r.name
}

func (r *matchesInstancePredicate) Update(event event.UpdateEvent) bool {
	return event.ObjectNew.GetNamespace() == r.namespace && event.ObjectNew.GetName() == r.name
}

func (r *matchesInstancePredicate) Delete(event event.DeleteEvent) bool {
	return event.Object.GetNamespace() == r.namespace && event.Object.GetName() == r.name
}

func (r *matchesInstancePredicate) Generic(event event.GenericEvent) bool {
	return event.Object.GetNamespace() == r.namespace && event.Object.GetName() == r.name
}

var _ predicate.Predicate = &defaultIngressClassPredicate{}

type defaultIngressClassPredicate struct{}

func (r *defaultIngressClassPredicate) Create(event event.CreateEvent) bool {
	return r.isIngressClassMarkedAsDefault(event.Object)
}

func (r *defaultIngressClassPredicate) Update(event event.UpdateEvent) bool {
	oldIngressClassDefault := r.isIngressClassMarkedAsDefault(event.ObjectOld)
	newIngressClassDefault := r.isIngressClassMarkedAsDefault(event.ObjectNew)

	return (oldIngressClassDefault || newIngressClassDefault) &&
		// Only in case of a change
		oldIngressClassDefault != newIngressClassDefault
}

func (r *defaultIngressClassPredicate) Delete(event event.DeleteEvent) bool {
	return r.isIngressClassMarkedAsDefault(event.Object)
}

func (r *defaultIngressClassPredicate) Generic(event event.GenericEvent) bool {
	return r.isIngressClassMarkedAsDefault(event.Object)
}

func (r *defaultIngressClassPredicate) isIngressClassMarkedAsDefault(o client.Object) bool {
	ingressClass, ok := o.(*networkingv1.IngressClass)
	if !ok {
		return false
	}

	isDefault, err := isIngressClassMarkedAsDefault(*ingressClass)
	if err != nil {
		return false
	}

	return isDefault
}

var _ predicate.Predicate = &matchesCiliumRelevantIngressPredicate{}

type matchesCiliumRelevantIngressPredicate struct {
	client client.Client
	logger logrus.FieldLogger
}

func (r *matchesCiliumRelevantIngressPredicate) Create(event event.CreateEvent) bool {
	return r.isCiliumManagedIngress(event.Object)
}

func (r *matchesCiliumRelevantIngressPredicate) Update(event event.UpdateEvent) bool {
	return r.isCiliumManagedIngress(event.ObjectOld) || r.isCiliumManagedIngress(event.ObjectNew)
}

func (r *matchesCiliumRelevantIngressPredicate) Delete(event event.DeleteEvent) bool {
	return r.isCiliumManagedIngress(event.Object)
}

func (r *matchesCiliumRelevantIngressPredicate) Generic(event event.GenericEvent) bool {
	return r.isCiliumManagedIngress(event.Object)
}

func (r *matchesCiliumRelevantIngressPredicate) isCiliumManagedIngress(o client.Object) bool {
	ingress, ok := o.(*networkingv1.Ingress)
	if !ok {
		return false
	}

	return isCiliumManagedIngress(context.Background(), r.client, r.logger, *ingress)
}
