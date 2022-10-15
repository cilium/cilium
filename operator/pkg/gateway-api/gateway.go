// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	translation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"

	lastTransitionTime = "LastTransitionTime"
	retryAfter         = time.Second * 30
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	controllerName string

	Model *internalModel
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *gatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: gateway,
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling Gateway")

	// Step 1: Retrieve the Gateway
	original := &gatewayv1beta1.Gateway{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		scopedLog.WithError(err).Error("Unable to get Gateway")
		return fail(err)
	}

	// Ignore deleting Gateway, this can happen when foregroundDeletion is enabled
	// The reconciliation loop will automatically kick off for related Gateway resources.
	if original.GetDeletionTimestamp() != nil {
		scopedLog.Info("Gateway is being deleted, doing nothing")
		return success()
	}

	gw := original.DeepCopy()
	defer func() {
		if err := r.updateStatus(ctx, original, gw); err != nil {
			scopedLog.WithError(err).Error("Unable to update Gateway status")
			return
		}
	}()
	setGatewayScheduled(gw, true, "Gateway successfully scheduled")

	// Step 2: Gather all required information for the ingestion model
	gwc := &gatewayv1beta1.GatewayClass{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: string(gw.Spec.GatewayClassName)}, gwc); err != nil {
		scopedLog.WithField(gatewayClass, gw.Spec.GatewayClassName).
			WithError(err).
			Error("Unable to get GatewayClass")
		if k8serrors.IsNotFound(err) {
			setGatewayScheduled(gw, false, "GatewayClass does not exist")
			return fail(err)
		}
		setGatewayScheduled(gw, false, "Unable to get GatewayClass")
		return fail(err)
	}

	routeList := &gatewayv1beta1.HTTPRouteList{}
	if err := r.Client.List(ctx, routeList); err != nil {
		scopedLog.WithError(err).Error("Unable to list HTTPRoutes")
		return fail(err)
	}

	listeners := ingestion.GatewayAPI(ingestion.Input{
		GatewayClass: *gwc,
		Gateway:      *gw,
		HTTPRoutes:   r.filterRoutesByGateway(ctx, gw, routeList.Items),
	})

	// Step 3: Translate the listeners into Cilium model
	cec, svc, ep, err := translation.NewTranslator("cilium-secrets").Translate(&model.Model{HTTP: listeners})
	if err != nil {
		scopedLog.WithError(err).Error("Unable to translate resources")
		setGatewayScheduled(gw, false, "Unable to translate resources")
		return fail(err)
	}

	if err = r.ensureService(ctx, svc); err != nil {
		scopedLog.WithError(err).Error("Unable to create Service")
		setGatewayScheduled(gw, false, "Unable to create Service resource")
		return fail(err)
	}

	if err = r.ensureEndpoints(ctx, ep); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure Endpoints")
		setGatewayScheduled(gw, false, "Unable to ensure Endpoints resource")
		return fail(err)
	}

	if err = r.ensureEnvoyConfig(ctx, cec); err != nil {
		scopedLog.WithError(err).Error("Unable to ensure CiliumEnvoyConfig")
		setGatewayScheduled(gw, false, "Unable to ensure CEC resource")
		return fail(err)
	}

	// Step 4: Update the status of the Gateway
	if err = r.setAddressStatus(ctx, gw); err != nil {
		scopedLog.WithError(err).Errorf("Address is not ready, retrying after %s", retryAfter)
		setGatewayReady(gw, false, "Address is not ready")
		return requeue(retryAfter)
	}

	if err = r.setListenerStatus(ctx, gw); err != nil {
		scopedLog.WithError(err).Error("Unable to set listener status")
		setGatewayReady(gw, false, "Unable to set listener status")
		return fail(err)
	}

	setGatewayReady(gw, true, "Gateway successfully reconciled")
	scopedLog.Info("Successfully reconciled Gateway")
	return success()
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1beta1.Gateway{}, builder.WithPredicates(predicate.NewPredicateFuncs(r.hasMatchingController))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&source.Kind{Type: &gatewayv1beta1.GatewayClass{}},
			r.enqueueRequestForOwningGatewayClass(),
			builder.WithPredicates(predicate.NewPredicateFuncs(r.hasMatchingController))).
		// Watch related LB service for status
		Watches(&source.Kind{Type: &corev1.Service{}},
			r.enqueueRequestForOwningResource(),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(object client.Object) bool {
				_, found := object.GetLabels()[owningGatewayLabel]
				return found
			}))).
		// Watch HTTP Route status changes, there is one assumption that any change in spec will
		// always update status always at least for observedGeneration value.
		Watches(&source.Kind{Type: &gatewayv1beta1.HTTPRoute{}},
			r.enqueueRequestForOwningHTTRoute(),
			builder.WithPredicates(onlyStatusChanged())).
		Complete(r)
}

func (r *gatewayReconciler) hasMatchingController(obj client.Object) bool {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Controller: "gateway",
		logfields.Resource:   obj.GetName(),
	})
	gw, ok := obj.(*gatewayv1beta1.Gateway)
	if !ok {
		return false
	}

	gwc := &gatewayv1beta1.GatewayClass{}
	key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
	if err := r.Client.Get(context.Background(), key, gwc); err != nil {
		scopedLog.WithError(err).Error("Unable to get GatewayClass")
		return false
	}

	return string(gwc.Spec.ControllerName) == r.controllerName
}

// enqueueRequestForOwningGatewayClass returns an event handler for all Gateway objects
// belonging to the given GatewayClass.
func (r *gatewayReconciler) enqueueRequestForOwningGatewayClass() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: gateway,
			logfields.Resource:   a.GetName(),
		})
		var reqs []reconcile.Request
		gwList := &gatewayv1beta1.GatewayList{}
		if err := r.Client.List(context.Background(), gwList); err != nil {
			scopedLog.Error("Unable to list Gateways")
			return nil
		}

		for _, gw := range gwList.Items {
			if gw.Spec.GatewayClassName == gatewayv1beta1.ObjectName(a.GetName()) {
				req := reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: gw.Namespace,
						Name:      gw.Name,
					},
				}
				reqs = append(reqs, req)
				scopedLog.WithFields(logrus.Fields{
					logfields.K8sNamespace: gw.GetNamespace(),
					logfields.Resource:     gw.GetName(),
				}).Info("Queueing gateway")
			}
		}
		return reqs
	})
}

// enqueueRequestForOwningResource returns an event handler for all Gateway objects having
// owningGatewayLabel
func (r *gatewayReconciler) enqueueRequestForOwningResource() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "gateway",
			logfields.Resource:   a.GetName(),
		})

		key, found := a.GetLabels()[owningGatewayLabel]
		if !found {
			return nil
		}

		scopedLog.WithFields(logrus.Fields{
			logfields.K8sNamespace: a.GetNamespace(),
			logfields.Resource:     a.GetName(),
			"gateway":              key,
		}).Info("Queueing gateway for backend service")

		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: a.GetNamespace(),
					Name:      key,
				},
			},
		}
	})
}

// enqueueRequestForOwningHTTRoute returns an event handler for any changes with HTTP Routes
// belonging to the given Gateway
func (r *gatewayReconciler) enqueueRequestForOwningHTTRoute() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: gateway,
			logfields.Resource:   a.GetName(),
		})

		var reqs []reconcile.Request

		hr, ok := a.(*gatewayv1beta1.HTTPRoute)
		if !ok {
			return nil
		}

		for _, parent := range hr.Spec.ParentRefs {
			if parent.Kind == nil || string(*parent.Kind) != kindGateway {
				continue
			}

			if parent.Group == nil || string(*parent.Group) != gatewayv1beta1.GroupName {
				continue
			}

			ns := namespaceDerefOr(parent.Namespace, hr.GetNamespace())
			scopedLog.WithFields(logrus.Fields{
				logfields.K8sNamespace: ns,
				logfields.Resource:     parent.Name,
				httpRoute:              hr.GetName(),
			}).Info("Queueing gateway for http route")

			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ns,
					Name:      string(parent.Name),
				},
			})
		}
		return reqs
	})
}

func onlyStatusChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			o, ok := e.ObjectOld.(*gatewayv1beta1.HTTPRoute)
			if !ok {
				return false
			}
			n, ok := e.ObjectNew.(*gatewayv1beta1.HTTPRoute)
			if !ok {
				return false
			}
			return !cmp.Equal(o.Status, n.Status)
		},
	}
}

func (r *gatewayReconciler) ensureService(ctx context.Context, desired *corev1.Service) error {
	existing := &corev1.Service{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	temp := existing.DeepCopy()
	temp.Spec = desired.Spec
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) ensureEndpoints(ctx context.Context, desired *corev1.Endpoints) error {
	existing := &corev1.Endpoints{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}

	temp := existing.DeepCopy()
	temp.Subsets = desired.Subsets
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) ensureEnvoyConfig(ctx context.Context, desired *ciliumv2.CiliumEnvoyConfig) error {
	existing := &ciliumv2.CiliumEnvoyConfig{}
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return r.Client.Create(ctx, desired)
		}
		return err
	}
	temp := existing.DeepCopy()
	temp.Spec = desired.Spec
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())

	return r.Client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *gatewayReconciler) updateStatus(ctx context.Context, original *gatewayv1beta1.Gateway, new *gatewayv1beta1.Gateway) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

func (r *gatewayReconciler) filterRoutesByGateway(ctx context.Context, gw *gatewayv1beta1.Gateway, routes []gatewayv1beta1.HTTPRoute) []gatewayv1beta1.HTTPRoute {
	var filtered []gatewayv1beta1.HTTPRoute

	for _, route := range routes {
		accepted := false
		for _, rps := range route.Status.RouteStatus.Parents {
			if namespaceDerefOr(rps.ParentRef.Namespace, route.GetNamespace()) == gw.GetNamespace() &&
				string(rps.ParentRef.Name) == gw.GetName() {
				for _, cond := range rps.Conditions {
					if cond.Type == conditionStatusAccepted && cond.Status == metav1.ConditionTrue {
						accepted = true
						break
					}
				}
			}
			if accepted {
				break
			}
		}

		if accepted && isAttachable(ctx, r.Client, gw, &route) {
			filtered = append(filtered, route)
		}
	}

	return filtered
}

func (r *gatewayReconciler) setAddressStatus(ctx context.Context, gw *gatewayv1beta1.Gateway) error {
	svcList := &corev1.ServiceList{}
	if err := r.Client.List(ctx, svcList, client.MatchingLabels{
		owningGatewayLabel: gw.GetName(),
	}); err != nil {
		return err
	}

	if len(svcList.Items) == 0 {
		return fmt.Errorf("no service found")
	}

	svc := svcList.Items[0]
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return fmt.Errorf("load balancer status is not ready")
	}

	var addresses []gatewayv1beta1.GatewayAddress
	for _, s := range svc.Status.LoadBalancer.Ingress {
		if len(s.IP) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.IPAddressType),
				Value: s.IP,
			})
		}
		if len(s.Hostname) != 0 {
			addresses = append(addresses, gatewayv1beta1.GatewayAddress{
				Type:  GatewayAddressTypePtr(gatewayv1beta1.HostnameAddressType),
				Value: s.Hostname,
			})
		}
	}

	gw.Status.Addresses = addresses
	return nil
}

func (r *gatewayReconciler) setListenerStatus(_ context.Context, gw *gatewayv1beta1.Gateway) error {
	for _, l := range gw.Spec.Listeners {
		found := false
		for _, status := range gw.Status.Listeners {
			if l.Name == status.Name {
				found = true
			}
			status.Conditions = merge(status.Conditions, gatewayListenerReadyCondition(gw, true, "Listener Ready"))
		}
		if !found {
			gw.Status.Listeners = append(gw.Status.Listeners, gatewayv1beta1.ListenerStatus{
				Name: l.Name,
				SupportedKinds: []gatewayv1beta1.RouteGroupKind{
					{
						Group: GroupPtr(gatewayv1beta1.GroupName),
						Kind:  getSupportedKind(l.Protocol),
					},
				},
				Conditions: []metav1.Condition{
					gatewayListenerReadyCondition(gw, true, "Listener Ready"),
				},
			})
		}
	}
	return nil
}
