// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// endpointSliceLocalMCSAPIControllerName is a unique value used with LabelManagedBy to indicate
	// the component managing an EndpointSlice.
	endpointSliceLocalMCSAPIControllerName = "endpointslice-local-mcsapi-controller.cilium.io"
	localEndpointSliceLabel                = annotation.ServicePrefix + "/local-endpointslice"
)

// mcsAPIEndpointSliceMirrorReconciler is a controller that mirrors local
// EndpointSlice from a local Service with a ServiceExport to its derived Service.
// It works by mirroring the EndpointSlice by its suffix name (the name without
// the generatedName prefix).
type mcsAPIEndpointSliceMirrorReconciler struct {
	client.Client
	Logger *slog.Logger

	clusterName string
}

func newMCSAPIEndpointSliceMirrorReconciler(mgr ctrl.Manager, logger *slog.Logger, clusterName string) *mcsAPIEndpointSliceMirrorReconciler {
	return &mcsAPIEndpointSliceMirrorReconciler{
		Client:      mgr.GetClient(),
		Logger:      logger,
		clusterName: clusterName,
	}
}

func getLocalEndpointSliceKey(derivedEpSlice *discoveryv1.EndpointSlice) *types.NamespacedName {
	if derivedEpSlice.Labels[localEndpointSliceLabel] == "" {
		return nil
	}
	return &types.NamespacedName{
		Name:      derivedEpSlice.Labels[localEndpointSliceLabel],
		Namespace: derivedEpSlice.Namespace,
	}
}

func getLocalDerivedEndpointSliceKey(localEpSlice *discoveryv1.EndpointSlice) *types.NamespacedName {
	suffix := getSuffix(localEpSlice)
	derivedServiceName := getDerivedServiceName(localEpSlice)
	if derivedServiceName == "" {
		return nil
	}
	name := derivedServiceName + "-" + suffix
	if suffix == "" {
		name = derivedServiceName
	}
	return &types.NamespacedName{Name: name, Namespace: localEpSlice.Namespace}
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalEndpointSlice(
	ctx context.Context, derivedEpSlice *discoveryv1.EndpointSlice,
) (*discoveryv1.EndpointSlice, error) {
	localEpSliceKey := getLocalEndpointSliceKey(derivedEpSlice)
	if localEpSliceKey == nil {
		return nil, nil
	}
	var localEpSlice discoveryv1.EndpointSlice
	if err := r.Client.Get(ctx, *localEpSliceKey, &localEpSlice); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &localEpSlice, nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) shouldMirrorLocalEndpointSlice(
	ctx context.Context, localEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) (bool, error) {
	if localEpSlice == nil {
		return false, nil
	}
	serviceName := localEpSlice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return false, nil
	}
	var svcExport mcsapiv1alpha1.ServiceExport
	if err := r.Client.Get(
		ctx,
		types.NamespacedName{Name: serviceName, Namespace: localEpSlice.Namespace},
		&svcExport,
	); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	// Only mirrors EndpointSlice compatible with the derived Service IP family
	if !slices.Contains(derivedService.Spec.IPFamilies, corev1.IPFamily(localEpSlice.AddressType)) {
		return false, nil
	}
	return true, nil
}

func getDerivedServiceName(localEpSlice *discoveryv1.EndpointSlice) string {
	serviceName := localEpSlice.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return ""
	}
	return derivedName(types.NamespacedName{
		Name: serviceName, Namespace: localEpSlice.Namespace,
	})
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalDerivedEndpointSlice(
	ctx context.Context, localEpSlice *discoveryv1.EndpointSlice,
) (*discoveryv1.EndpointSlice, error) {
	derivedEpSliceKey := getLocalDerivedEndpointSliceKey(localEpSlice)
	if derivedEpSliceKey == nil {
		return nil, nil
	}
	var derivedEpSlice discoveryv1.EndpointSlice
	if err := r.Client.Get(ctx, *derivedEpSliceKey, &derivedEpSlice); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &derivedEpSlice, nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) updateDerivedEndpointSlice(
	derivedEpSlice, localEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) {
	controllerutil.SetControllerReference(derivedService, derivedEpSlice, r.Scheme())

	derivedEpSlice.Labels = maps.Clone(derivedService.Labels)
	if derivedEpSlice.Labels == nil {
		derivedEpSlice.Labels = map[string]string{}
	}
	derivedEpSlice.Labels[mcsapiv1alpha1.LabelServiceName] = localEpSlice.Labels[discoveryv1.LabelServiceName]
	derivedEpSlice.Labels[discoveryv1.LabelServiceName] = derivedService.Name
	derivedEpSlice.Labels[mcsapiv1alpha1.LabelSourceCluster] = r.clusterName
	derivedEpSlice.Labels[discoveryv1.LabelManagedBy] = endpointSliceLocalMCSAPIControllerName

	if derivedEpSlice.Annotations == nil {
		derivedEpSlice.Annotations = map[string]string{}
	}
	derivedEpSlice.Labels[localEndpointSliceLabel] = localEpSlice.Name

	derivedEpSlice.AddressType = localEpSlice.AddressType

	// Beware those are shallow copies, content of the struct should not be modified
	derivedEpSlice.Endpoints = slices.Clone(localEpSlice.Endpoints)
	derivedEpSlice.Ports = slices.Clone(localEpSlice.Ports)
}

func (r *mcsAPIEndpointSliceMirrorReconciler) newDerivedEndpointSlice(
	localEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) *discoveryv1.EndpointSlice {
	// Note that derivedEpsliceKey can not return nil here since it has already
	// been checked by shouldMirrorLocalEndpointSlice that prevents the EndpointSlice
	// to not have a service label name
	derivedEpSliceKey := getLocalDerivedEndpointSliceKey(localEpSlice)
	derivedEndpointSlice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      derivedEpSliceKey.Name,
			Namespace: derivedEpSliceKey.Namespace,
		},
	}

	r.updateDerivedEndpointSlice(&derivedEndpointSlice, localEpSlice, derivedService)
	return &derivedEndpointSlice
}

func (r *mcsAPIEndpointSliceMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var epSlice discoveryv1.EndpointSlice
	if err := r.Client.Get(ctx, req.NamespacedName, &epSlice); err != nil {
		return controllerruntime.Fail(client.IgnoreNotFound(err))
	}

	var localEpSlice *discoveryv1.EndpointSlice
	var derivedEpSlice *discoveryv1.EndpointSlice
	var derivedServiceName string
	var err error

	if epSlice.Labels[discoveryv1.LabelManagedBy] == endpointSliceLocalMCSAPIControllerName {
		derivedEpSlice = &epSlice
		localEpSlice, err = r.getLocalEndpointSlice(ctx, derivedEpSlice)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		derivedServiceName = derivedEpSlice.Labels[discoveryv1.LabelServiceName]
		// We try to aggressively find the service name here to have a chance to fix the mirrored EndpointSlice
		if derivedServiceName == "" {
			derivedServiceName = getOwnerReferenceName(derivedEpSlice.GetOwnerReferences(), "v1", "Service")
		}
		if derivedServiceName == "" && localEpSlice != nil {
			derivedServiceName = getDerivedServiceName(localEpSlice)
		}
	} else {
		localEpSlice = &epSlice
		derivedEpSlice, err = r.getLocalDerivedEndpointSlice(ctx, localEpSlice)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		derivedServiceName = getDerivedServiceName(localEpSlice)
	}

	// Not finding the derived service name essentially means that the user manually
	// removed every mention of a link that we support between the EndpointSlice and its Service.
	if derivedServiceName == "" {
		if derivedEpSlice != nil {
			r.Logger.Warn(
				"Can not find a possible related derived Service name, "+
					"derived mirrored EndpointSlice was likely tampered and will be deleted",
				logfields.Request, req.NamespacedName,
			)
			if err := r.Client.Delete(ctx, derivedEpSlice); err != nil {
				return controllerruntime.Fail(client.IgnoreNotFound(err))
			}
		} else if localEpSlice != nil {
			// This will happen if the user has manually created an EndpointSlice and remove the label service name
			// instead of deleting it. In that case we find the mirrored derived EndpointSlice from its label
			// and remove it bypassing the general logic for this specific case.
			if derivedEpSlice, err = r.getDerivedEndpointSliceByLabel(ctx, client.ObjectKeyFromObject(localEpSlice)); err != nil {
				return controllerruntime.Fail(err)
			}
			if derivedEpSlice == nil {
				r.Logger.Debug(
					"Can not find a possible related derived Service name, reconciliation is aborted",
					logfields.Request, req.NamespacedName,
				)
				return controllerruntime.Success()
			}
			if err := r.Client.Delete(ctx, derivedEpSlice); err != nil {
				return controllerruntime.Fail(client.IgnoreNotFound(err))
			}
			return controllerruntime.Success()
		}
	}
	var derivedService corev1.Service
	if err := r.Client.Get(ctx, types.NamespacedName{
		Name:      derivedServiceName,
		Namespace: req.Namespace,
	}, &derivedService); err != nil {
		// If the derived service is not found, it probably isn't created yet
		// so we can stop there and wait for a future reconciliation where the derived
		// Service would be created.
		return controllerruntime.Fail(client.IgnoreNotFound(err))
	}

	var shouldMirror bool
	if shouldMirror, err = r.shouldMirrorLocalEndpointSlice(ctx, localEpSlice, &derivedService); err != nil {
		return controllerruntime.Fail(err)
	}
	if !shouldMirror {
		localEpSlice = nil
	}

	if localEpSlice == nil && derivedEpSlice != nil {
		err = r.Client.Delete(ctx, derivedEpSlice)
	} else if localEpSlice != nil && derivedEpSlice == nil {
		derivedEpSlice = r.newDerivedEndpointSlice(localEpSlice, &derivedService)
		err = r.Client.Create(ctx, derivedEpSlice)
	} else if localEpSlice != nil && r.needUpdate(localEpSlice, derivedEpSlice, &derivedService) {
		r.updateDerivedEndpointSlice(derivedEpSlice, localEpSlice, &derivedService)
		err = r.Client.Update(ctx, derivedEpSlice)
	}

	return controllerruntime.Fail(err)
}

// endpointSliceMirrorDeleteWatcher watch EndpointSlice and return the predicted
// mirrored EndpointSlice. If a non derived EndpointSlice it will return a derived
// EndpointSlice and the other way around. We have to do this because the very first
// thing we do in the Reconcile method is to get the EndpointSlice requested so on
// a delete we have to swap the EndpointSlice object essentially.
type endpointSliceMirrorDeleteWatcher struct{}

func (*endpointSliceMirrorDeleteWatcher) Delete(ctx context.Context, evt event.TypedDeleteEvent[client.Object], q workqueue.TypedRateLimitingInterface[ctrl.Request]) {
	epSlice := evt.Object.(*discoveryv1.EndpointSlice)
	switch epSlice.Labels[discoveryv1.LabelManagedBy] {
	case utils.EndpointSliceMeshControllerName:
		// We can explicitly ignore remote EndpointSlice
	case endpointSliceLocalMCSAPIControllerName:
		localEpSliceKey := getLocalEndpointSliceKey(epSlice)
		if localEpSliceKey == nil {
			return
		}
		q.Add(ctrl.Request{NamespacedName: *localEpSliceKey})
	default:
		derivedEpSliceKey := getLocalDerivedEndpointSliceKey(epSlice)
		if derivedEpSliceKey == nil {
			return
		}
		q.Add(ctrl.Request{NamespacedName: *derivedEpSliceKey})
	}
}

func (*endpointSliceMirrorDeleteWatcher) Create(context.Context, event.TypedCreateEvent[client.Object], workqueue.TypedRateLimitingInterface[ctrl.Request]) {
}

func (*endpointSliceMirrorDeleteWatcher) Update(context.Context, event.TypedUpdateEvent[client.Object], workqueue.TypedRateLimitingInterface[ctrl.Request]) {
}

func (*endpointSliceMirrorDeleteWatcher) Generic(context.Context, event.TypedGenericEvent[client.Object], workqueue.TypedRateLimitingInterface[ctrl.Request]) {
}

// SetupWithManager sets up the controller with the Manager.
func (r *mcsAPIEndpointSliceMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("EndpointSliceMirrorMCSAPI").
		For(&discoveryv1.EndpointSlice{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			switch obj.GetLabels()[discoveryv1.LabelManagedBy] {
			case utils.EndpointSliceMeshControllerName:
				// We can explicitly ignore remote EndpointSlice
			case endpointSliceLocalMCSAPIControllerName:
				return true
			default:
				return true
			}

			return false
		}))).

		// Special watchers for EndpointSlice deletion
		Watches(&discoveryv1.EndpointSlice{}, &endpointSliceMirrorDeleteWatcher{}).

		// Watch for changes to Service to enqueue local EndpointSlice
		Watches(&mcsapiv1alpha1.ServiceExport{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			return r.getEndpointSliceFromServiceRequests(ctx, client.ObjectKeyFromObject(obj))
		})).
		// Watch for changes to derived Service to enqueue local EndpointSlices.
		// We need to enqueue the "other" EndpointSlice to allow derived
		// EndpointSlice initial creation.
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			svcImportOwner := getOwnerReferenceName(obj.GetOwnerReferences(), mcsapiv1alpha1.GroupVersion.String(), kindServiceImport)
			if svcImportOwner != "" {
				return r.getEndpointSliceFromServiceRequests(ctx, types.NamespacedName{Name: svcImportOwner, Namespace: obj.GetNamespace()})
			}
			return nil
		})).
		Complete(r)
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getEndpointSliceFromServiceRequests(ctx context.Context, key types.NamespacedName) []ctrl.Request {
	serviceReq, _ := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{key.Name})
	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: key.Namespace, LabelSelector: selector}); err != nil {
		return nil
	}

	requests := make([]ctrl.Request, 0, len(epSliceList.Items))
	for _, epSlice := range epSliceList.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&epSlice)})
	}
	return requests
}

// getSuffix return the name of the EndpointSlice trimmed by its generatedName
func getSuffix(endpointSlice *discoveryv1.EndpointSlice) string {
	suffix := strings.TrimPrefix(endpointSlice.Name, endpointSlice.Labels[discoveryv1.LabelServiceName])
	suffixLen := min(40, len(suffix))
	suffix = strings.TrimLeft(suffix[len(suffix)-suffixLen:], "-.")
	return suffix
}

func (r *mcsAPIEndpointSliceMirrorReconciler) needUpdate(
	localEpSlice, derivedEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) bool {
	desiredDerivedEndpointSlice := r.newDerivedEndpointSlice(localEpSlice, derivedService)

	if !maps.Equal(derivedEpSlice.Labels, desiredDerivedEndpointSlice.Labels) {
		return true
	}
	if len(derivedEpSlice.OwnerReferences) != 1 &&
		derivedEpSlice.OwnerReferences[0].UID != derivedService.UID {
		return true
	}
	if derivedEpSlice.AddressType != desiredDerivedEndpointSlice.AddressType {
		return true
	}

	equalsEndpoint := func(a, b discoveryv1.Endpoint) bool {
		return reflect.DeepEqual(a, b)
	}
	if !slices.EqualFunc(derivedEpSlice.Endpoints, desiredDerivedEndpointSlice.Endpoints, equalsEndpoint) {
		return true
	}

	equalsEndpointPort := func(a, b discoveryv1.EndpointPort) bool {
		return reflect.DeepEqual(a, b)
	}
	if !slices.EqualFunc(derivedEpSlice.Ports, desiredDerivedEndpointSlice.Ports, equalsEndpointPort) {
		return true
	}

	return false
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getDerivedEndpointSliceByLabel(ctx context.Context, key types.NamespacedName) (*discoveryv1.EndpointSlice, error) {
	serviceReq, _ := labels.NewRequirement(localEndpointSliceLabel, selection.Equals, []string{key.Name})
	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: key.Namespace, LabelSelector: selector}); err != nil {
		return nil, err
	}

	if len(epSliceList.Items) != 1 {
		return nil, nil
	}

	return &epSliceList.Items[0], nil
}
