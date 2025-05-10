// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const (
	// endpointSliceLocalMCSAPIControllerName is a unique value used with LabelManagedBy to indicate
	// the component managing an EndpointSlice.
	endpointSliceLocalMCSAPIControllerName = "endpointslice-local-mcsapi-controller.cilium.io"
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

func (r *mcsAPIEndpointSliceMirrorReconciler) getDerivedService(ctx context.Context, key types.NamespacedName) (*corev1.Service, error) {
	var derivedService corev1.Service
	if err := r.Client.Get(ctx, key, &derivedService); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &derivedService, nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalEndpointSlice(
	ctx context.Context, derivedEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) (*discoveryv1.EndpointSlice, error) {
	serviceName := derivedEpSlice.Labels[mcsapiv1alpha1.LabelServiceName]
	if serviceName == "" {
		return nil, nil
	}
	suffix := getSuffix(derivedEpSlice)
	var localEpSlice discoveryv1.EndpointSlice
	if err := r.Client.Get(
		ctx,
		types.NamespacedName{Name: serviceName + "-" + suffix, Namespace: derivedEpSlice.Namespace},
		&localEpSlice,
	); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return &localEpSlice, nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) isServiceExported(ctx context.Context, key types.NamespacedName) (bool, error) {
	var svcExport mcsapiv1alpha1.ServiceExport
	if err := r.Client.Get(
		ctx, key, &svcExport,
	); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return true, nil
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
	if isExported, err := r.isServiceExported(
		ctx,
		types.NamespacedName{Name: serviceName, Namespace: localEpSlice.Namespace},
	); !isExported || err != nil {
		return false, err
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

func getLocalDerivedEndpointSliceName(localEpSlice *discoveryv1.EndpointSlice) string {
	suffix := getSuffix(localEpSlice)
	derivedServiceName := getDerivedServiceName(localEpSlice)
	if derivedServiceName == "" || suffix == "" {
		return ""
	}
	return derivedServiceName + "-" + suffix
}

func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalDerivedEndpointSlice(
	ctx context.Context, localEpSlice *discoveryv1.EndpointSlice,
) (*discoveryv1.EndpointSlice, error) {
	derivedEpSliceName := getLocalDerivedEndpointSliceName(localEpSlice)
	if derivedEpSliceName == "" {
		return nil, nil
	}
	var derivedEpSlice discoveryv1.EndpointSlice
	if err := r.Client.Get(
		ctx,
		types.NamespacedName{
			Name:      derivedEpSliceName,
			Namespace: localEpSlice.Namespace,
		},
		&derivedEpSlice,
	); err != nil {
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

	derivedEpSlice.Annotations = nil
	derivedEpSlice.AddressType = localEpSlice.AddressType

	// Beware those are shallow copies, content of the struct should not be modified
	derivedEpSlice.Endpoints = slices.Clone(localEpSlice.Endpoints)
	derivedEpSlice.Ports = shallowCopyServicePortToEndpointPort(derivedService.Spec.Ports)
}

func shallowCopyServicePortToEndpointPort(ports []corev1.ServicePort) []discoveryv1.EndpointPort {
	endpointPorts := make([]discoveryv1.EndpointPort, 0, len(ports))
	for _, port := range ports {
		endpointPort := discoveryv1.EndpointPort{
			Port:        &port.Port,
			AppProtocol: port.AppProtocol,
		}
		if port.Name != "" {
			endpointPort.Name = &port.Name
		}
		if port.Protocol != "" {
			endpointPort.Protocol = &port.Protocol
		}
		endpointPorts = append(endpointPorts, endpointPort)
	}
	return endpointPorts
}

func (r *mcsAPIEndpointSliceMirrorReconciler) newDerivedEndpointSlice(
	localEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) *discoveryv1.EndpointSlice {
	derivedEndpointSlice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      derivedService.Name + "-" + getSuffix(localEpSlice),
			Namespace: derivedService.Namespace,
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
	var derivedService *corev1.Service
	var err error

	if epSlice.Labels[discoveryv1.LabelManagedBy] == endpointSliceLocalMCSAPIControllerName {
		derivedEpSlice = &epSlice
		derivedService, err = r.getDerivedService(
			ctx,
			types.NamespacedName{
				Name:      derivedEpSlice.Labels[discoveryv1.LabelServiceName],
				Namespace: derivedEpSlice.Namespace,
			},
		)
		if err != nil || derivedService == nil {
			return controllerruntime.Fail(err)
		}
		localEpSlice, err = r.getLocalEndpointSlice(ctx, derivedEpSlice, derivedService)
	} else {
		localEpSlice = &epSlice
		if isExported, err := r.isServiceExported(
			ctx,
			types.NamespacedName{
				Name:      localEpSlice.Labels[discoveryv1.LabelServiceName],
				Namespace: localEpSlice.Namespace,
			},
		); !isExported || err != nil {
			return controllerruntime.Fail(err)
		}
		derivedEpSlice, err = r.getLocalDerivedEndpointSlice(ctx, localEpSlice)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		derivedService, err = r.getDerivedService(ctx,
			types.NamespacedName{
				Name:      getDerivedServiceName(localEpSlice),
				Namespace: localEpSlice.Namespace,
			})
	}
	if err != nil || derivedService == nil {
		return controllerruntime.Fail(err)
	}

	var shouldMirror bool
	if shouldMirror, err = r.shouldMirrorLocalEndpointSlice(ctx, localEpSlice, derivedService); err != nil {
		return controllerruntime.Fail(err)
	}
	if !shouldMirror {
		localEpSlice = nil
	}

	if localEpSlice == nil && derivedEpSlice != nil {
		err = r.Client.Delete(ctx, derivedEpSlice)
	} else if localEpSlice != nil && derivedEpSlice == nil {
		derivedEpSlice = r.newDerivedEndpointSlice(localEpSlice, derivedService)
		err = r.Client.Create(ctx, derivedEpSlice)
	} else if localEpSlice != nil && r.needUpdate(localEpSlice, derivedEpSlice, derivedService) {
		r.updateDerivedEndpointSlice(derivedEpSlice, localEpSlice, derivedService)
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
		serviceName := epSlice.Labels[mcsapiv1alpha1.LabelServiceName]
		if serviceName == "" {
			return
		}
		q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
			Name:      serviceName + "-" + getSuffix(epSlice),
			Namespace: epSlice.Namespace,
		}})
	default:
		q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
			Name:      getLocalDerivedEndpointSliceName(epSlice),
			Namespace: epSlice.Namespace,
		}})
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
			serviceReq, _ := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{obj.GetName()})
			selector := labels.NewSelector()
			selector = selector.Add(*serviceReq)

			var epSliceList discoveryv1.EndpointSliceList
			if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: obj.GetNamespace(), LabelSelector: selector}); err != nil {
				return []ctrl.Request{}
			}

			requests := []ctrl.Request{}
			for _, epSlice := range epSliceList.Items {
				requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
					Name:      epSlice.Name,
					Namespace: epSlice.Namespace,
				}})
			}
			return requests
		})).
		// Watch for changes to derived Service to enqueue local EndpointSlices.
		// We need to enqueue the "other" EndpointSlice to allow derived
		// EndpointSlice initial creation.
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			svcImportOwner := getOwnerReferenceName(obj.GetOwnerReferences(), mcsapiv1alpha1.GroupVersion.String(), kindServiceImport)
			if svcImportOwner != "" {
				serviceReq, _ := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{svcImportOwner})
				selector := labels.NewSelector()
				selector = selector.Add(*serviceReq)

				var epSliceList discoveryv1.EndpointSliceList
				if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: obj.GetNamespace(), LabelSelector: selector}); err != nil {
					return []ctrl.Request{}
				}

				requests := []ctrl.Request{}
				for _, epSlice := range epSliceList.Items {
					requests = append(requests, ctrl.Request{NamespacedName: types.NamespacedName{
						Name:      epSlice.Name,
						Namespace: epSlice.Namespace,
					}})
				}
				return requests
			}
			return []ctrl.Request{}
		})).
		Complete(r)
}

// getSuffix return the name of the EndpointSlice trimmed by its generatedName
func getSuffix(endpointSlice *discoveryv1.EndpointSlice) string {
	suffix := strings.TrimPrefix(endpointSlice.Name, endpointSlice.Labels[discoveryv1.LabelServiceName]+"-")
	suffixLen := min(40, len(suffix))
	suffix = strings.TrimPrefix(suffix[len(suffix)-suffixLen:], "-")
	return suffix
}

func equalsEndpointPort(a, b discoveryv1.EndpointPort) bool {
	if ptr.Deref(a.Name, "") != ptr.Deref(b.Name, "") {
		return false
	}
	if ptr.Deref(a.Protocol, "") != ptr.Deref(b.Protocol, "") {
		return false
	}
	if ptr.Deref(a.Port, 0) != ptr.Deref(b.Port, 0) {
		return false
	}
	if ptr.Deref(a.AppProtocol, "") != ptr.Deref(b.AppProtocol, "") {
		return false
	}
	return true
}

func equalsEndpoint(a, b discoveryv1.Endpoint) bool {
	if !slices.Equal(a.Addresses, b.Addresses) {
		return false
	}
	if ptr.Deref(a.Conditions.Ready, false) != ptr.Deref(b.Conditions.Ready, false) {
		return false
	}
	if ptr.Deref(a.Conditions.Serving, false) != ptr.Deref(b.Conditions.Serving, false) {
		return false
	}
	if ptr.Deref(a.Conditions.Terminating, false) != ptr.Deref(b.Conditions.Terminating, false) {
		return false
	}
	if ptr.Deref(a.Hostname, "") != ptr.Deref(b.Hostname, "") {
		return false
	}
	if (a.TargetRef == nil || b.TargetRef == nil) && a.TargetRef != b.TargetRef {
		return false
	} else if a.TargetRef != nil && a.TargetRef.UID != b.TargetRef.UID {
		return false
	}
	if ptr.Deref(a.NodeName, "") != ptr.Deref(b.NodeName, "") {
		return false
	}
	if ptr.Deref(a.Zone, "") != ptr.Deref(b.Zone, "") {
		return false
	}
	if (a.Hints == nil || b.Hints == nil) && a.Hints != b.Hints {
		return false
	} else if a.Hints != nil && !slices.Equal(a.Hints.ForZones, b.Hints.ForZones) {
		return false
	}
	return true
}

func (r *mcsAPIEndpointSliceMirrorReconciler) needUpdate(
	localEpSlice, derivedEpSlice *discoveryv1.EndpointSlice, derivedService *corev1.Service,
) bool {
	desiredDerivedEndpointSlice := r.newDerivedEndpointSlice(localEpSlice, derivedService)

	if !maps.Equal(derivedEpSlice.Labels, desiredDerivedEndpointSlice.Labels) {
		return true
	}
	if !maps.Equal(derivedEpSlice.Annotations, desiredDerivedEndpointSlice.Annotations) {
		return true
	}
	if len(derivedEpSlice.OwnerReferences) != 1 &&
		derivedEpSlice.OwnerReferences[0].UID != derivedService.UID {
		return true
	}
	if derivedEpSlice.AddressType != localEpSlice.AddressType {
		return true
	}

	if !slices.EqualFunc(derivedEpSlice.Endpoints, localEpSlice.Endpoints, equalsEndpoint) {
		return true
	}
	desiredPorts := shallowCopyServicePortToEndpointPort(derivedService.Spec.Ports)
	if !slices.EqualFunc(derivedEpSlice.Ports, desiredPorts, equalsEndpointPort) {
		return true
	}

	return false
}
