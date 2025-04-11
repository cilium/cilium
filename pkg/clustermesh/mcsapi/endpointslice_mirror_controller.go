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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

// getLocalEndpointSliceIfExported returns the EndpointSlices from a local service if it is being exported.
func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalEndpointSliceIfExported(ctx context.Context, req ctrl.Request) ([]discoveryv1.EndpointSlice, error) {
	var svcExport mcsapiv1alpha1.ServiceExport
	if err := r.Client.Get(ctx, req.NamespacedName, &svcExport); err != nil {
		return nil, client.IgnoreNotFound(err)
	}

	var svc corev1.Service
	if err := r.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		return nil, client.IgnoreNotFound(err)
	}

	serviceReq, _ := labels.NewRequirement(discoveryv1.LabelServiceName, selection.Equals, []string{svc.Name})
	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: svc.Namespace, LabelSelector: selector}); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return epSliceList.Items, nil
}

// getLocalDerivedEndpointSlice returns the EndpointSlice of local (non derived) Service
// if it is being exported.
func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalDerivedEndpointSlice(
	ctx context.Context, req ctrl.Request,
) ([]discoveryv1.EndpointSlice, error) {
	serviceReq, _ := labels.NewRequirement(mcsapiv1alpha1.LabelServiceName, selection.Equals, []string{req.Name})
	controllerReq, _ := labels.NewRequirement(discoveryv1.LabelManagedBy, selection.Equals, []string{endpointSliceLocalMCSAPIControllerName})

	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)
	selector = selector.Add(*controllerReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.Client.List(ctx, &epSliceList, &client.ListOptions{Namespace: req.Namespace, LabelSelector: selector}); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return epSliceList.Items, nil
}

func computePlan(
	derivedEndpointSlicesMap, localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice,
	clusterName string, derivedService *corev1.Service, scheme *runtime.Scheme,
) (toUpdateSuffixes, toAddSuffixes, toDeleteSuffixes []string) {
	for derivedSuffix, derivedEndpointSlice := range derivedEndpointSlicesMap {
		localEndpointSlice, ok := localEndpointSlicesMap[derivedSuffix]
		if !ok {
			toDeleteSuffixes = append(toDeleteSuffixes, derivedSuffix)
		} else if needUpdate(localEndpointSlice, derivedEndpointSlice, clusterName, derivedService, scheme) {
			toUpdateSuffixes = append(toUpdateSuffixes, derivedSuffix)
		}
	}

	for localSuffix := range localEndpointSlicesMap {
		if _, ok := derivedEndpointSlicesMap[localSuffix]; !ok {
			toAddSuffixes = append(toAddSuffixes, localSuffix)
		}
	}

	return
}

func (r *mcsAPIEndpointSliceMirrorReconciler) updateEndpointSlices(
	ctx context.Context, toUpdateSuffixes []string, derivedEndpointSlicesMap,
	localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice,
	derivedService *corev1.Service,
) error {
	for _, suffix := range toUpdateSuffixes {
		localEndpointSlice := localEndpointSlicesMap[suffix]
		derivedEndpointSlice := derivedEndpointSlicesMap[suffix]

		updateDerivedEndpointSlice(derivedEndpointSlice, localEndpointSlice, r.clusterName, derivedService, r.Scheme())
		if err := r.Client.Update(ctx, derivedEndpointSlice); err != nil {
			return err
		}
	}
	return nil
}

func updateDerivedEndpointSlice(
	derivedEndpointSlice, localEndpointSlice *discoveryv1.EndpointSlice,
	clusterName string, derivedService *corev1.Service, scheme *runtime.Scheme,
) {
	controllerutil.SetControllerReference(derivedService, derivedEndpointSlice, scheme)

	derivedEndpointSlice.Labels = maps.Clone(derivedService.Labels)
	if derivedEndpointSlice.Labels == nil {
		derivedEndpointSlice.Labels = map[string]string{}
	}
	derivedEndpointSlice.Labels[mcsapiv1alpha1.LabelServiceName] = localEndpointSlice.Labels[discoveryv1.LabelServiceName]
	derivedEndpointSlice.Labels[discoveryv1.LabelServiceName] = derivedService.Name
	derivedEndpointSlice.Labels[mcsapiv1alpha1.LabelSourceCluster] = clusterName
	derivedEndpointSlice.Labels[discoveryv1.LabelManagedBy] = endpointSliceLocalMCSAPIControllerName

	derivedEndpointSlice.Annotations = nil
	derivedEndpointSlice.AddressType = localEndpointSlice.AddressType

	// Beware those are shallow copies, content of the struct should not be modified
	derivedEndpointSlice.Endpoints = slices.Clone(localEndpointSlice.Endpoints)
	derivedEndpointSlice.Ports = slices.Clone(localEndpointSlice.Ports)
}

func newDerivedEndpointSlice(
	localEndpointSlice *discoveryv1.EndpointSlice, clusterName string,
	derivedService *corev1.Service, scheme *runtime.Scheme,
) *discoveryv1.EndpointSlice {
	derivedEndpointSlice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:         derivedService.Name + "-" + getSuffix(localEndpointSlice),
			GenerateName: derivedService.Name + "-",
			Namespace:    derivedService.Namespace,
		},
	}

	updateDerivedEndpointSlice(&derivedEndpointSlice, localEndpointSlice, clusterName, derivedService, scheme)
	return &derivedEndpointSlice
}

func (r *mcsAPIEndpointSliceMirrorReconciler) addEndpointSlices(
	ctx context.Context, toAddSuffixes []string, localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice,
	derivedService *corev1.Service,
) error {
	for _, suffix := range toAddSuffixes {
		localEndpointSlice := localEndpointSlicesMap[suffix]

		if err := r.Client.Create(ctx, newDerivedEndpointSlice(localEndpointSlice, r.clusterName, derivedService, r.Scheme())); err != nil {
			return err
		}
	}
	return nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) deleteEndpointSlices(
	ctx context.Context, toDeleteSuffixes []string, derivedEndpointSlicesMap map[string]*discoveryv1.EndpointSlice,
) error {
	for _, suffix := range toDeleteSuffixes {
		if err := r.Client.Delete(ctx, derivedEndpointSlicesMap[suffix]); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

const (
	logAttrToUpdateSuffixes = "toUpdateSuffixes"
	logAttrToAddSuffixes    = "toAddSuffixes"
	logAttrToDeleteSuffixes = "toDeleteSuffixes"
)

func (r *mcsAPIEndpointSliceMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	localEndpointSlices, err := r.getLocalEndpointSliceIfExported(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	derivedEndpointSlices, err := r.getLocalDerivedEndpointSlice(ctx, req)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	derivedService := corev1.Service{}
	derivedServiceName := derivedName(req.NamespacedName)
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      derivedServiceName,
	}, &derivedService); err != nil {
		return controllerruntime.Fail(client.IgnoreNotFound(err))
	}

	derivedEndpointSlicesMap := getSuffixMap(derivedEndpointSlices)
	localEndpointSlicesMap := getSuffixMap(localEndpointSlices)

	toUpdateSuffixes, toAddSuffixes, toDeleteSuffixes := computePlan(
		derivedEndpointSlicesMap, localEndpointSlicesMap, r.clusterName,
		&derivedService, r.Scheme(),
	)
	r.Logger.Debug(
		"MCSAPI EndpointSlice Mirror Reconciler",
		logfields.Request, req,
		logAttrToUpdateSuffixes, toUpdateSuffixes,
		logAttrToAddSuffixes, toAddSuffixes,
		logAttrToDeleteSuffixes, toDeleteSuffixes,
	)

	if err := r.addEndpointSlices(ctx, toAddSuffixes, localEndpointSlicesMap, &derivedService); err != nil {
		return controllerruntime.Fail(err)
	}
	if err := r.updateEndpointSlices(ctx, toUpdateSuffixes, derivedEndpointSlicesMap, localEndpointSlicesMap, &derivedService); err != nil {
		return controllerruntime.Fail(err)
	}
	if err := r.deleteEndpointSlices(ctx, toDeleteSuffixes, derivedEndpointSlicesMap); err != nil {
		return controllerruntime.Fail(err)
	}

	return controllerruntime.Success()
}

// SetupWithManager sets up the controller with the Manager.
func (r *mcsAPIEndpointSliceMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("EndpointSliceMirrorMCSAPI").
		// We own the ServiceExport as we need to get the actual name of the service
		// and that we only need to do this when a Service is actually exported.
		For(&mcsapiv1alpha1.ServiceExport{}).
		// Watch for changes to EndpointSlices
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			switch obj.GetLabels()[discoveryv1.LabelManagedBy] {
			case utils.EndpointSliceMeshControllerName:
				// We can explicitly ignore remote EndpointSlice
			case endpointSliceLocalMCSAPIControllerName:
				if svcName := obj.GetLabels()[mcsapiv1alpha1.LabelServiceName]; svcName != "" {
					return []ctrl.Request{{NamespacedName: types.NamespacedName{
						Name: svcName, Namespace: obj.GetNamespace(),
					}}}
				}
			default:
				if svcName := obj.GetLabels()[discoveryv1.LabelServiceName]; svcName != "" {
					return []ctrl.Request{{NamespacedName: types.NamespacedName{
						Name: svcName, Namespace: obj.GetNamespace(),
					}}}
				}
			}

			return []ctrl.Request{}
		})).
		// Watch for changes to Services
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			svcImportOwner := getOwnerReferenceName(obj.GetOwnerReferences(), mcsapiv1alpha1.GroupVersion.String(), kindServiceImport)
			if svcImportOwner == "" {
				return []ctrl.Request{{NamespacedName: types.NamespacedName{
					Name: obj.GetName(), Namespace: obj.GetNamespace(),
				}}}
			}
			return []ctrl.Request{{NamespacedName: types.NamespacedName{
				Name: svcImportOwner, Namespace: obj.GetNamespace(),
			}}}
		})).
		Complete(r)
}

// getSuffix return the name of the EndpointSlice trimmed by its generatedName
func getSuffix(endpointSlice *discoveryv1.EndpointSlice) string {
	suffix := strings.TrimPrefix(endpointSlice.Name, endpointSlice.GenerateName)
	// We also attempt to trim the prefix via the Service name in case the EndpointSlice
	// was not created via kube-controller-manager and make sure it is within a reasonable length
	suffix = strings.TrimPrefix(suffix, endpointSlice.Labels[discoveryv1.LabelServiceName])
	suffixLen := min(40, len(suffix))
	suffix = strings.TrimPrefix(suffix[len(suffix)-suffixLen:], "-")
	return suffix
}

// getSuffixMap return a map with the keys being the name of the EndpointSlice trimmed by its generatedName
func getSuffixMap(endpointSlices []discoveryv1.EndpointSlice) map[string]*discoveryv1.EndpointSlice {
	endpointSlicesMap := map[string]*discoveryv1.EndpointSlice{}
	for _, endpointSlice := range endpointSlices {
		endpointSlicesMap[getSuffix(&endpointSlice)] = &endpointSlice
	}
	return endpointSlicesMap
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

func needUpdate(
	localEndpointSlice, derivedEndpointSlice *discoveryv1.EndpointSlice,
	clusterName string, derivedService *corev1.Service, scheme *runtime.Scheme,
) bool {
	desiredDerivedEndpointSlice := newDerivedEndpointSlice(localEndpointSlice, clusterName, derivedService, scheme)

	if !maps.Equal(derivedEndpointSlice.Labels, desiredDerivedEndpointSlice.Labels) {
		return true
	}
	if !maps.Equal(derivedEndpointSlice.Annotations, desiredDerivedEndpointSlice.Annotations) {
		return true
	}
	if len(derivedEndpointSlice.OwnerReferences) != 1 &&
		derivedEndpointSlice.OwnerReferences[0].UID != derivedService.UID {
		return true
	}
	if derivedEndpointSlice.AddressType != localEndpointSlice.AddressType {
		return true
	}

	if !slices.EqualFunc(derivedEndpointSlice.Ports, localEndpointSlice.Ports, equalsEndpointPort) {
		return true
	}
	if !slices.EqualFunc(derivedEndpointSlice.Endpoints, localEndpointSlice.Endpoints, equalsEndpoint) {
		return true
	}

	return false
}
