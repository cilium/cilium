// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"context"
	"fmt"
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
	endpointsliceutil "k8s.io/endpointslice/util"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
// EndpointSlice from a local Service with a ServiceExport to its derived Service
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
	if err := r.Client.List(ctx, &epSliceList); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	if err := r.List(ctx, &epSliceList, &client.ListOptions{Namespace: svc.Namespace, LabelSelector: selector}); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return epSliceList.Items, nil
}

// getLocalDerivedEndpointSlice returns the service that we are currently exporting from. This
// means that that the Service is only returned if a ServiceExport is also created
func (r *mcsAPIEndpointSliceMirrorReconciler) getLocalDerivedEndpointSlice(ctx context.Context, req ctrl.Request) ([]discoveryv1.EndpointSlice, error) {
	serviceReq, _ := labels.NewRequirement(mcsapiv1alpha1.LabelServiceName, selection.Equals, []string{req.Name})
	controllerReq, _ := labels.NewRequirement(discoveryv1.LabelManagedBy, selection.Equals, []string{endpointSliceLocalMCSAPIControllerName})

	selector := labels.NewSelector()
	selector = selector.Add(*serviceReq)
	selector = selector.Add(*controllerReq)

	var epSliceList discoveryv1.EndpointSliceList
	if err := r.Client.List(ctx, &epSliceList); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	if err := r.List(ctx, &epSliceList, &client.ListOptions{Namespace: req.Namespace, LabelSelector: selector}); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return epSliceList.Items, nil
}

// getSuffix return the name of the EndpointSlice trimmed by its generatedName
func getSuffix(endpointSlice *discoveryv1.EndpointSlice) string {
	return strings.TrimPrefix(endpointSlice.Name, endpointSlice.GenerateName)
}

// getSuffixMap return a map with the keys being the name of the EndpointSlice trimmed by its generatedName
func getSuffixMap(endpointSlices []discoveryv1.EndpointSlice) map[string]*discoveryv1.EndpointSlice {
	endpointSlicesMap := map[string]*discoveryv1.EndpointSlice{}
	for _, endpointSlice := range endpointSlices {
		endpointSlicesMap[getSuffix(&endpointSlice)] = &endpointSlice
	}
	return endpointSlicesMap
}

func equalsEndpointPorts(a, b *discoveryv1.EndpointPort) bool {
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

func needUpdate(localEndpointSlice, derivedEndpointSlice *discoveryv1.EndpointSlice, clusterName string, derivedService *corev1.Service) bool {
	desiredDerivedEndpointSlice := newDerivedEndpointSlice(localEndpointSlice, clusterName, derivedService)

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

	if len(derivedEndpointSlice.Ports) != len(localEndpointSlice.Ports) {
		return true
	}
	for i := range derivedEndpointSlice.Ports {
		if !equalsEndpointPorts(&derivedEndpointSlice.Ports[i], &localEndpointSlice.Ports[i]) {
			return true
		}
	}

	if len(derivedEndpointSlice.Endpoints) != len(localEndpointSlice.Endpoints) {
		return true
	}
	for i := range derivedEndpointSlice.Endpoints {
		if !endpointsliceutil.EndpointsEqualBeyondHash(&derivedEndpointSlice.Endpoints[i], &localEndpointSlice.Endpoints[i]) {
			return true
		}
	}

	return false
}

func computePlan(derivedEndpointSlicesMap, localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice, clusterName string, derivedService *corev1.Service) (toUpdateSuffixes, toAddSuffixes, toDeleteSuffixes []string) {
	for derivedSuffix, derivedEndpointSlice := range derivedEndpointSlicesMap {
		localEndpointSlice, ok := localEndpointSlicesMap[derivedSuffix]
		if !ok {
			toDeleteSuffixes = append(toDeleteSuffixes, derivedSuffix)
		} else if needUpdate(localEndpointSlice, derivedEndpointSlice, clusterName, derivedService) {
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

func (r *mcsAPIEndpointSliceMirrorReconciler) updateEndpointSlices(ctx context.Context, toUpdateSuffixes []string, derivedEndpointSlicesMap, localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice, derivedService *corev1.Service) error {
	if len(toUpdateSuffixes) == 0 {
		return nil
	}

	for _, suffix := range toUpdateSuffixes {
		localEndpointSlice := localEndpointSlicesMap[suffix]
		derivedEndpointSlice := derivedEndpointSlicesMap[suffix]

		updateDerivedEndpointSlice(derivedEndpointSlice, localEndpointSlice, r.clusterName, derivedService)
		if err := r.Client.Update(ctx, derivedEndpointSlice); err != nil {
			return err
		}
	}
	return nil
}

func updateDerivedEndpointSlice(derivedEndpointSlice, localEndpointSlice *discoveryv1.EndpointSlice, clusterName string, derivedService *corev1.Service) {
	derivedEndpointSlice.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         derivedService.APIVersion,
			Kind:               derivedService.Kind,
			Name:               derivedService.Name,
			UID:                derivedService.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		},
	}

	derivedEndpointSlice.Labels = maps.Clone(derivedService.Labels)
	if derivedEndpointSlice.Labels == nil {
		derivedEndpointSlice.Labels = map[string]string{}
	}
	derivedEndpointSlice.Labels[mcsapiv1alpha1.LabelSourceCluster] = clusterName
	derivedEndpointSlice.Labels[discoveryv1.LabelManagedBy] = endpointSliceLocalMCSAPIControllerName

	derivedEndpointSlice.Annotations = maps.Clone(localEndpointSlice.Annotations)

	derivedEndpointSlice.AddressType = localEndpointSlice.AddressType
	derivedEndpointSlice.Endpoints = slices.Clone(localEndpointSlice.Endpoints)
	derivedEndpointSlice.Ports = slices.Clone(localEndpointSlice.Ports)
}

func newDerivedEndpointSlice(localEndpointSlice *discoveryv1.EndpointSlice, clusterName string, derivedService *corev1.Service) *discoveryv1.EndpointSlice {
	derivedEndpointSlice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:         derivedService.Name + "-" + getSuffix(localEndpointSlice),
			GenerateName: derivedService.Name + "-",
			Namespace:    derivedService.Namespace,
		},
	}

	updateDerivedEndpointSlice(&derivedEndpointSlice, localEndpointSlice, clusterName, derivedService)
	return &derivedEndpointSlice
}

func (r *mcsAPIEndpointSliceMirrorReconciler) addEndpointSlices(ctx context.Context, toAddSuffixes []string, localEndpointSlicesMap map[string]*discoveryv1.EndpointSlice, derivedService *corev1.Service) error {
	if len(toAddSuffixes) == 0 {
		return nil
	}

	for _, suffix := range toAddSuffixes {
		localEndpointSlice := localEndpointSlicesMap[suffix]

		if err := r.Client.Create(ctx, newDerivedEndpointSlice(localEndpointSlice, r.clusterName, derivedService)); err != nil {
			return err
		}
	}
	return nil
}

func (r *mcsAPIEndpointSliceMirrorReconciler) deleteEndpointSlices(ctx context.Context, toDeleteSuffixes []string, derivedEndpointSlicesMap map[string]*discoveryv1.EndpointSlice) error {
	if len(toDeleteSuffixes) == 0 {
		return nil
	}

	for _, suffix := range toDeleteSuffixes {
		if err := r.Client.Delete(ctx, derivedEndpointSlicesMap[suffix]); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

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

	toUpdateSuffixes, toAddSuffixes, toDeleteSuffixes := computePlan(derivedEndpointSlicesMap, localEndpointSlicesMap, r.clusterName, &derivedService)
	r.Logger.Debug(
		"MCSAPI EndpointSlice Mirror Reconciler",
		slog.String("req", req.String()), slog.String("toUpdateSuffixes", fmt.Sprint(toUpdateSuffixes)),
		slog.String("toAddSUffixes", fmt.Sprint(toAddSuffixes)), slog.String("toDeleteSuffixes", fmt.Sprint(toDeleteSuffixes)),
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
