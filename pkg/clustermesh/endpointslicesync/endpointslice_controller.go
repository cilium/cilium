// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/pkg/annotation"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	endpointslicetypes "github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	slimdiscoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
)

const (
	remoteEndpointSliceAnnotation      = annotation.ServicePrefix + "/remote-endpointslice"
	localEndpointSliceByRemoteKeyIndex = "clustermesh.cilium.io/endpointslice-by-remote-key"
	malformedEndpointSlicePrefix       = "@malformed-endpointslice|"
)

func malformedEndpointSliceRequest(name string) string {
	return malformedEndpointSlicePrefix + name
}

func parseMalformedEndpointSliceRequest(name string) (string, bool) {
	return strings.CutPrefix(name, malformedEndpointSlicePrefix)
}

// endpointSliceReconciler is a controller that reconciles remote ClusterEndpointSlices
// into local EndpointSlices.
type endpointSliceReconciler struct {
	client.Client
	logger                    *slog.Logger
	cache                     *operator.CacheStore[*endpointslicetypes.ClusterEndpointSlice]
	remoteEndpointSliceSource source.Source
	namespaceConfig           cmnamespace.Config
}

func localEndpointSliceKey(remoteEndpointSlice *endpointslicetypes.ClusterEndpointSlice) types.NamespacedName {
	name := remoteEndpointSlice.Name + "-" + remoteEndpointSlice.Cluster
	return types.NamespacedName{
		Name:      shortener.ShortenDNSSubdomainK8sName(name),
		Namespace: remoteEndpointSlice.Namespace,
	}
}

func remoteEndpointSliceReconcileKey(remoteEndpointSlice *endpointslicetypes.ClusterEndpointSlice) types.NamespacedName {
	return types.NamespacedName{
		Name:      remoteEndpointSlice.Name + "@" + remoteEndpointSlice.Cluster,
		Namespace: remoteEndpointSlice.Namespace,
	}
}

func parseRemoteEndpointSliceKey(key types.NamespacedName) (name, cluster string) {
	name, cluster, _ = strings.Cut(key.Name, "@")
	return name, cluster
}

func remoteEndpointSliceReconcileKeyFromLocalEndpointSlice(localEndpointSlice *discoveryv1.EndpointSlice) *types.NamespacedName {
	name := localEndpointSlice.Annotations[remoteEndpointSliceAnnotation]
	cluster := localEndpointSlice.Labels[mcsapiv1beta1.LabelSourceCluster]
	if name == "" || cluster == "" {
		return nil
	}
	return &types.NamespacedName{
		Name:      name + "@" + cluster,
		Namespace: localEndpointSlice.Namespace,
	}
}

func localEndpointSliceByRemoteKeyIndexFunc(obj client.Object) []string {
	localEndpointSlice := obj.(*discoveryv1.EndpointSlice)
	if localEndpointSlice.Labels[discoveryv1.LabelManagedBy] != utils.EndpointSliceMeshControllerName {
		return nil
	}
	key := remoteEndpointSliceReconcileKeyFromLocalEndpointSlice(localEndpointSlice)
	if key == nil {
		return nil
	}
	return []string{key.String()}
}

func (r *endpointSliceReconciler) getRemoteEndpointSlice(
	key types.NamespacedName,
) (*endpointslicetypes.ClusterEndpointSlice, bool) {
	name, cluster := parseRemoteEndpointSliceKey(key)
	return r.cache.Get(&endpointslicetypes.ClusterEndpointSlice{
		Cluster: cluster, Namespace: key.Namespace, Name: name,
	})
}

func shouldSyncEndpointSlice(svc *corev1.Service, addressType slimdiscoveryv1.AddressType) bool {
	value, ok := annotation.Get(svc, annotation.GlobalService, annotation.GlobalServiceAlias)
	if !ok || !strings.EqualFold(value, "true") {
		return false
	}
	value, ok = annotation.Get(svc, annotation.GlobalServiceSyncEndpointSlices)
	if !ok {
		// If the service is headless we sync the EndpointSlice by default
		if svc.Spec.ClusterIP != corev1.ClusterIPNone {
			return false
		}
	} else if !strings.EqualFold(value, "true") {
		return false
	}

	// Use the internal supported IP families annotation from our MCS-API implementation if present
	value, ok = svc.Annotations[annotation.SupportedIPFamilies]
	ipFamilies, err := mcsapitypes.IPFamiliesFromString(value)
	if !ok || err != nil {
		ipFamilies = svc.Spec.IPFamilies
	}
	return slices.Contains(ipFamilies, corev1.IPFamily(addressType))
}

func (r *endpointSliceReconciler) getAndCleanupLocalEndpointSlices(
	ctx context.Context,
	requestKey types.NamespacedName,
	desiredKey *types.NamespacedName,
) (*discoveryv1.EndpointSlice, error) {
	var localEndpointSlices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &localEndpointSlices,
		client.InNamespace(requestKey.Namespace),
		client.MatchingFields{localEndpointSliceByRemoteKeyIndex: requestKey.String()},
		client.MatchingLabels{discoveryv1.LabelManagedBy: utils.EndpointSliceMeshControllerName},
	); err != nil {
		return nil, err
	}

	var current *discoveryv1.EndpointSlice
	for i := range localEndpointSlices.Items {
		localEndpointSlice := &localEndpointSlices.Items[i]
		if desiredKey != nil && localEndpointSlice.Name == desiredKey.Name {
			current = localEndpointSlice
			continue
		}
		if err := r.Client.Delete(ctx, localEndpointSlice, client.Preconditions{
			UID: &localEndpointSlice.UID, ResourceVersion: &localEndpointSlice.ResourceVersion,
		}); err != nil && !apierrors.IsNotFound(err) {
			return nil, err
		}
	}
	return current, nil
}

func (r *endpointSliceReconciler) cleanupLocalEndpointSlices(ctx context.Context, key types.NamespacedName) error {
	_, err := r.getAndCleanupLocalEndpointSlices(ctx, key, nil)
	return err
}

func (r *endpointSliceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Most reconcile requests should be from remote cluster endpoint slices except when
	// we cannot map the local endpoint slice object back when we receive events. In this case
	// we use a specific prefix and handle it outside of the normal reconcile flow.
	if name, ok := parseMalformedEndpointSliceRequest(req.Name); ok {
		return r.reconcileMalformedEndpointSlice(ctx, types.NamespacedName{Name: name, Namespace: req.Namespace})
	}

	remoteEndpointSlice, exists := r.getRemoteEndpointSlice(req.NamespacedName)
	if !exists || remoteEndpointSlice.Labels[discoveryv1.LabelServiceName] == "" {
		return controllerruntime.Fail(r.cleanupLocalEndpointSlices(ctx, req.NamespacedName))
	}
	var namespace corev1.Namespace
	if err := r.Client.Get(ctx, types.NamespacedName{Name: remoteEndpointSlice.Namespace}, &namespace); err != nil {
		if apierrors.IsNotFound(err) {
			return controllerruntime.Fail(r.cleanupLocalEndpointSlices(ctx, req.NamespacedName))
		}
		return controllerruntime.Fail(err)
	}
	if !cmnamespace.IsGlobalNamespace(&namespace, r.namespaceConfig.GlobalNamespacesByDefault) {
		return controllerruntime.Fail(r.cleanupLocalEndpointSlices(ctx, req.NamespacedName))
	}

	var svc corev1.Service
	if err := r.Client.Get(ctx, types.NamespacedName{
		Name:      remoteEndpointSlice.Labels[discoveryv1.LabelServiceName],
		Namespace: remoteEndpointSlice.Namespace,
	}, &svc); err != nil {
		// If the service is not found, it probably isn't created yet or is getting
		// deleted so we can stop there and defer to a future reconciliation
		return controllerruntime.Fail(client.IgnoreNotFound(err))
	}
	if !shouldSyncEndpointSlice(&svc, remoteEndpointSlice.AddressType) {
		return controllerruntime.Fail(r.cleanupLocalEndpointSlices(ctx, req.NamespacedName))
	}

	desiredLocalEndpointSlice := r.newLocalEndpointSlice(remoteEndpointSlice, &svc)
	localEndpointSlice, err := r.getAndCleanupLocalEndpointSlices(
		ctx, req.NamespacedName, new(client.ObjectKeyFromObject(desiredLocalEndpointSlice)),
	)
	if err != nil {
		return controllerruntime.Fail(err)
	}

	if localEndpointSlice != nil && localEndpointSlice.AddressType != desiredLocalEndpointSlice.AddressType {
		if err := r.Client.Delete(ctx, localEndpointSlice, client.Preconditions{
			UID: &localEndpointSlice.UID, ResourceVersion: &localEndpointSlice.ResourceVersion,
		}); err != nil {
			return controllerruntime.Fail(client.IgnoreNotFound(err))
		}
		localEndpointSlice = nil
	}

	if localEndpointSlice == nil {
		err = r.Client.Create(ctx, desiredLocalEndpointSlice)
		if apierrors.IsForbidden(err) && apierrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
			r.logger.InfoContext(ctx, "Aborting reconciliation because namespace is being terminated")
			return controllerruntime.Success()
		}
	} else if localEndpointSlice.Annotations[remoteEndpointSliceAnnotation] != remoteEndpointSlice.Name ||
		!operator.EndpointSliceEqualsForMirroring(localEndpointSlice, desiredLocalEndpointSlice) {
		r.updateLocalEndpointSlice(localEndpointSlice, remoteEndpointSlice, &svc)
		err = r.Client.Update(ctx, localEndpointSlice)
	}

	return controllerruntime.Fail(err)
}

func (r *endpointSliceReconciler) reconcileMalformedEndpointSlice(
	ctx context.Context, key types.NamespacedName,
) (ctrl.Result, error) {
	var localEndpointSlice discoveryv1.EndpointSlice
	if err := r.Get(ctx, key, &localEndpointSlice); err != nil {
		return controllerruntime.Fail(client.IgnoreNotFound(err))
	}
	if localEndpointSlice.Labels[discoveryv1.LabelManagedBy] != utils.EndpointSliceMeshControllerName ||
		remoteEndpointSliceReconcileKeyFromLocalEndpointSlice(&localEndpointSlice) != nil {
		// This endpoint slice is no longer malformed
		return controllerruntime.Success()
	}
	r.logger.Warn(
		"This local EndpointSlice was tampered and cannot be traced back to its remote EndpointSlice and will be deleted",
		logfields.Request, key,
	)
	return controllerruntime.Fail(client.IgnoreNotFound(r.Client.Delete(ctx, &localEndpointSlice, client.Preconditions{
		UID: &localEndpointSlice.UID, ResourceVersion: &localEndpointSlice.ResourceVersion,
	})))
}

func (r *endpointSliceReconciler) updateLocalEndpointSlice(
	localEndpointSlice *discoveryv1.EndpointSlice,
	remoteEndpointSlice *endpointslicetypes.ClusterEndpointSlice, svc *corev1.Service,
) {
	controllerutil.SetControllerReference(svc, localEndpointSlice, r.Scheme())

	localEndpointSlice.Labels = maps.Clone(svc.Labels)
	if localEndpointSlice.Labels == nil {
		localEndpointSlice.Labels = map[string]string{}
	}
	localEndpointSlice.Labels[discoveryv1.LabelServiceName] = svc.Name
	localEndpointSlice.Labels[discoveryv1.LabelManagedBy] = utils.EndpointSliceMeshControllerName
	localEndpointSlice.Labels[mcsapiv1beta1.LabelSourceCluster] = remoteEndpointSlice.Cluster

	if localEndpointSlice.Annotations == nil {
		localEndpointSlice.Annotations = map[string]string{}
	}
	localEndpointSlice.Annotations[remoteEndpointSliceAnnotation] = remoteEndpointSlice.Name

	localEndpointSlice.AddressType = discoveryv1.AddressType(remoteEndpointSlice.AddressType)

	// Beware those are shallow copies, content of the struct should not be modified
	localEndpointSlice.Endpoints = convertEndpoints(remoteEndpointSlice.Endpoints)
	localEndpointSlice.Ports = convertPorts(remoteEndpointSlice.Ports)
}

func (r *endpointSliceReconciler) newLocalEndpointSlice(
	remoteEndpointSlice *endpointslicetypes.ClusterEndpointSlice, svc *corev1.Service,
) *discoveryv1.EndpointSlice {
	localEndpointSliceKey := localEndpointSliceKey(remoteEndpointSlice)
	localEndpointSlice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
		Name: localEndpointSliceKey.Name, Namespace: localEndpointSliceKey.Namespace,
	}}

	r.updateLocalEndpointSlice(localEndpointSlice, remoteEndpointSlice, svc)
	return localEndpointSlice
}

func convertEndpoints(in []slimdiscoveryv1.Endpoint) []discoveryv1.Endpoint {
	out := make([]discoveryv1.Endpoint, 0, len(in))
	for _, remoteEndpoint := range in {
		endpoint := discoveryv1.Endpoint{
			Addresses: remoteEndpoint.Addresses,
			Conditions: discoveryv1.EndpointConditions{
				Ready:       remoteEndpoint.Conditions.Ready,
				Serving:     remoteEndpoint.Conditions.Serving,
				Terminating: remoteEndpoint.Conditions.Terminating,
			},
			Hostname:           remoteEndpoint.Hostname,
			DeprecatedTopology: remoteEndpoint.DeprecatedTopology,
			NodeName:           remoteEndpoint.NodeName,
			Zone:               remoteEndpoint.Zone,
		}
		if remoteEndpoint.Hints != nil {
			endpoint.Hints = &discoveryv1.EndpointHints{
				ForZones: make([]discoveryv1.ForZone, 0, len(remoteEndpoint.Hints.ForZones)),
			}
			for _, forZone := range remoteEndpoint.Hints.ForZones {
				endpoint.Hints.ForZones = append(
					endpoint.Hints.ForZones, discoveryv1.ForZone{Name: forZone.Name},
				)
			}
		}
		out = append(out, endpoint)
	}
	return out
}

func convertPorts(in []slimdiscoveryv1.EndpointPort) []discoveryv1.EndpointPort {
	out := make([]discoveryv1.EndpointPort, 0, len(in))
	for _, remotePort := range in {
		port := discoveryv1.EndpointPort{Name: remotePort.Name, Port: remotePort.Port}
		if remotePort.Protocol != nil {
			port.Protocol = new(corev1.Protocol(*remotePort.Protocol))
		}
		out = append(out, port)
	}
	return out
}

func (r *endpointSliceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&discoveryv1.EndpointSlice{},
		localEndpointSliceByRemoteKeyIndex,
		localEndpointSliceByRemoteKeyIndexFunc,
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("ClusterEndpointSliceSync").
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []ctrl.Request {
			items := r.cache.MustByIndex(ServiceIndex, client.ObjectKeyFromObject(obj).String())
			requests := make([]ctrl.Request, 0, len(items))
			for _, remoteEndpointSlice := range items {
				requests = append(requests, ctrl.Request{NamespacedName: remoteEndpointSliceReconcileKey(remoteEndpointSlice)})
			}
			return requests
		})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []ctrl.Request {
			items := r.cache.MustByIndex(cache.NamespaceIndex, obj.GetName())
			requests := make([]ctrl.Request, 0, len(items))
			for _, remoteEndpointSlice := range items {
				requests = append(requests, ctrl.Request{NamespacedName: remoteEndpointSliceReconcileKey(remoteEndpointSlice)})
			}
			return requests
		})).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []ctrl.Request {
			localEndpointSlice := obj.(*discoveryv1.EndpointSlice)
			if localEndpointSlice.Labels[discoveryv1.LabelManagedBy] != utils.EndpointSliceMeshControllerName {
				return nil
			}
			remoteKey := remoteEndpointSliceReconcileKeyFromLocalEndpointSlice(localEndpointSlice)
			if remoteKey == nil {
				return []ctrl.Request{{NamespacedName: types.NamespacedName{
					Name:      malformedEndpointSliceRequest(localEndpointSlice.Name),
					Namespace: localEndpointSlice.Namespace,
				}}}
			}
			return []ctrl.Request{{NamespacedName: *remoteKey}}
		})).
		WatchesRawSource(r.remoteEndpointSliceSource).
		Complete(r)
}
