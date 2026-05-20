// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	"github.com/cilium/cilium/operator/pkg/gateway-api/predicates"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	gwModel "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// endpointSliceReconciler keeps the Endpoints and resolved target port of
// operator-managed frontend EndpointSlices in sync with the referenced backend
// Service.
//
// Ownership split with the gatewayReconciler:
//   - gatewayReconciler owns slice identity (Ports name/protocol, labels,
//     annotations, OwnerReferences, stale-slice deletion) and seeds new slices
//     with empty Endpoints.
//   - endpointSliceReconciler owns the data-plane fields: Endpoints and the
//     resolved numeric value applied uniformly across every Ports[].Port entry.
//
// Splitting writes between the two reconcilers prevents update loops.
type endpointSliceReconciler struct {
	client.Client
	logger *slog.Logger
}

func newEndpointSliceReconciler(mgr ctrl.Manager, logger *slog.Logger) *endpointSliceReconciler {
	return &endpointSliceReconciler{
		Client: mgr.GetClient(),
		logger: logger.With(logfields.Controller, endpointSlice),
	}
}

// SetupWithManager wires the reconciler into the controller-runtime manager.
func (r *endpointSliceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(endpointSlice).
		For(&discoveryv1.EndpointSlice{},
			builder.WithPredicates(predicates.ManagedFrontendEndpointSlice())).
		Watches(&discoveryv1.EndpointSlice{},
			watchhandlers.EnqueueFrontendsForBackendEndpointSlice(r.Client, r.logger),
			builder.WithPredicates(predicates.NonManagedEndpointSlice())).
		Watches(&corev1.Service{},
			watchhandlers.EnqueueFrontendsForBackendService(r.Client, r.logger)).
		Complete(r)
}

// Reconcile populates the endpoints and target port of a managed frontend
// EndpointSlice from the backend Service and its own EndpointSlices.
func (r *endpointSliceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(logfields.Resource, req.NamespacedName)

	frontend := &discoveryv1.EndpointSlice{}
	if err := r.Client.Get(ctx, req.NamespacedName, frontend); err != nil {
		if k8serrors.IsNotFound(err) {
			return controllerruntime.Success()
		}
		return controllerruntime.Fail(err)
	}
	if !predicates.IsManagedFrontendEndpointSlice(frontend) {
		return controllerruntime.Success()
	}

	backendRef := frontend.Annotations[gwModel.BackendServiceAnnotation]
	if backendRef == "" {
		scopedLog.WarnContext(ctx, "Managed EndpointSlice missing backend-service annotation, skipping")
		return controllerruntime.Success()
	}
	backendNs, backendName, ok := strings.Cut(backendRef, "/")
	if !ok || backendNs == "" || backendName == "" {
		scopedLog.WarnContext(ctx, "Invalid backend-service annotation",
			"annotation", backendRef)
		return controllerruntime.Success()
	}

	servicePort, err := strconv.ParseUint(frontend.Annotations[gwModel.BackendPortAnnotation], 10, 16)
	if err != nil {
		return controllerruntime.Fail(fmt.Errorf("invalid backend-port annotation %q: %w",
			frontend.Annotations[gwModel.BackendPortAnnotation], err))
	}

	backendSvc := &corev1.Service{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: backendNs, Name: backendName}, backendSvc); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.DebugContext(ctx, "Backend Service not found, clearing endpoints",
				"backend", backendRef)
			return r.patchFrontend(ctx, frontend, nil, nil)
		}
		return controllerruntime.Fail(fmt.Errorf("failed to get backend Service %s: %w", backendRef, err))
	}

	matchedPort := matchServicePort(backendSvc.Spec.Ports, uint16(servicePort), portProtocol(frontend.Ports))
	if matchedPort == nil {
		scopedLog.WarnContext(ctx, "Backend Service does not expose requested port; clearing endpoints",
			"backend", backendRef,
			"port", servicePort,
		)
		return r.patchFrontend(ctx, frontend, nil, nil)
	}

	endpointPort, addresses, err := r.resolveBackendEndpoints(ctx, backendNs, backendName, frontend.AddressType, *matchedPort)
	if err != nil {
		return controllerruntime.Fail(err)
	}
	if endpointPort == nil {
		// Backend Service exists but no matching EndpointSlice port resolved yet.
		// Keep frontend port name/proto stable; clear endpoints until backend appears.
		return r.patchFrontend(ctx, frontend, nil, nil)
	}

	return r.patchFrontend(ctx, frontend, endpointPort, addresses)
}

func (r *endpointSliceReconciler) patchFrontend(ctx context.Context, frontend *discoveryv1.EndpointSlice, port *int32, endpoints []discoveryv1.Endpoint) (ctrl.Result, error) {
	updated := &discoveryv1.EndpointSlice{}
	updated.Name = frontend.Name
	updated.Namespace = frontend.Namespace

	_, err := controllerutil.CreateOrPatch(ctx, r.Client, updated, func() error {
		updated.Endpoints = endpoints
		if port != nil {
			// All EndpointPort entries in a managed frontend slice share the
			// same backend Service port (see toL4EndpointSlices dedup), so they
			// all resolve to the same target pod port. Apply the resolved port
			// uniformly so per-listener name lookups in the LB reflector see
			// matching numeric ports.
			for i := range updated.Ports {
				updated.Ports[i].Port = port
			}
		}
		return nil
	})
	if err != nil {
		return controllerruntime.Fail(fmt.Errorf("failed to patch frontend EndpointSlice: %w", err))
	}
	return controllerruntime.Success()
}

// matchServicePort returns the ServicePort matching the requested port number
// and protocol, or nil when not found.
func matchServicePort(ports []corev1.ServicePort, want uint16, proto corev1.Protocol) *corev1.ServicePort {
	for i := range ports {
		p := ports[i]
		if uint16(p.Port) != want {
			continue
		}
		if p.Protocol != "" && p.Protocol != proto {
			continue
		}
		return &p
	}
	return nil
}

// resolveBackendEndpoints returns the resolved target port and endpoint addresses
// for the given backend Service's ServicePort. The target port is determined by
// matching backend EndpointSlice ports by name (preferred) or by port number.
func (r *endpointSliceReconciler) resolveBackendEndpoints(ctx context.Context, ns, svcName string, family discoveryv1.AddressType, svcPort corev1.ServicePort) (*int32, []discoveryv1.Endpoint, error) {
	list := &discoveryv1.EndpointSliceList{}
	if err := r.Client.List(ctx, list,
		client.InNamespace(ns),
		client.MatchingLabels{gwModel.EndpointSliceServiceNameLabel: svcName},
	); err != nil {
		return nil, nil, fmt.Errorf("failed to list backend EndpointSlices for %s/%s: %w", ns, svcName, err)
	}

	var resolvedPort *int32
	addrSeen := make(map[string]struct{})
	var endpoints []discoveryv1.Endpoint
	for i := range list.Items {
		be := list.Items[i]
		if be.AddressType != family {
			continue
		}
		if predicates.IsManagedFrontendEndpointSlice(&be) {
			continue
		}
		bePort := matchEndpointSlicePort(be.Ports, svcPort)
		if bePort == nil {
			continue
		}
		if resolvedPort == nil {
			resolvedPort = ptr.To(*bePort)
		}
		for _, ep := range be.Endpoints {
			if len(ep.Addresses) == 0 {
				continue
			}
			key := strings.Join(ep.Addresses, ",")
			if _, ok := addrSeen[key]; ok {
				continue
			}
			addrSeen[key] = struct{}{}
			endpoints = append(endpoints, discoveryv1.Endpoint{
				Addresses:  append([]string(nil), ep.Addresses...),
				Conditions: ep.Conditions,
				Hostname:   ep.Hostname,
				TargetRef:  ep.TargetRef,
				NodeName:   ep.NodeName,
				Zone:       ep.Zone,
				Hints:      ep.Hints,
			})
		}
	}

	sort.SliceStable(endpoints, func(i, j int) bool {
		return strings.Join(endpoints[i].Addresses, ",") < strings.Join(endpoints[j].Addresses, ",")
	})
	return resolvedPort, endpoints, nil
}

// matchEndpointSlicePort returns the EPS port number whose name matches the
// ServicePort name, or whose numeric port matches the ServicePort targetPort.
func matchEndpointSlicePort(ports []discoveryv1.EndpointPort, svcPort corev1.ServicePort) *int32 {
	wantProto := svcPort.Protocol
	wantName := svcPort.Name
	wantNumeric := int32(0)
	if svcPort.TargetPort.Type == 0 { // intstr.Int
		wantNumeric = svcPort.TargetPort.IntVal
	}

	for _, p := range ports {
		if p.Port == nil {
			continue
		}
		if p.Protocol != nil && wantProto != "" && *p.Protocol != wantProto {
			continue
		}
		// Prefer name match.
		if p.Name != nil && wantName != "" && *p.Name == wantName {
			return p.Port
		}
		// Fall back to numeric targetPort match.
		if wantNumeric != 0 && *p.Port == wantNumeric {
			return p.Port
		}
	}
	// If the Service has only one port and no name match was found, use the first EPS port.
	if len(ports) == 1 && ports[0].Port != nil {
		return ports[0].Port
	}
	return nil
}

func portProtocol(ports []discoveryv1.EndpointPort) corev1.Protocol {
	for _, p := range ports {
		if p.Protocol != nil {
			return *p.Protocol
		}
	}
	return corev1.ProtocolTCP
}
