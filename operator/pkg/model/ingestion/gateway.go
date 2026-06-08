// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"cmp"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/annotation"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	allHosts = "*"
)

type ListenerWithContext struct {
	gatewayv1.Listener
	// Source is where this listener appears: Gateway or ListenerSet
	Source model.FullyQualifiedResource

	// AllowedNamespaces is the set of namespaces allowed for Route attachment
	AllowedNamespaces map[string]struct{}
}

func parentRefMatchesSource(parent gatewayv1.ParentReference, source model.FullyQualifiedResource, routeNamespace string) bool {
	parentKind := "Gateway"
	if parent.Kind != nil {
		parentKind = string(*parent.Kind)
	}
	if parentKind != source.Kind {
		return false
	}
	if string(parent.Name) != source.Name {
		return false
	}
	parentNS := routeNamespace
	if parent.Namespace != nil {
		parentNS = string(*parent.Namespace)
	}
	return parentNS == source.Namespace
}

func (l *ListenerWithContext) routeAllowedByParent(parentRefs []gatewayv1.ParentReference, routeNamespace string) bool {
	if l.AllowedNamespaces != nil {
		if _, ok := l.AllowedNamespaces[routeNamespace]; !ok {
			return false
		}
	}

	for _, parent := range parentRefs {
		if parentRefMatchesSource(parent, l.Source, routeNamespace) {
			if parent.SectionName != nil && string(*parent.SectionName) != string(l.Listener.Name) {
				// We didn't find a listener yet that matches the section name
				continue
			}
			return true
		}
	}

	return false
}

func (l *ListenerWithContext) FilterHTTPRoutes(routes []gatewayv1.HTTPRoute) []gatewayv1.HTTPRoute {
	var filtered []gatewayv1.HTTPRoute
	for _, r := range routes {
		if l.routeAllowedByParent(r.Spec.ParentRefs, r.GetNamespace()) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (l *ListenerWithContext) FilterGRPCRoutes(routes []gatewayv1.GRPCRoute) []gatewayv1.GRPCRoute {
	var filtered []gatewayv1.GRPCRoute
	for _, r := range routes {
		if l.routeAllowedByParent(r.Spec.ParentRefs, r.GetNamespace()) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (l *ListenerWithContext) FilterTLSRoutes(routes []gatewayv1.TLSRoute) []gatewayv1.TLSRoute {
	var filtered []gatewayv1.TLSRoute
	for _, r := range routes {
		if l.routeAllowedByParent(r.Spec.ParentRefs, r.GetNamespace()) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (l *ListenerWithContext) FilterTCPRoutes(routes []gatewayv1alpha2.TCPRoute) []gatewayv1alpha2.TCPRoute {
	var filtered []gatewayv1alpha2.TCPRoute
	for _, r := range routes {
		if l.routeAllowedByParent(r.Spec.ParentRefs, r.GetNamespace()) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (l *ListenerWithContext) FilterUDPRoutes(routes []gatewayv1alpha2.UDPRoute) []gatewayv1alpha2.UDPRoute {
	var filtered []gatewayv1alpha2.UDPRoute
	for _, r := range routes {
		if l.routeAllowedByParent(r.Spec.ParentRefs, r.GetNamespace()) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// Input is the input for GatewayAPI.
type Input struct {
	GatewayClass       gatewayv1.GatewayClass
	GatewayClassConfig *v2alpha1.CiliumGatewayClassConfig

	Gateway             gatewayv1.Gateway
	HTTPRoutes          []gatewayv1.HTTPRoute
	TLSRoutes           []gatewayv1.TLSRoute
	GRPCRoutes          []gatewayv1.GRPCRoute
	TCPRoutes           []gatewayv1alpha2.TCPRoute
	UDPRoutes           []gatewayv1alpha2.UDPRoute
	ReferenceGrants     []gatewayv1.ReferenceGrant
	Namespaces          []corev1.Namespace
	Services            []corev1.Service
	ServiceImports      []mcsapiv1beta1.ServiceImport
	BackendTLSPolicyMap helpers.BackendTLSPolicyServiceMap
	MergedListeners     []ListenerWithContext

	EnableExtensionRefFilters bool
	CiliumEnvoyExtProcFilters []v2alpha1.CiliumEnvoyExtProcFilter
}

// GatewayAPI translates Gateway API resources into a model.
func GatewayAPI(log *slog.Logger, input Input) *model.Model {
	var resHTTP []model.HTTPListener
	var resTLSPassthrough []model.TLSPassthroughListener
	var resL4 []model.L4Listener

	labels := make(map[string]string)
	annotations := make(map[string]string)
	if input.Gateway.Spec.Infrastructure != nil {
		labels = toMapString(input.Gateway.Spec.Infrastructure.Labels)
		annotations = toMapString(input.Gateway.Spec.Infrastructure.Annotations)
	}
	ips := make([]string, 0, len(input.Gateway.Spec.Addresses))
	for _, address := range input.Gateway.Spec.Addresses {
		if address.Type == nil || *address.Type == gatewayv1.IPAddressType {
			ips = append(ips, address.Value)
		}
	}
	// If already use the LBIPAMIPKeyAlias to specify the IP, don't overwrite it.
	// At a future date this annotation will be removed if no spec.addresses are set.
	if len(ips) != 0 && annotations[annotation.LBIPAMIPKeyAlias] == "" {
		annotations[annotation.LBIPAMIPKeyAlias] = strings.Join(ips, ",")
	}
	var infra *model.Infrastructure
	if len(labels) != 0 || len(annotations) != 0 {
		infra = &model.Infrastructure{
			Labels:      labels,
			Annotations: annotations,
		}
	}

	namespaceLabels := helpers.NewNamespaceLabelIndex(input.Namespaces)
	listeners := input.MergedListeners
	// When MergedListeners is not provided, build it from the direct
	// Gateway-listeners
	if listeners == nil {
		gwSource := model.FullyQualifiedResource{
			Name:      input.Gateway.GetName(),
			Namespace: input.Gateway.GetNamespace(),
			Group:     gatewayv1.SchemeGroupVersion.Group,
			Version:   gatewayv1.SchemeGroupVersion.Version,
			Kind:      "Gateway",
			UID:       string(input.Gateway.GetUID()),
		}
		for _, l := range input.Gateway.Spec.Listeners {
			listeners = append(listeners, ListenerWithContext{
				Listener: l,
				Source:   gwSource,
			})
		}
	}

	// Find all the listener host names, so that we can match them with the routes
	// Gateway API spec guarantees that the hostnames are unique across all listeners
	listenerHostnamesByProtocol := make(map[gatewayv1.ProtocolType][]string)
	for _, l := range listeners {
		if l.Hostname != nil {
			_, ok := listenerHostnamesByProtocol[l.Protocol]
			if !ok {
				listenerHostnamesByProtocol[l.Protocol] = []string{}
			}
			listenerHostnamesByProtocol[l.Protocol] = append(listenerHostnamesByProtocol[l.Protocol], toHostname(l.Hostname))
		}
	}

	for _, l := range listeners {
		switch l.Protocol {
		case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
			filteredHTTPRoutes := l.FilterHTTPRoutes(input.HTTPRoutes)
			filteredGRPCRoutes := l.FilterGRPCRoutes(input.GRPCRoutes)

			var httpRoutes []model.HTTPRoute

			// (ajs) Note well, we are using the existence of AllowedNamespace
			// as a hint that this listener has already performed filtering for
			// routes based on AllowedNamespaces. We need to refactor this type
			// of assumption to not apply only to ListenerSets, and be a true
			// invariant expected by this code path. That is, move all such
			// validation out of the ingestion codepath and into a combined
			// validate-and-record status phase of the reconcile pipeline.
			namespacesPreFiltered := l.AllowedNamespaces != nil

			httpRoutes = append(httpRoutes, toHTTPRoutes(log, l.Listener, l.Source.Namespace, namespaceLabels, namespacesPreFiltered, listenerHostnamesByProtocol, filteredHTTPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants, input.BackendTLSPolicyMap, input.EnableExtensionRefFilters, input.CiliumEnvoyExtProcFilters)...)
			httpRoutes = append(httpRoutes, toGRPCRoutes(log, l.Listener, l.Source.Namespace, namespaceLabels, namespacesPreFiltered, listenerHostnamesByProtocol, filteredGRPCRoutes, input.Services, input.ServiceImports, input.ReferenceGrants, input.EnableExtensionRefFilters, input.CiliumEnvoyExtProcFilters)...)
			resHTTP = append(resHTTP, model.HTTPListener{
				Name:           string(l.Name),
				Sources:        []model.FullyQualifiedResource{l.Source},
				Port:           uint32(l.Port),
				Hostname:       toHostname(l.Hostname),
				TLS:            toTLS(l.TLS, input.ReferenceGrants, l.Source.Namespace, schema.GroupVersionKind{Group: l.Source.Group, Version: l.Source.Version, Kind: l.Source.Kind}),
				Routes:         httpRoutes,
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})

			if l.Protocol == gatewayv1.TLSProtocolType {
				resTLSPassthrough = append(resTLSPassthrough, model.TLSPassthroughListener{
					Name:           string(l.Name),
					Sources:        []model.FullyQualifiedResource{l.Source},
					Port:           uint32(l.Port),
					Hostname:       toHostname(l.Hostname),
					Routes:         toTLSRoutes(l.Listener, l.Source.Namespace, namespaceLabels, namespacesPreFiltered, listenerHostnamesByProtocol, l.FilterTLSRoutes(input.TLSRoutes), input.Services, input.ServiceImports, input.ReferenceGrants),
					Infrastructure: infra,
					Service:        toServiceModel(input.GatewayClassConfig),
				})
			}

		case gatewayv1.TCPProtocolType:
			namespacesPreFiltered := l.AllowedNamespaces != nil
			resL4 = append(resL4, model.L4Listener{
				Name:           string(l.Name),
				Sources:        []model.FullyQualifiedResource{l.Source},
				Port:           uint32(l.Port),
				Protocol:       model.L4ProtocolTCP,
				Routes:         toTCPRoutes(l.Listener, l.Source.Namespace, namespaceLabels, namespacesPreFiltered, l.FilterTCPRoutes(input.TCPRoutes), input.Services, input.ServiceImports, input.ReferenceGrants),
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})

		case gatewayv1.UDPProtocolType:
			namespacesPreFiltered := l.AllowedNamespaces != nil
			resL4 = append(resL4, model.L4Listener{
				Name:           string(l.Name),
				Sources:        []model.FullyQualifiedResource{l.Source},
				Port:           uint32(l.Port),
				Protocol:       model.L4ProtocolUDP,
				Routes:         toUDPRoutes(l.Listener, l.Source.Namespace, namespaceLabels, namespacesPreFiltered, l.FilterUDPRoutes(input.UDPRoutes), input.Services, input.ServiceImports, input.ReferenceGrants),
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})
		}
	}

	m := &model.Model{
		HTTP:           resHTTP,
		TLSPassthrough: resTLSPassthrough,
		L4:             resL4,
	}

	if input.GatewayClassConfig != nil {
		m.HTTPOptions = &model.HTTPOptions{
			GRPCWebTranslation: &model.GRPCWebTranslationConfig{
				Enabled: input.GatewayClassConfig.GRPCWebTranslationEnabled(),
			},
		}
	}

	return m
}

func getBackendServiceName(namespace string, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, backendObjectReference gatewayv1.BackendObjectReference) (string, error) {
	svcName := string(backendObjectReference.Name)

	switch {
	case helpers.IsService(backendObjectReference):
		// We don't have to do anything here
	case helpers.IsServiceImport(backendObjectReference):
		svcImport := getServiceImport(string(backendObjectReference.Name), namespace, serviceImports)
		if svcImport == nil {
			return "", fmt.Errorf("Service Import %s/%s does not exists", string(backendObjectReference.Name), namespace)
		}

		var err error
		svcName, err = helpers.GetServiceName(svcImport)
		if err != nil {
			return "", err
		}

	default:
		return "", fmt.Errorf("Unsupported backend kind %s", *backendObjectReference.Kind)
	}

	svc := getServiceSpec(svcName, namespace, services)
	if svc == nil {
		return "", fmt.Errorf("Service %s/%s does not exist", svcName, namespace)
	}
	return svcName, nil
}

func toHTTPRoutes(log *slog.Logger,
	listener gatewayv1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	namespacesPreFiltered bool,
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.HTTPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	btlspMap helpers.BackendTLSPolicyServiceMap,
	enableExtensionRefFilters bool,
	extProcFilters []v2alpha1.CiliumEnvoyExtProcFilter,
) []model.HTTPRoute {
	var httpRoutes []model.HTTPRoute
	for _, r := range input {
		listenerIsParent := false
		// Check parents to see if r can attach to them.
		// We have to consider _both_ SectionName and Port
		for _, parent := range r.Spec.ParentRefs {
			// First, if both SectionName and Port are unset, attach
			if parent.SectionName == nil && parent.Port == nil {
				listenerIsParent = true
				break
			}

			// Then, if SectionName is set, check combinations with Port.
			if parent.SectionName != nil {
				if *parent.SectionName != listener.Name {
					// If SectionName is set but not equal, no other settings
					// matter, so check the next parent.
					continue
				}

				if parent.Port != nil && *parent.Port != listener.Port {
					// If SectionName is set and equal, but Port is set and _unequal_,
					continue
				}

				listenerIsParent = true
				break
			}

			if parent.Port != nil {
				if *parent.Port != listener.Port {
					// If Port is set but not equal, no other settings
					// matter, check the next parent.
					continue
				}

				listenerIsParent = true
				break
			}

		}

		if !listenerIsParent {
			continue
		}

		if !namespacesPreFiltered && !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allProtocolHostnames)
		// No matching host, skip this route
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}

		httpRoutes = append(httpRoutes, extractRoutes(log, int32(listener.Port), computedHost, r, services, serviceImports, grants, btlspMap, enableExtensionRefFilters, extProcFilters)...)

	}
	return httpRoutes
}

func extractRoutes(logger *slog.Logger,
	listenerPort int32,
	hostnames []string,
	hr gatewayv1.HTTPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	btlspMap helpers.BackendTLSPolicyServiceMap,
	enableExtensionRefFilters bool,
	extProcFilters []v2alpha1.CiliumEnvoyExtProcFilter,
) []model.HTTPRoute {
	var httpRoutes []model.HTTPRoute
	for _, rule := range hr.Spec.Rules {
		var backendHTTPFilters []*model.BackendHTTPFilter
		bes := make([]model.Backend, 0, len(rule.BackendRefs))
		for _, be := range rule.BackendRefs {
			if !helpers.IsBackendReferenceAllowed(hr.GetNamespace(), be.BackendRef, gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"), grants) {
				continue
			}
			svcName, err := getBackendServiceName(helpers.NamespaceDerefOr(be.Namespace, hr.Namespace), services, serviceImports, be.BackendObjectReference)
			if err != nil {
				continue
			}
			if svcName != string(be.Name) {
				be = *be.DeepCopy()
				be.BackendRef.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
					Name:      gatewayv1beta1.ObjectName(svcName),
					Port:      be.Port,
					Namespace: be.Namespace,
				}
			}
			if be.BackendRef.Port == nil {
				// must have port for Service reference
				continue
			}
			svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, hr.Namespace), services)
			if svc != nil {
				toAppend := backendToModelBackend(*svc, be.BackendRef, hr.Namespace)
				var include bool
				toAppend, include = addBackendTLSDetails(logger, toAppend, svc, btlspMap)
				if !include {
					continue
				}
				bes = append(bes, toAppend)
				for _, f := range be.Filters {
					switch f.Type {
					case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
						backendHTTPFilters = append(backendHTTPFilters, &model.BackendHTTPFilter{
							Name: fmt.Sprintf("%s:%s:%d", helpers.NamespaceDerefOr(be.Namespace, hr.Namespace), be.Name, uint32(*be.Port)),
							RequestHeaderFilter: &model.HTTPHeaderFilter{
								HeadersToAdd:    toHTTPHeaders(f.RequestHeaderModifier.Add),
								HeadersToSet:    toHTTPHeaders(f.RequestHeaderModifier.Set),
								HeadersToRemove: f.RequestHeaderModifier.Remove,
							},
						})
					case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
						backendHTTPFilters = append(backendHTTPFilters, &model.BackendHTTPFilter{
							Name: fmt.Sprintf("%s:%s:%d", helpers.NamespaceDerefOr(be.Namespace, hr.Namespace), be.Name, uint32(*be.Port)),
							ResponseHeaderModifier: &model.HTTPHeaderFilter{
								HeadersToAdd:    toHTTPHeaders(f.ResponseHeaderModifier.Add),
								HeadersToSet:    toHTTPHeaders(f.ResponseHeaderModifier.Set),
								HeadersToRemove: f.ResponseHeaderModifier.Remove,
							},
						})
					}
				}
			}
		}

		var dr *model.DirectResponse
		if len(bes) == 0 {
			dr = &model.DirectResponse{
				StatusCode: 500,
			}
		}

		var requestHeaderFilter *model.HTTPHeaderFilter
		var responseHeaderFilter *model.HTTPHeaderFilter
		var requestRedirectFilter *model.HTTPRequestRedirectFilter
		var rewriteFilter *model.HTTPURLRewriteFilter
		var requestMirrors []*model.HTTPRequestMirror
		var externalAuth *model.HTTPExternalAuthFilter
		var requestCORS *model.HTTPCORSFilter
		var extensionRefFilters []model.ExtensionRefFilter

	filterLoop:
		for _, f := range rule.Filters {
			switch f.Type {
			case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
				requestHeaderFilter = &model.HTTPHeaderFilter{
					HeadersToAdd:    toHTTPHeaders(f.RequestHeaderModifier.Add),
					HeadersToSet:    toHTTPHeaders(f.RequestHeaderModifier.Set),
					HeadersToRemove: f.RequestHeaderModifier.Remove,
				}
			case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
				responseHeaderFilter = &model.HTTPHeaderFilter{
					HeadersToAdd:    toHTTPHeaders(f.ResponseHeaderModifier.Add),
					HeadersToSet:    toHTTPHeaders(f.ResponseHeaderModifier.Set),
					HeadersToRemove: f.ResponseHeaderModifier.Remove,
				}
			case gatewayv1.HTTPRouteFilterRequestRedirect:
				requestRedirectFilter = toHTTPRequestRedirectFilter(listenerPort, f.RequestRedirect)
			case gatewayv1.HTTPRouteFilterURLRewrite:
				rewriteFilter = toHTTPRewriteFilter(f.URLRewrite)
			case gatewayv1.HTTPRouteFilterRequestMirror:
				if f.RequestMirror == nil {
					continue
				}

				if !helpers.IsBackendReferenceAllowed(hr.GetNamespace(),
					gatewayv1.BackendRef{BackendObjectReference: f.RequestMirror.BackendRef},
					gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"), grants) {
					continue
				}

				svc := getServiceSpec(string(f.RequestMirror.BackendRef.Name), helpers.NamespaceDerefOr(f.RequestMirror.BackendRef.Namespace, hr.Namespace), services)
				if svc != nil {
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(*svc, f.RequestMirror, hr.Namespace))
				}
			case gatewayv1.HTTPRouteFilterExternalAuth:
				if f.ExternalAuth != nil {
					beRef := gatewayv1.BackendRef{BackendObjectReference: f.ExternalAuth.BackendRef}
					if !helpers.IsBackendReferenceAllowed(hr.GetNamespace(), beRef, gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"), grants) {
						break
					}
				}
				externalAuth = toHTTPExternalAuthFilter(logger, f.ExternalAuth, hr.Namespace, services, serviceImports, btlspMap)
			case gatewayv1.HTTPRouteFilterCORS:
				ac := false
				if f.CORS.AllowCredentials != nil {
					ac = *f.CORS.AllowCredentials
				}
				requestCORS = &model.HTTPCORSFilter{
					AllowOrigins:     toStringSlice(f.CORS.AllowOrigins),
					AllowCredentials: ac,
					AllowMethods:     toStringSlice(f.CORS.AllowMethods),
					AllowHeaders:     toStringSlice(f.CORS.AllowHeaders),
					ExposeHeaders:    toStringSlice(f.CORS.ExposeHeaders),
					// CRD defaults the value to 5 and allows values of 1 or higher.
					// Local tests can bypass this, ensuring we always get a default.
					MaxAge: cmp.Or(f.CORS.MaxAge, int32(5)),
				}
			case gatewayv1.HTTPRouteFilterExtensionRef:
				if f.ExtensionRef != nil {
					extensionRefFilter, ok := resolveExtensionRef(
						logger,
						enableExtensionRefFilters,
						hr.Namespace,
						f.ExtensionRef,
						extProcFilters,
					)
					if ok {
						extensionRefFilters = append(extensionRefFilters, *extensionRefFilter)
					} else {
						logger.Debug("ExtensionRef resolution failed; route will return 500",
							logfields.K8sNamespace, hr.Namespace,
							logfields.Name, string(f.ExtensionRef.Name),
							logfields.Group, string(f.ExtensionRef.Group),
							logfields.Kind, string(f.ExtensionRef.Kind),
						)
						bes = nil
						extensionRefFilters = nil
						dr = &model.DirectResponse{StatusCode: 500}
						// Stop processing further filters: a route with dr=500 carries no
						// backends or ext_proc filters. extensionRefFilters is nil from
						// this point, which is the invariant expected by translation.
						break filterLoop
					}
				}
			}
		}

		if len(rule.Matches) == 0 {
			httpRoutes = append(httpRoutes, model.HTTPRoute{
				Hostnames:              hostnames,
				Backends:               bes,
				BackendHTTPFilters:     backendHTTPFilters,
				DirectResponse:         dr,
				RequestHeaderFilter:    requestHeaderFilter,
				ResponseHeaderModifier: responseHeaderFilter,
				RequestRedirect:        requestRedirectFilter,
				Rewrite:                rewriteFilter,
				RequestMirrors:         requestMirrors,
				ExternalAuth:           externalAuth,
				ExtensionRefFilters:    extensionRefFilters,
				Timeout:                toTimeout(rule.Timeouts),
				Retry:                  toHTTPRetry(rule.Retry),
				CORS:                   requestCORS,
			})
		}

		for _, match := range rule.Matches {
			httpRoutes = append(httpRoutes, model.HTTPRoute{
				Hostnames:              hostnames,
				PathMatch:              toPathMatch(match),
				HeadersMatch:           toHeaderMatch(match),
				QueryParamsMatch:       toQueryMatch(match),
				Method:                 (*string)(match.Method),
				Backends:               bes,
				BackendHTTPFilters:     backendHTTPFilters,
				DirectResponse:         dr,
				RequestHeaderFilter:    requestHeaderFilter,
				ResponseHeaderModifier: responseHeaderFilter,
				RequestRedirect:        requestRedirectFilter,
				Rewrite:                rewriteFilter,
				RequestMirrors:         requestMirrors,
				ExternalAuth:           externalAuth,
				ExtensionRefFilters:    extensionRefFilters,
				Timeout:                toTimeout(rule.Timeouts),
				Retry:                  toHTTPRetry(rule.Retry),
				CORS:                   requestCORS,
			})
		}
	}
	return httpRoutes
}

func addBackendTLSDetails(log *slog.Logger, be model.Backend, svc *corev1.Service, btlspMap helpers.BackendTLSPolicyServiceMap) (model.Backend, bool) {
	svcFullName := types.NamespacedName{Name: svc.GetName(), Namespace: svc.GetNamespace()}

	log = log.With(logfields.Service, svcFullName)
	log.Debug("Checking Backend TLS Details for service",
		logfields.Backend, be,
		logfields.Port, be.Port.Port)

	// Check for relevant BackendTLSPolicies
	if collection, ok := btlspMap[svcFullName]; ok {
		// A BackendTLSPolicy is relevant to this object.
		// Now, we check to see if the port matches.
		for _, port := range svc.Spec.Ports {
			if port.Port != int32(be.Port.Port) {
				continue
			}
			// Port matches, so now we need to check the sections that are valid.
			// There are two possibilities here:
			// * Specific section name, matches only that Service port.
			// * no specific section name, matches any Service port
			//
			// The more specific section name must beat the less specific, so we check for that first,
			// and in this case can blindly set the TLS settings correctly.
			//
			// When we are checking the no specific section name case, we need to allow for a more
			// specific section name already handling this backend, and so skip if the TLS is already updated.
			//
			// Finally, if the TLS has been changed, we're done, so return after checking all the valid
			// sections.
			for sectionName, btlsp := range collection.Valid {

				scopedLog := log.With(
					logfields.BackendTLSPolicyName, btlsp.Name,
					logfields.Port, port.Name,
					logfields.Section, sectionName,
				)

				scopedLog.Debug("Checking valid BTLSP on port")

				if port.Name == string(sectionName) {
					scopedLog.Debug("Got a match for valid BTLSP on specific port, adding")
					// We need to add the BackendTLSPolicy details into the backend, then eject
					be.TLS = &model.BackendTLSOrigination{
						SNI: string(btlsp.Spec.Validation.Hostname),
					}
					if len(btlsp.Spec.Validation.CACertificateRefs) > 0 {
						// Cilium only supports ConfigMap currently
						be.TLS.CACertRef = &model.FullyQualifiedResource{
							Group:     "",
							Kind:      "ConfigMap",
							Version:   "v1",
							Name:      string(btlsp.Spec.Validation.CACertificateRefs[0].Name),
							Namespace: btlsp.GetNamespace(),
						}
					}
				}

				if sectionName == "" {
					scopedLog.Debug("Got a match for valid BTLSP on all ports, adding")
					// If the TLS is already set, then a specific target reference has already claimed this port, and
					// we need to skip it.
					if be.TLS == nil {
						be.TLS = &model.BackendTLSOrigination{
							SNI: string(btlsp.Spec.Validation.Hostname),
						}
						if len(btlsp.Spec.Validation.CACertificateRefs) > 0 {
							// Cilium only supports ConfigMap currently
							be.TLS.CACertRef = &model.FullyQualifiedResource{
								Group:     "",
								Kind:      "ConfigMap",
								Version:   "v1",
								Name:      string(btlsp.Spec.Validation.CACertificateRefs[0].Name),
								Namespace: btlsp.GetNamespace(),
							}
						}
					}
				}

			}
			if be.TLS != nil {
				return be, true
			}

			// No valid BackendTLSPolicy matched this port. Check if an invalid policy
			// would have matched. If so, the backend must be excluded.
			for sectionName := range collection.Invalid {
				if port.Name == string(sectionName) || sectionName == "" {
					log.Info("Service has an invalid BackendTLSPolicy for this port, excluding backend",
						logfields.Section, sectionName)
					return be, false
				}
			}

		}
	}
	// There was no relevant BackendTLSPolicy, no changes.
	return be, true
}

func toTimeout(timeouts *gatewayv1.HTTPRouteTimeouts) model.Timeout {
	res := model.Timeout{}
	if timeouts == nil {
		return res
	}
	if timeouts.BackendRequest != nil {
		if duration, err := time.ParseDuration(string(*timeouts.BackendRequest)); err == nil {
			res.Backend = ptr.To(duration)
		}
	}
	if timeouts.Request != nil {
		if duration, err := time.ParseDuration(string(*timeouts.Request)); err == nil {
			res.Request = ptr.To(duration)
		}
	}
	return res
}

func toHTTPRetry(retry *gatewayv1.HTTPRouteRetry) *model.HTTPRetry {
	if retry == nil {
		return nil
	}

	codes := make([]uint32, 0, len(retry.Codes))
	for _, c := range retry.Codes {
		codes = append(codes, uint32(c))
	}

	res := &model.HTTPRetry{
		Codes:    codes,
		Attempts: retry.Attempts,
	}

	if retry.Backoff != nil {
		if duration, err := time.ParseDuration(string(*retry.Backoff)); err == nil {
			res.Backoff = ptr.To(duration)
		}
	}

	return res
}

func toGRPCRoutes(log *slog.Logger,
	listener gatewayv1beta1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	namespacesPreFiltered bool,
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.GRPCRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	enableExtensionRefFilters bool,
	extProcFilters []v2alpha1.CiliumEnvoyExtProcFilter,
) []model.HTTPRoute {
	var grpcRoutes []model.HTTPRoute
	for _, r := range input {
		isListener := false
		for _, parent := range r.Spec.ParentRefs {
			if parent.SectionName == nil || *parent.SectionName == listener.Name {
				isListener = true
				break
			}
		}
		if !isListener {
			continue
		}

		if !namespacesPreFiltered && !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allProtocolHostnames)
		// No matching host, skip this route
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}
		grpcRoutes = append(grpcRoutes, extractGRPCRoutes(log, computedHost, r, services, serviceImports, grants, enableExtensionRefFilters, extProcFilters)...)
	}
	return grpcRoutes
}

func extractGRPCRoutes(logger *slog.Logger, hostnames []string, grpcr gatewayv1.GRPCRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant, enableExtensionRefFilters bool, extProcFilters []v2alpha1.CiliumEnvoyExtProcFilter) []model.HTTPRoute {
	var grpcRoutes []model.HTTPRoute
	for _, rule := range grpcr.Spec.Rules {
		bes := make([]model.Backend, 0, len(rule.BackendRefs))
		for _, be := range rule.BackendRefs {
			if !helpers.IsBackendReferenceAllowed(grpcr.GetNamespace(), be.BackendRef, gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"), grants) {
				continue
			}
			svcName, err := getBackendServiceName(helpers.NamespaceDerefOr(be.Namespace, grpcr.Namespace), services, serviceImports, be.BackendObjectReference)
			if err != nil {
				continue
			}
			if svcName != string(be.Name) {
				be = *be.DeepCopy()
				be.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
					Name:      gatewayv1beta1.ObjectName(svcName),
					Port:      be.Port,
					Namespace: be.Namespace,
				}
			}
			if be.BackendRef.Port == nil {
				// must have port for Service reference
				continue
			}
			svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, grpcr.Namespace), services)
			if svc != nil {
				bes = append(bes, backendToModelBackend(*svc, be.BackendRef, grpcr.Namespace))
			}
		}

		var dr *model.DirectResponse
		if len(bes) == 0 {
			dr = &model.DirectResponse{
				StatusCode: 500,
			}
		}

		var requestHeaderFilter *model.HTTPHeaderFilter
		var responseHeaderFilter *model.HTTPHeaderFilter
		var requestMirrors []*model.HTTPRequestMirror
		var extensionRefFilters []model.ExtensionRefFilter

	filterLoop:
		for _, f := range rule.Filters {
			switch f.Type {
			case gatewayv1.GRPCRouteFilterRequestHeaderModifier:
				requestHeaderFilter = &model.HTTPHeaderFilter{
					HeadersToAdd:    toHTTPHeaders(f.RequestHeaderModifier.Add),
					HeadersToSet:    toHTTPHeaders(f.RequestHeaderModifier.Set),
					HeadersToRemove: f.RequestHeaderModifier.Remove,
				}
			case gatewayv1.GRPCRouteFilterResponseHeaderModifier:
				responseHeaderFilter = &model.HTTPHeaderFilter{
					HeadersToAdd:    toHTTPHeaders(f.ResponseHeaderModifier.Add),
					HeadersToSet:    toHTTPHeaders(f.ResponseHeaderModifier.Set),
					HeadersToRemove: f.ResponseHeaderModifier.Remove,
				}
			case gatewayv1.GRPCRouteFilterRequestMirror:
				if f.RequestMirror == nil {
					continue
				}

				if !helpers.IsBackendReferenceAllowed(grpcr.GetNamespace(),
					gatewayv1.BackendRef{BackendObjectReference: f.RequestMirror.BackendRef},
					gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"), grants) {
					continue
				}

				svc := getServiceSpec(string(f.RequestMirror.BackendRef.Name), helpers.NamespaceDerefOr(f.RequestMirror.BackendRef.Namespace, grpcr.Namespace), services)
				if svc != nil {
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(*svc, f.RequestMirror, grpcr.Namespace))
				}
			case gatewayv1.GRPCRouteFilterExtensionRef:
				if f.ExtensionRef != nil {
					extensionRefFilter, ok := resolveExtensionRef(
						logger,
						enableExtensionRefFilters,
						grpcr.Namespace,
						f.ExtensionRef,
						extProcFilters,
					)
					if ok {
						extensionRefFilters = append(extensionRefFilters, *extensionRefFilter)
					} else {
						logger.Debug("ExtensionRef resolution failed; route will return 500",
							logfields.K8sNamespace, grpcr.Namespace,
							logfields.Name, string(f.ExtensionRef.Name),
							logfields.Group, string(f.ExtensionRef.Group),
							logfields.Kind, string(f.ExtensionRef.Kind),
						)
						bes = nil
						extensionRefFilters = nil
						dr = &model.DirectResponse{StatusCode: 500}
						// Stop processing further filters: a route with dr=500 carries no
						// backends or ext_proc filters. extensionRefFilters is nil from
						// this point, which is the invariant expected by translation.
						break filterLoop
					}
				}
			}
		}

		if len(rule.Matches) == 0 {
			grpcRoutes = append(grpcRoutes, model.HTTPRoute{
				Hostnames:              hostnames,
				Backends:               bes,
				DirectResponse:         dr,
				RequestHeaderFilter:    requestHeaderFilter,
				ResponseHeaderModifier: responseHeaderFilter,
				RequestMirrors:         requestMirrors,
				ExtensionRefFilters:    extensionRefFilters,
			})
		}

		for _, match := range rule.Matches {
			grpcRoutes = append(grpcRoutes, model.HTTPRoute{
				Hostnames:              hostnames,
				PathMatch:              toGRPCPathMatch(match),
				HeadersMatch:           toGRPCHeaderMatch(match),
				Backends:               bes,
				DirectResponse:         dr,
				RequestHeaderFilter:    requestHeaderFilter,
				ResponseHeaderModifier: responseHeaderFilter,
				RequestMirrors:         requestMirrors,
				ExtensionRefFilters:    extensionRefFilters,
				IsGRPC:                 true,
			})
		}
	}

	return grpcRoutes
}

func toTLSRoutes(listener gatewayv1beta1.Listener, gatewayNamespace string, namespaceLabels helpers.NamespaceLabelIndex, namespacesPreFiltered bool, listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string, input []gatewayv1.TLSRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.TLSPassthroughRoute {
	var tlsRoutes []model.TLSPassthroughRoute
	for _, r := range input {
		isListener := false
		for _, parent := range r.Spec.ParentRefs {
			if parent.SectionName == nil || *parent.SectionName == listener.Name {
				isListener = true
				break
			}
		}
		if !isListener {
			continue
		}

		if !namespacesPreFiltered && !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]
		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allProtocolHostnames)
		// No matching host, skip this route
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}

		for _, rule := range r.Spec.Rules {
			bes := make([]model.Backend, 0, len(rule.BackendRefs))
			for _, be := range rule.BackendRefs {
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be, gatewayv1.SchemeGroupVersion.WithKind("TLSRoute"), grants) {
					continue
				}
				svcName, err := getBackendServiceName(helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services, serviceImports, be.BackendObjectReference)
				if err != nil {
					continue
				}
				if svcName != string(be.Name) {
					be = *be.DeepCopy()
					be.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
						Name:      gatewayv1beta1.ObjectName(svcName),
						Port:      be.Port,
						Namespace: be.Namespace,
					}
				}
				svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services)
				if svc != nil {
					bes = append(bes, backendToModelBackend(*svc, be, r.Namespace))
				}
			}

			tlsRoutes = append(tlsRoutes, model.TLSPassthroughRoute{
				Hostnames: computedHost,
				Backends:  bes,
			})

		}
	}
	return tlsRoutes
}

// l4RouteAttachesToListener reports whether a TCP/UDP route with the given
// parentRefs attaches to the listener, mirroring the sectionName/port matching
// rules used by HTTP/TLS routes.
func l4RouteAttachesToListener(parentRefs []gatewayv1.ParentReference, listener gatewayv1beta1.Listener) bool {
	for _, parent := range parentRefs {
		if parent.SectionName == nil && parent.Port == nil {
			return true
		}

		if parent.SectionName != nil {
			if *parent.SectionName != listener.Name {
				continue
			}
			if parent.Port != nil && *parent.Port != listener.Port {
				continue
			}
			return true
		}

		if parent.Port != nil {
			if *parent.Port != listener.Port {
				continue
			}
			return true
		}
	}
	return false
}

// sortL4RoutesByAge orders routes oldest-first by creation timestamp, tie-broken
// by namespace then name, so L4 conflict resolution deterministically binds the
// oldest route to the listener.
func sortL4RoutesByAge[T any](routes []T, meta func(T) metav1.ObjectMeta) {
	slices.SortStableFunc(routes, func(a, b T) int {
		ma, mb := meta(a), meta(b)
		if c := ma.CreationTimestamp.Time.Compare(mb.CreationTimestamp.Time); c != 0 {
			return c
		}
		if c := cmp.Compare(ma.Namespace, mb.Namespace); c != 0 {
			return c
		}
		return cmp.Compare(ma.Name, mb.Name)
	})
}

func toTCPRoutes(listener gatewayv1beta1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	namespacesPreFiltered bool,
	input []gatewayv1alpha2.TCPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
) []model.L4Route {
	// Collect every TCPRoute that attaches to this listener, then keep only the
	// oldest. Per Gateway API conflict resolution
	// (https://gateway-api.sigs.k8s.io/guides/api-design/#conflicts), an L4
	// listener binds traffic to a single route: the oldest by creation
	// timestamp, tie-broken by namespace/name. Newer routes still report
	// Accepted=True (handled by the status reconciler) but route no traffic.
	attached := make([]gatewayv1alpha2.TCPRoute, 0, len(input))
	for _, r := range input {
		if !namespacesPreFiltered && !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}
		if l4RouteAttachesToListener(r.Spec.ParentRefs, listener) {
			attached = append(attached, r)
		}
	}
	if len(attached) == 0 {
		return nil
	}
	sortL4RoutesByAge(attached, func(r gatewayv1alpha2.TCPRoute) metav1.ObjectMeta { return r.ObjectMeta })

	var l4Routes []model.L4Route
	{
		r := attached[0]
		for _, rule := range r.Spec.Rules {
			bes := make([]model.Backend, 0, len(rule.BackendRefs))
			for _, be := range rule.BackendRefs {
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be, gatewayv1alpha2.SchemeGroupVersion.WithKind("TCPRoute"), grants) {
					continue
				}
				svcName, err := getBackendServiceName(helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services, serviceImports, be.BackendObjectReference)
				if err != nil {
					continue
				}
				if svcName != string(be.Name) {
					be = *be.DeepCopy()
					be.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
						Name:      gatewayv1beta1.ObjectName(svcName),
						Port:      be.Port,
						Namespace: be.Namespace,
					}
				}
				svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services)
				if svc != nil {
					bes = append(bes, backendToModelBackend(*svc, be, r.Namespace))
				}
			}

			l4Routes = append(l4Routes, model.L4Route{
				Backends: bes,
			})
		}
	}
	return l4Routes
}

func toUDPRoutes(listener gatewayv1beta1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	namespacesPreFiltered bool,
	input []gatewayv1alpha2.UDPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
) []model.L4Route {
	// Keep only the oldest attaching UDPRoute. See toTCPRoutes for the rationale.
	attached := make([]gatewayv1alpha2.UDPRoute, 0, len(input))
	for _, r := range input {
		if !namespacesPreFiltered && !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}
		if l4RouteAttachesToListener(r.Spec.ParentRefs, listener) {
			attached = append(attached, r)
		}
	}
	if len(attached) == 0 {
		return nil
	}
	sortL4RoutesByAge(attached, func(r gatewayv1alpha2.UDPRoute) metav1.ObjectMeta { return r.ObjectMeta })

	var l4Routes []model.L4Route
	{
		r := attached[0]
		for _, rule := range r.Spec.Rules {
			bes := make([]model.Backend, 0, len(rule.BackendRefs))
			for _, be := range rule.BackendRefs {
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be, gatewayv1alpha2.SchemeGroupVersion.WithKind("UDPRoute"), grants) {
					continue
				}
				svcName, err := getBackendServiceName(helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services, serviceImports, be.BackendObjectReference)
				if err != nil {
					continue
				}
				if svcName != string(be.Name) {
					be = *be.DeepCopy()
					be.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
						Name:      gatewayv1beta1.ObjectName(svcName),
						Port:      be.Port,
						Namespace: be.Namespace,
					}
				}
				svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services)
				if svc != nil {
					bes = append(bes, backendToModelBackend(*svc, be, r.Namespace))
				}
			}

			l4Routes = append(l4Routes, model.L4Route{
				Backends: bes,
			})
		}
	}
	return l4Routes
}

func toHTTPRequestRedirectFilter(listenerPort int32, redirect *gatewayv1.HTTPRequestRedirectFilter) *model.HTTPRequestRedirectFilter {
	if redirect == nil {
		return nil
	}
	var pathModifier *model.StringMatch
	if redirect.Path != nil {
		pathModifier = &model.StringMatch{}

		switch redirect.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			pathModifier.Exact = *redirect.Path.ReplaceFullPath
		case gatewayv1.PrefixMatchHTTPPathModifier:
			pathModifier.Prefix = *redirect.Path.ReplacePrefixMatch
		}
	}
	var redirectPort *int32
	if redirect.Port == nil {
		if redirect.Scheme == nil {
			// If redirect scheme is empty, the redirect port MUST be the Gateway
			// Listener port.
			// Refer to: https://github.com/kubernetes-sigs/gateway-api/blob/35fe25d1384a41c9b89dd5af7ae3214c431f008c/apis/v1/httproute_types.go#L1040-L1041
			redirectPort = ptr.To(listenerPort)
		}
	} else {
		redirectPort = (*int32)(redirect.Port)
	}
	return &model.HTTPRequestRedirectFilter{
		Scheme:     redirect.Scheme,
		Hostname:   (*string)(redirect.Hostname),
		Path:       pathModifier,
		Port:       redirectPort,
		StatusCode: redirect.StatusCode,
	}
}

func toHTTPRewriteFilter(rewrite *gatewayv1.HTTPURLRewriteFilter) *model.HTTPURLRewriteFilter {
	if rewrite == nil {
		return nil
	}
	var path *model.StringMatch
	if rewrite.Path != nil {
		switch rewrite.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			if rewrite.Path.ReplaceFullPath != nil {
				path = &model.StringMatch{
					Exact: *rewrite.Path.ReplaceFullPath,
				}
			}
		case gatewayv1.PrefixMatchHTTPPathModifier:
			if rewrite.Path.ReplacePrefixMatch != nil {
				path = &model.StringMatch{
					// a trailing `/` is ignored
					Prefix: strings.TrimSuffix(*rewrite.Path.ReplacePrefixMatch, "/"),
				}
			}
		}
	}
	return &model.HTTPURLRewriteFilter{
		HostName: (*string)(rewrite.Hostname),
		Path:     path,
	}
}

func toHTTPExternalAuthFilter(log *slog.Logger, ea *gatewayv1.HTTPExternalAuthFilter, defaultNamespace string, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, btlspMap helpers.BackendTLSPolicyServiceMap) *model.HTTPExternalAuthFilter {
	if ea == nil {
		return nil
	}
	if ea.BackendRef.Port == nil {
		log.Warn("ExternalAuth filter has no port specified; filter will be ignored",
			logfields.K8sNamespace, helpers.NamespaceDerefOr(ea.BackendRef.Namespace, defaultNamespace),
			logfields.Name, string(ea.BackendRef.Name),
		)
		return nil
	}
	ns := helpers.NamespaceDerefOr(ea.BackendRef.Namespace, defaultNamespace)
	svcName, err := getBackendServiceName(ns, services, serviceImports, ea.BackendRef)
	if err != nil {
		return nil
	}
	svc := getServiceSpec(svcName, ns, services)
	if svc == nil {
		return nil
	}

	be := model.Backend{
		Name:      svcName,
		Namespace: ns,
		Port:      &model.BackendPort{Port: uint32(*ea.BackendRef.Port)},
	}
	var include bool
	be, include = addBackendTLSDetails(log, be, svc, btlspMap)
	if !include {
		return nil
	}

	filter := &model.HTTPExternalAuthFilter{
		Backend:  be,
		Protocol: model.ExternalAuthProtocol(ea.ExternalAuthProtocol),
	}
	if ea.HTTPAuthConfig != nil {
		filter.PathPrefix = ea.HTTPAuthConfig.Path
		filter.AllowedRequestHeaders = ea.HTTPAuthConfig.AllowedRequestHeaders
		filter.AllowedResponseHeaders = ea.HTTPAuthConfig.AllowedResponseHeaders
	}
	if ea.GRPCAuthConfig != nil {
		filter.AllowedRequestHeaders = ea.GRPCAuthConfig.AllowedRequestHeaders
	}
	if ea.ForwardBody != nil && ea.ForwardBody.MaxSize > 0 {
		filter.ForwardBody = &model.ForwardBodyConfig{MaxSize: uint32(ea.ForwardBody.MaxSize)}
	}
	return filter
}

func toHTTPRequestMirror(svc corev1.Service, mirror *gatewayv1.HTTPRequestMirrorFilter, ns string) *model.HTTPRequestMirror {
	var n, d int32 = 100, 100

	switch {
	case mirror.Percent != nil:
		n = *mirror.Percent
	case mirror.Fraction != nil:
		n = mirror.Fraction.Numerator
		if mirror.Fraction.Denominator != nil {
			d = *mirror.Fraction.Denominator
		}
	}

	return &model.HTTPRequestMirror{
		Backend:     ptr.To(backendRefToModelBackend(svc, mirror.BackendRef, ns)),
		Numerator:   n,
		Denominator: d,
	}
}

// resolveExtensionRef resolves a Gateway API ExtensionRef filter to a
// ExtensionRefFilter. Returns nil, false when the filter cannot be resolved
// (disabled, wrong group/kind, or CRD not found), which signals a fail-closed
// 500 DirectResponse.
func resolveExtensionRef(
	log *slog.Logger,
	enableExtensionRefFilters bool,
	namespace string,
	ref *gatewayv1.LocalObjectReference,
	extProcFilters []v2alpha1.CiliumEnvoyExtProcFilter,
) (*model.ExtensionRefFilter, bool) {
	if !enableExtensionRefFilters {
		log.Debug("ExtensionRef filters not enabled; ignoring ExtensionRef filter",
			logfields.K8sNamespace, namespace,
			logfields.Name, string(ref.Name),
		)
		return nil, false
	}

	if ref.Group != "cilium.io" || ref.Kind != "CiliumEnvoyExtProcFilter" {
		log.Debug("ExtensionRef group/kind not supported",
			logfields.Group, string(ref.Group),
			logfields.Kind, string(ref.Kind),
		)
		return nil, false
	}

	var found *v2alpha1.CiliumEnvoyExtProcFilter
	for i := range extProcFilters {
		if extProcFilters[i].Name == string(ref.Name) && extProcFilters[i].Namespace == namespace {
			found = &extProcFilters[i]
			break
		}
	}
	if found == nil {
		log.Debug("ExtensionRef CRD not found",
			logfields.K8sNamespace, namespace,
			logfields.Name, string(ref.Name),
		)
		return nil, false
	}

	return crdToExtensionRefFilter(log, found)
}

// crdToExtensionRefFilter converts a CiliumEnvoyExtProcFilter CRD to a
// model.ExtensionRefFilter by building an ExternalProcessor protobuf config.
func crdToExtensionRefFilter(log *slog.Logger, crd *v2alpha1.CiliumEnvoyExtProcFilter) (*model.ExtensionRefFilter, bool) {
	ns := helpers.NamespaceDerefOr(helpers.ExtProcBackendRefNamespace(crd.Spec.BackendRef), crd.Namespace)

	backend := &model.Backend{
		Name:      crd.Spec.BackendRef.Name,
		Namespace: ns,
		Port: &model.BackendPort{
			Port: uint32(crd.Spec.BackendRef.Port),
		},
	}

	// Use the same "namespace:name:port" format as getClusterName in the
	// translation layer so this reference matches the cluster that will be created.
	clusterName := backend.Namespace + ":" + backend.Name + ":" + backend.Port.GetPort()

	extProc := &ext_procv3.ExternalProcessor{
		StatPrefix: extProcStatPrefix(crd.Namespace, crd.Name),
		GrpcService: &envoy_config_core_v3.GrpcService{
			TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
					ClusterName: clusterName,
					// Authority overrides the :authority pseudo-header sent to the
					// ext_proc server. Without this, Envoy uses the cluster name,
					// which after CEC namespace-qualification contains slashes
					// ("ns/cec/cluster") that are illegal in an HTTP/2 authority
					// and cause strict gRPC clients to reset the connection.
					Authority: fmt.Sprintf("%s:%d", crd.Spec.BackendRef.Name, crd.Spec.BackendRef.Port),
				},
			},
		},
		FailureModeAllow: crd.Spec.FailureModeAllow,
	}

	if crd.Spec.ProcessingMode != nil {
		extProc.ProcessingMode = convertProcessingMode(crd.Spec.ProcessingMode)
	}

	if crd.Spec.MessageTimeout != nil {
		extProc.MessageTimeout = durationpb.New(crd.Spec.MessageTimeout.Duration)
	}

	config, err := proto.Marshal(extProc)
	if err != nil {
		log.Warn("Failed to marshal ext_proc filter config",
			logfields.Error, err,
			logfields.ResourceName, crd.Name,
			logfields.K8sNamespace, crd.Namespace,
		)
		return nil, false
	}

	return &model.ExtensionRefFilter{
		Name:    extProcFilterName(crd.Namespace, crd.Name),
		TypeURL: model.ExtProcExternalProcessorTypeURL,
		Config:  config,
		Backend: backend,
	}, true
}

// extProcFilterName returns the Envoy filter instance name for a CiliumEnvoyExtProcFilter.
// The name is used as both the HCM filter name and the TypedPerFilterConfig key on routes.
func extProcFilterName(namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", model.ExtProcFilterNamePrefix, namespace, name)
}

func extProcStatPrefix(namespace, name string) string {
	return fmt.Sprintf("ceepf.%s.%s.", sanitizeExtProcStatPart(namespace), sanitizeExtProcStatPart(name))
}

var extProcStatReplacer = strings.NewReplacer("-", "_", ".", "_")

func sanitizeExtProcStatPart(s string) string {
	return extProcStatReplacer.Replace(s)
}

func convertProcessingMode(pm *v2alpha1.ExtProcProcessingMode) *ext_procv3.ProcessingMode {
	mode := &ext_procv3.ProcessingMode{}
	if pm.RequestHeaderMode != nil {
		mode.RequestHeaderMode = toHeaderSendMode(*pm.RequestHeaderMode)
	}
	if pm.ResponseHeaderMode != nil {
		mode.ResponseHeaderMode = toHeaderSendMode(*pm.ResponseHeaderMode)
	}
	if pm.RequestBodyMode != nil {
		mode.RequestBodyMode = toBodySendMode(*pm.RequestBodyMode)
	}
	if pm.ResponseBodyMode != nil {
		mode.ResponseBodyMode = toBodySendMode(*pm.ResponseBodyMode)
	}
	if pm.RequestTrailerMode != nil {
		mode.RequestTrailerMode = toHeaderSendMode(*pm.RequestTrailerMode)
	}
	if pm.ResponseTrailerMode != nil {
		mode.ResponseTrailerMode = toHeaderSendMode(*pm.ResponseTrailerMode)
	}
	return mode
}

func toHeaderSendMode(s string) ext_procv3.ProcessingMode_HeaderSendMode {
	switch s {
	case "SEND":
		return ext_procv3.ProcessingMode_SEND
	case "SKIP":
		return ext_procv3.ProcessingMode_SKIP
	default:
		return ext_procv3.ProcessingMode_DEFAULT
	}
}

func toBodySendMode(s string) ext_procv3.ProcessingMode_BodySendMode {
	switch s {
	case "NONE":
		return ext_procv3.ProcessingMode_NONE
	case "STREAMED":
		return ext_procv3.ProcessingMode_STREAMED
	case "BUFFERED":
		return ext_procv3.ProcessingMode_BUFFERED
	case "BUFFERED_PARTIAL":
		return ext_procv3.ProcessingMode_BUFFERED_PARTIAL
	default:
		return ext_procv3.ProcessingMode_NONE
	}
}

func toHostname(hostname *gatewayv1.Hostname) string {
	if hostname != nil {
		return string(*hostname)
	}
	return allHosts
}

func getServiceSpec(svcName, svcNamespace string, services []corev1.Service) *corev1.Service {
	for _, svc := range services {
		if svc.GetName() == svcName && svc.GetNamespace() == svcNamespace {
			return &svc
		}
	}
	return nil
}

func getServiceImport(svcName, svcNamespace string, serviceImports []mcsapiv1beta1.ServiceImport) *mcsapiv1beta1.ServiceImport {
	for _, svc := range serviceImports {
		if svc.GetName() == svcName && svc.GetNamespace() == svcNamespace {
			return &svc
		}
	}
	return nil
}

func backendToModelBackend(svc corev1.Service, be gatewayv1.BackendRef, defaultNamespace string) model.Backend {
	res := backendRefToModelBackend(svc, be.BackendObjectReference, defaultNamespace)
	res.Weight = be.Weight
	return res
}

func backendRefToModelBackend(svc corev1.Service, be gatewayv1.BackendObjectReference, defaultNamespace string) model.Backend {
	ns := helpers.NamespaceDerefOr(be.Namespace, defaultNamespace)
	var port *model.BackendPort
	var appProtocol *string

	if be.Port != nil {
		backendPort := uint32(*be.Port)
		appProtocol = backendRefToAppProtocol(svc, int32(*be.Port))

		port = &model.BackendPort{
			Port: backendPort,
		}
	}

	return model.Backend{
		Name:        string(be.Name),
		Namespace:   ns,
		Port:        port,
		AppProtocol: appProtocol,
	}
}

func backendRefToAppProtocol(svc corev1.Service, backendPort int32) *string {
	for _, portSpec := range svc.Spec.Ports {
		if backendPort == portSpec.Port {
			return portSpec.AppProtocol
		}
	}

	return nil
}

func toPathMatch(match gatewayv1.HTTPRouteMatch) model.StringMatch {
	if match.Path == nil {
		return model.StringMatch{}
	}

	switch *match.Path.Type {
	case gatewayv1.PathMatchExact:
		return model.StringMatch{
			Exact: *match.Path.Value,
		}
	case gatewayv1.PathMatchPathPrefix:
		return model.StringMatch{
			Prefix: *match.Path.Value,
		}
	case gatewayv1.PathMatchRegularExpression:
		return model.StringMatch{
			Regex: *match.Path.Value,
		}
	}
	return model.StringMatch{}
}

func toGRPCPathMatch(match gatewayv1.GRPCRouteMatch) model.StringMatch {
	if match.Method == nil {
		return model.StringMatch{}
	}

	t := gatewayv1.GRPCMethodMatchExact
	if match.Method.Type != nil {
		t = *match.Method.Type
	}
	switch t {
	case gatewayv1.GRPCMethodMatchExact:
		if match.Method.Service != nil && match.Method.Method != nil {
			return model.StringMatch{
				Exact: "/" + *match.Method.Service + "/" + *match.Method.Method,
			}
		} else if match.Method.Service != nil {
			return model.StringMatch{
				Prefix: "/" + *match.Method.Service + "/",
			}
		} else if match.Method.Method != nil {
			return model.StringMatch{
				Regex: "/.+/" + *match.Method.Method,
			}
		} else {
			// This case is not allowed by the spec
		}
	case gatewayv1.GRPCMethodMatchRegularExpression:
		if match.Method.Service != nil && match.Method.Method != nil {
			return model.StringMatch{
				Regex: "/" + *match.Method.Service + "/" + *match.Method.Method,
			}
		} else if match.Method.Service != nil {
			return model.StringMatch{
				Regex: "/" + *match.Method.Service + "/.+",
			}
		} else if match.Method.Method != nil {
			return model.StringMatch{
				Regex: "/.+/" + *match.Method.Method,
			}
		} else {
			return model.StringMatch{
				Prefix: "/",
			}
		}
	}
	return model.StringMatch{}
}

func toHeaderMatch(match gatewayv1.HTTPRouteMatch) []model.KeyValueMatch {
	if len(match.Headers) == 0 {
		return nil
	}
	res := make([]model.KeyValueMatch, 0, len(match.Headers))
	for _, h := range match.Headers {
		t := gatewayv1.HeaderMatchExact
		if h.Type != nil {
			t = *h.Type
		}
		switch t {
		case gatewayv1.HeaderMatchExact:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Exact: h.Value,
				},
			})
		case gatewayv1.HeaderMatchRegularExpression:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Regex: h.Value,
				},
			})
		}
	}
	return res
}

func toGRPCHeaderMatch(match gatewayv1.GRPCRouteMatch) []model.KeyValueMatch {
	if len(match.Headers) == 0 {
		return nil
	}
	res := make([]model.KeyValueMatch, 0, len(match.Headers))
	for _, h := range match.Headers {
		t := gatewayv1.GRPCHeaderMatchExact
		if h.Type != nil {
			t = *h.Type
		}
		switch t {
		case gatewayv1.GRPCHeaderMatchExact:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Exact: h.Value,
				},
			})
		case gatewayv1.GRPCHeaderMatchRegularExpression:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Regex: h.Value,
				},
			})
		}
	}
	return res
}

func toQueryMatch(match gatewayv1.HTTPRouteMatch) []model.KeyValueMatch {
	if len(match.QueryParams) == 0 {
		return nil
	}
	res := make([]model.KeyValueMatch, 0, len(match.QueryParams))
	for _, h := range match.QueryParams {
		t := gatewayv1.QueryParamMatchExact
		if h.Type != nil {
			t = *h.Type
		}
		switch t {
		case gatewayv1.QueryParamMatchExact:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Exact: h.Value,
				},
			})
		case gatewayv1.QueryParamMatchRegularExpression:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Regex: h.Value,
				},
			})
		}
	}
	return res
}

func toTLS(tls *gatewayv1.ListenerTLSConfig, grants []gatewayv1.ReferenceGrant, defaultNamespace string, sourceGVK schema.GroupVersionKind) []model.TLSSecret {
	if tls == nil {
		return nil
	}

	res := make([]model.TLSSecret, 0, len(tls.CertificateRefs))
	for _, cert := range tls.CertificateRefs {
		if !helpers.IsSecretReferenceAllowed(defaultNamespace, cert, sourceGVK, grants) {
			// not allowed to be referred to, skipping
			continue
		}
		res = append(res, model.TLSSecret{
			Name:      string(cert.Name),
			Namespace: helpers.NamespaceDerefOr(cert.Namespace, defaultNamespace),
		})
	}
	return res
}

func toHTTPHeaders(headers []gatewayv1.HTTPHeader) []model.Header {
	if len(headers) == 0 {
		return nil
	}
	res := make([]model.Header, 0, len(headers))
	for _, h := range headers {
		res = append(res, model.Header{
			Name:  string(h.Name),
			Value: h.Value,
		})
	}
	return res
}

func toMapString[K, V ~string](in map[K]V) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

func toStringSlice[S ~string](s []S) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}
