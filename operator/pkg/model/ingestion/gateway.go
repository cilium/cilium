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
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	allHosts = "*"
)

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

	// Find all the listener host names, so that we can match them with the routes
	// Gateway API spec guarantees that the hostnames are unique across all listeners
	listenerHostnamesByProtocol := make(map[gatewayv1.ProtocolType][]string)
	for _, l := range input.Gateway.Spec.Listeners {
		if l.Hostname != nil {
			_, ok := listenerHostnamesByProtocol[l.Protocol]
			if !ok {
				listenerHostnamesByProtocol[l.Protocol] = []string{}
			}
			listenerHostnamesByProtocol[l.Protocol] = append(listenerHostnamesByProtocol[l.Protocol], toHostname(l.Hostname))
		}
	}

	for _, l := range input.Gateway.Spec.Listeners {
		switch l.Protocol {
		case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType, gatewayv1.TLSProtocolType:
			var httpRoutes []model.HTTPRoute
			httpRoutes = append(httpRoutes, toHTTPRoutes(log, l, input.Gateway.GetNamespace(), namespaceLabels, listenerHostnamesByProtocol, input.HTTPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants, input.BackendTLSPolicyMap)...)
			httpRoutes = append(httpRoutes, toGRPCRoutes(l, input.Gateway.GetNamespace(), namespaceLabels, listenerHostnamesByProtocol, input.GRPCRoutes, input.Services, input.ServiceImports, input.ReferenceGrants)...)
			resHTTP = append(resHTTP, model.HTTPListener{
				Name: string(l.Name),
				Sources: []model.FullyQualifiedResource{
					{
						Name:      input.Gateway.GetName(),
						Namespace: input.Gateway.GetNamespace(),
						Group:     gatewayv1.SchemeGroupVersion.Group,
						Version:   gatewayv1.SchemeGroupVersion.Version,
						Kind:      "Gateway",
						UID:       string(input.Gateway.GetUID()),
					},
				},
				Port:           uint32(l.Port),
				Hostname:       toHostname(l.Hostname),
				TLS:            toTLS(l.TLS, input.ReferenceGrants, input.Gateway.GetNamespace()),
				Routes:         httpRoutes,
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})

			if l.Protocol == gatewayv1.TLSProtocolType {
				resTLSPassthrough = append(resTLSPassthrough, model.TLSPassthroughListener{
					Name: string(l.Name),
					Sources: []model.FullyQualifiedResource{
						{
							Name:      input.Gateway.GetName(),
							Namespace: input.Gateway.GetNamespace(),
							Group:     gatewayv1.SchemeGroupVersion.Group,
							Version:   gatewayv1.SchemeGroupVersion.Version,
							Kind:      "Gateway",
							UID:       string(input.Gateway.GetUID()),
						},
					},
					Port:           uint32(l.Port),
					Hostname:       toHostname(l.Hostname),
					Routes:         toTLSRoutes(l, input.Gateway.GetNamespace(), namespaceLabels, listenerHostnamesByProtocol, input.TLSRoutes, input.Services, input.ServiceImports, input.ReferenceGrants),
					Infrastructure: infra,
					Service:        toServiceModel(input.GatewayClassConfig),
				})
			}

		case gatewayv1.TCPProtocolType:
			resL4 = append(resL4, model.L4Listener{
				Name: string(l.Name),
				Sources: []model.FullyQualifiedResource{
					{
						Name:      input.Gateway.GetName(),
						Namespace: input.Gateway.GetNamespace(),
						Group:     gatewayv1.SchemeGroupVersion.Group,
						Version:   gatewayv1.SchemeGroupVersion.Version,
						Kind:      "Gateway",
						UID:       string(input.Gateway.GetUID()),
					},
				},
				Port:           uint32(l.Port),
				Protocol:       model.L4ProtocolTCP,
				Routes:         toTCPRoutes(l, input.Gateway.GetNamespace(), namespaceLabels, input.TCPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants),
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})

		case gatewayv1.UDPProtocolType:
			resL4 = append(resL4, model.L4Listener{
				Name: string(l.Name),
				Sources: []model.FullyQualifiedResource{
					{
						Name:      input.Gateway.GetName(),
						Namespace: input.Gateway.GetNamespace(),
						Group:     gatewayv1.SchemeGroupVersion.Group,
						Version:   gatewayv1.SchemeGroupVersion.Version,
						Kind:      "Gateway",
						UID:       string(input.Gateway.GetUID()),
					},
				},
				Port:           uint32(l.Port),
				Protocol:       model.L4ProtocolUDP,
				Routes:         toUDPRoutes(l, input.Gateway.GetNamespace(), namespaceLabels, input.UDPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants),
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
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.HTTPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	btlspMap helpers.BackendTLSPolicyServiceMap,
) []model.HTTPRoute {
	var httpRoutes []model.HTTPRoute
	for _, match := range matchingHostnameRoutes(listener, gatewayNamespace, namespaceLabels, listenerHostnamesByProtocol, input,
		func(r gatewayv1.HTTPRoute) []gatewayv1.ParentReference { return r.Spec.ParentRefs },
		func(r gatewayv1.HTTPRoute) string { return r.GetNamespace() },
		func(r gatewayv1.HTTPRoute) []gatewayv1.Hostname { return r.Spec.Hostnames },
	) {
		httpRoutes = append(httpRoutes, extractRoutes(log, int32(listener.Port), match.hostnames, match.route, services, serviceImports, grants, btlspMap)...)
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
) []model.HTTPRoute {
	var httpRoutes []model.HTTPRoute
	for _, rule := range hr.Spec.Rules {
		var backendHTTPFilters []*model.BackendHTTPFilter
		bes := make([]model.Backend, 0, len(rule.BackendRefs))
		for _, be := range rule.BackendRefs {
			toAppend, svc, ok := resolveBackendRef(hr.GetNamespace(), be.BackendRef, gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"), services, serviceImports, grants)
			if !ok {
				continue
			}
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
						Name: fmt.Sprintf("%s:%s:%d", toAppend.Namespace, toAppend.Name, toAppend.Port.Port),
						RequestHeaderFilter: &model.HTTPHeaderFilter{
							HeadersToAdd:    toHTTPHeaders(f.RequestHeaderModifier.Add),
							HeadersToSet:    toHTTPHeaders(f.RequestHeaderModifier.Set),
							HeadersToRemove: f.RequestHeaderModifier.Remove,
						},
					})
				case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
					backendHTTPFilters = append(backendHTTPFilters, &model.BackendHTTPFilter{
						Name: fmt.Sprintf("%s:%s:%d", toAppend.Namespace, toAppend.Name, toAppend.Port.Port),
						ResponseHeaderModifier: &model.HTTPHeaderFilter{
							HeadersToAdd:    toHTTPHeaders(f.ResponseHeaderModifier.Add),
							HeadersToSet:    toHTTPHeaders(f.ResponseHeaderModifier.Set),
							HeadersToRemove: f.ResponseHeaderModifier.Remove,
						},
					})
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

				backend, _, ok := resolveBackendRef(hr.GetNamespace(), gatewayv1.BackendRef{BackendObjectReference: f.RequestMirror.BackendRef}, gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"), services, serviceImports, grants)
				if ok {
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(backend, f.RequestMirror))
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

func toGRPCRoutes(listener gatewayv1beta1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.GRPCRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
) []model.HTTPRoute {
	var grpcRoutes []model.HTTPRoute
	for _, match := range matchingHostnameRoutes(listener, gatewayNamespace, namespaceLabels, listenerHostnamesByProtocol, input,
		func(r gatewayv1.GRPCRoute) []gatewayv1.ParentReference { return r.Spec.ParentRefs },
		func(r gatewayv1.GRPCRoute) string { return r.GetNamespace() },
		func(r gatewayv1.GRPCRoute) []gatewayv1.Hostname { return r.Spec.Hostnames },
	) {
		grpcRoutes = append(grpcRoutes, extractGRPCRoutes(match.hostnames, match.route, services, serviceImports, grants)...)
	}
	return grpcRoutes
}

func extractGRPCRoutes(hostnames []string, grpcr gatewayv1.GRPCRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.HTTPRoute {
	var grpcRoutes []model.HTTPRoute
	for _, rule := range grpcr.Spec.Rules {
		bes := make([]model.Backend, 0, len(rule.BackendRefs))
		for _, be := range rule.BackendRefs {
			if backend, _, ok := resolveBackendRef(grpcr.GetNamespace(), be.BackendRef, gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"), services, serviceImports, grants); ok {
				bes = append(bes, backend)
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

				backend, _, ok := resolveBackendRef(grpcr.GetNamespace(), gatewayv1.BackendRef{BackendObjectReference: f.RequestMirror.BackendRef}, gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"), services, serviceImports, grants)
				if ok {
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(backend, f.RequestMirror))
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
				IsGRPC:                 true,
			})
		}
	}

	return grpcRoutes
}

func toTLSRoutes(listener gatewayv1beta1.Listener, gatewayNamespace string, namespaceLabels helpers.NamespaceLabelIndex, listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string, input []gatewayv1.TLSRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.TLSPassthroughRoute {
	var tlsRoutes []model.TLSPassthroughRoute
	for _, match := range matchingHostnameRoutes(listener, gatewayNamespace, namespaceLabels, listenerHostnamesByProtocol, input,
		func(r gatewayv1.TLSRoute) []gatewayv1.ParentReference { return r.Spec.ParentRefs },
		func(r gatewayv1.TLSRoute) string { return r.GetNamespace() },
		func(r gatewayv1.TLSRoute) []gatewayv1.Hostname { return r.Spec.Hostnames },
	) {
		r := match.route
		for _, rule := range r.Spec.Rules {
			bes := make([]model.Backend, 0, len(rule.BackendRefs))
			for _, be := range rule.BackendRefs {
				if backend, _, ok := resolveBackendRef(r.GetNamespace(), be, gatewayv1.SchemeGroupVersion.WithKind("TLSRoute"), services, serviceImports, grants); ok {
					bes = append(bes, backend)
				}
			}

			tlsRoutes = append(tlsRoutes, model.TLSPassthroughRoute{
				Hostnames: match.hostnames,
				Backends:  bes,
			})

		}
	}
	return tlsRoutes
}

type hostnameRouteMatch[T any] struct {
	route     T
	hostnames []string
}

func matchingHostnameRoutes[T any](
	listener gatewayv1.Listener,
	gatewayNamespace string,
	namespaceLabels helpers.NamespaceLabelIndex,
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []T,
	parentRefs func(T) []gatewayv1.ParentReference,
	namespace func(T) string,
	hostnames func(T) []gatewayv1.Hostname,
) []hostnameRouteMatch[T] {
	var routes []hostnameRouteMatch[T]
	for _, r := range input {
		if !routeAttachesToListener(parentRefs(r), listener) {
			continue
		}

		if !helpers.IsListenerNamespaceAllowed(listener, namespace(r), gatewayNamespace, namespaceLabels) {
			continue
		}

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]
		computedHost := model.ComputeHosts(toStringSlice(hostnames(r)), (*string)(listener.Hostname), allProtocolHostnames)
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}

		routes = append(routes, hostnameRouteMatch[T]{
			route:     r,
			hostnames: computedHost,
		})
	}
	return routes
}

// routeAttachesToListener reports whether a route with the given parentRefs
// attaches to the listener by SectionName and Port.
func routeAttachesToListener(parentRefs []gatewayv1.ParentReference, listener gatewayv1beta1.Listener) bool {
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

func toTCPRoutes(listener gatewayv1beta1.Listener, gatewayNamespace string, namespaceLabels helpers.NamespaceLabelIndex, input []gatewayv1alpha2.TCPRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.L4Route {
	// Collect every TCPRoute that attaches to this listener, then keep only the
	// oldest. Per Gateway API conflict resolution
	// (https://gateway-api.sigs.k8s.io/guides/api-design/#conflicts), an L4
	// listener binds traffic to a single route: the oldest by creation
	// timestamp, tie-broken by namespace/name. Newer routes still report
	// Accepted=True (handled by the status reconciler) but route no traffic.
	attached := make([]gatewayv1alpha2.TCPRoute, 0, len(input))
	for _, r := range input {
		if !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}
		if routeAttachesToListener(r.Spec.ParentRefs, listener) {
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
				if backend, _, ok := resolveBackendRef(r.GetNamespace(), be, gatewayv1alpha2.SchemeGroupVersion.WithKind("TCPRoute"), services, serviceImports, grants); ok {
					bes = append(bes, backend)
				}
			}

			l4Routes = append(l4Routes, model.L4Route{
				Backends: bes,
			})
		}
	}
	return l4Routes
}

func toUDPRoutes(listener gatewayv1beta1.Listener, gatewayNamespace string, namespaceLabels helpers.NamespaceLabelIndex, input []gatewayv1alpha2.UDPRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.L4Route {
	// Keep only the oldest attaching UDPRoute. See toTCPRoutes for the rationale.
	attached := make([]gatewayv1alpha2.UDPRoute, 0, len(input))
	for _, r := range input {
		if !helpers.IsListenerNamespaceAllowed(listener, r.GetNamespace(), gatewayNamespace, namespaceLabels) {
			continue
		}
		if routeAttachesToListener(r.Spec.ParentRefs, listener) {
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
				if backend, _, ok := resolveBackendRef(r.GetNamespace(), be, gatewayv1alpha2.SchemeGroupVersion.WithKind("UDPRoute"), services, serviceImports, grants); ok {
					bes = append(bes, backend)
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

func toHTTPRequestMirror(backend model.Backend, mirror *gatewayv1.HTTPRequestMirrorFilter) *model.HTTPRequestMirror {
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
		Backend:     ptr.To(backend),
		Numerator:   n,
		Denominator: d,
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

func resolveBackendRef(routeNamespace string, be gatewayv1.BackendRef, routeGVK schema.GroupVersionKind, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) (model.Backend, *corev1.Service, bool) {
	if !helpers.IsBackendReferenceAllowed(routeNamespace, be, routeGVK, grants) {
		return model.Backend{}, nil, false
	}

	backendNamespace := helpers.NamespaceDerefOr(be.Namespace, routeNamespace)
	svcName, err := getBackendServiceName(backendNamespace, services, serviceImports, be.BackendObjectReference)
	if err != nil {
		return model.Backend{}, nil, false
	}

	if svcName != string(be.Name) {
		be = *be.DeepCopy()
		be.BackendObjectReference = gatewayv1beta1.BackendObjectReference{
			Name:      gatewayv1beta1.ObjectName(svcName),
			Port:      be.Port,
			Namespace: be.Namespace,
		}
	}

	if be.Port == nil {
		return model.Backend{}, nil, false
	}

	svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, routeNamespace), services)
	if svc == nil {
		return model.Backend{}, nil, false
	}

	return backendToModelBackend(*svc, be, routeNamespace), svc, true
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

func toTLS(tls *gatewayv1.ListenerTLSConfig, grants []gatewayv1.ReferenceGrant, defaultNamespace string) []model.TLSSecret {
	if tls == nil {
		return nil
	}

	res := make([]model.TLSSecret, 0, len(tls.CertificateRefs))
	for _, cert := range tls.CertificateRefs {
		if !helpers.IsSecretReferenceAllowed(defaultNamespace, cert, gatewayv1.SchemeGroupVersion.WithKind("Gateway"), grants) {
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
