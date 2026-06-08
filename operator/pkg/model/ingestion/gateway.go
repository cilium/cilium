// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"cmp"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	// Envoy specialized types for Rate Limiting
	envoy_extensions_filters_http_local_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	envoy_extensions_filters_http_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

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
	ReferenceGrants     []gatewayv1.ReferenceGrant
	Services            []corev1.Service
	ServiceImports      []mcsapiv1beta1.ServiceImport
	BackendTLSPolicyMap helpers.BackendTLSPolicyServiceMap
	RateLimitPolicies   []v2alpha1.CiliumRateLimitPolicy
}

// GatewayAPI translates Gateway API resources into a model.
func GatewayAPI(log *slog.Logger, input Input) ([]model.HTTPListener, []model.TLSPassthroughListener) {
	var resHTTP []model.HTTPListener
	var resTLSPassthrough []model.TLSPassthroughListener

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

	// Gateway API spec guarantees that the hostnames are unique across all listeners
	listenerHostnamesByProtocol := make(map[gatewayv1.ProtocolType][]string)
	for _, l := range input.Gateway.Spec.Listeners {
		if l.Hostname != nil {
			if _, ok := listenerHostnamesByProtocol[l.Protocol]; !ok {
				listenerHostnamesByProtocol[l.Protocol] = []string{}
			}
			listenerHostnamesByProtocol[l.Protocol] = append(listenerHostnamesByProtocol[l.Protocol], toHostname(l.Hostname))
		}
	}

	for _, l := range input.Gateway.Spec.Listeners {
		if l.Protocol != gatewayv1.HTTPProtocolType &&
			l.Protocol != gatewayv1.HTTPSProtocolType &&
			l.Protocol != gatewayv1.TLSProtocolType {
			continue
		}

		// 1. Extract all routes (HTTP and GRPC) for this specific listener.
		// We pass RateLimitPolicies down the chain to be associated with specific routes.
		var combinedRoutes []model.HTTPRoute
		combinedRoutes = append(combinedRoutes, toHTTPRoutes(log, l, listenerHostnamesByProtocol, input.HTTPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants, input.BackendTLSPolicyMap, input.RateLimitPolicies)...)
		combinedRoutes = append(combinedRoutes, toGRPCRoutes(l, listenerHostnamesByProtocol, input.GRPCRoutes, input.Services, input.ServiceImports, input.ReferenceGrants, input.RateLimitPolicies)...)

		// 2. Filter Chain Analysis:
		// Scan the extracted routes to see if we need to enable the Rate Limit filter in the HCM.
		var listenerFilters []model.HTTPFilter
		needsLocalRateLimit := false
		needsGlobalRateLimit := false

		for _, r := range combinedRoutes {
			if r.TypedPerFilterConfig != nil {
				if _, ok := r.TypedPerFilterConfig["envoy.filters.http.local_ratelimit"]; ok {
					needsLocalRateLimit = true
				}
				if _, ok := r.TypedPerFilterConfig["envoy.filters.http.ratelimit"]; ok {
					needsGlobalRateLimit = true
				}
			}
		}

		// 3. Register Local Rate Limit if required.
		if needsLocalRateLimit {
			localProto := &envoy_extensions_filters_http_local_ratelimit_v3.LocalRateLimit{
				StatPrefix: "local_limit",
			}
			if anyCfg, err := anypb.New(localProto); err == nil {
				listenerFilters = append(listenerFilters, model.HTTPFilter{
					Name:     "envoy.filters.http.local_ratelimit",
					Priority: model.HTTPFilterPriorityRateLimit,
					Config:   anyCfg,
				})
			}
		}

		// 4. Register Global Rate Limit if required.
		if needsGlobalRateLimit {
			listenerFilters = append(listenerFilters, model.HTTPFilter{
				Name:     "envoy.filters.http.ratelimit",
				Priority: model.HTTPFilterPriorityRateLimit,
			})
		}

		// 5. Construct the final HTTPListener model for the Translator.
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
			Routes:         combinedRoutes,
			Filters:        listenerFilters, // Injected Dynamic Filters
			Infrastructure: infra,
			Service:        toServiceModel(input.GatewayClassConfig),
		})

		// 6. Handle TLS Passthrough (Layer 4) for TLS protocol listeners.
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
				Routes:         toTLSRoutes(l, listenerHostnamesByProtocol, input.TLSRoutes, input.Services, input.ServiceImports, input.ReferenceGrants),
				Infrastructure: infra,
				Service:        toServiceModel(input.GatewayClassConfig),
			})
		}
	}

	return resHTTP, resTLSPassthrough
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
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.HTTPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	btlspMap helpers.BackendTLSPolicyServiceMap,
    rateLimitPolicies []v2alpha1.CiliumRateLimitPolicy,
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

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allProtocolHostnames)
		// No matching host, skip this route
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}

		httpRoutes = append(httpRoutes, extractRoutes(log, int32(listener.Port), computedHost, r, services, serviceImports, grants, btlspMap,rateLimitPolicies)...)

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
	rateLimitPolicies []v2alpha1.CiliumRateLimitPolicy,

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
			}
		}



		perRouteFilterConfig := getRateLimitPerRouteConfig(hr, rateLimitPolicies)

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
				TypedPerFilterConfig:   perRouteFilterConfig, 
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
				TypedPerFilterConfig:   perRouteFilterConfig, 
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
	listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string,
	input []gatewayv1.GRPCRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1beta1.ServiceImport,
	grants []gatewayv1.ReferenceGrant,
	//Accept rate limit policies
	rateLimitPolicies []v2alpha1.CiliumRateLimitPolicy, 
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

		allProtocolHostnames := listenerHostnamesByProtocol[listener.Protocol]
		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allProtocolHostnames)
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}
		grpcRoutes = append(grpcRoutes, extractGRPCRoutes(computedHost, r, services, serviceImports, grants, rateLimitPolicies)...)
	}
	return grpcRoutes
}
func extractGRPCRoutes(hostnames []string, 
	grpcr gatewayv1.GRPCRoute, 
	services []corev1.Service, 
	serviceImports []mcsapiv1beta1.ServiceImport, 
	grants []gatewayv1.ReferenceGrant,
	rateLimitPolicies []v2alpha1.CiliumRateLimitPolicy, // NEW: Pass policies
) []model.HTTPRoute {
	var grpcRoutes []model.HTTPRoute
	
	// NEW: Resolve RateLimit configuration for this specific GRPCRoute
	perRouteFilterConfig, rateLimitActions := getRateLimitConfigs(grpcr.Name, grpcr.Namespace, "GRPCRoute", rateLimitPolicies)

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
				svc := getServiceSpec(string(f.RequestMirror.BackendRef.Name), helpers.NamespaceDerefOr(f.RequestMirror.BackendRef.Namespace, grpcr.Namespace), services)
				if svc != nil {
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(*svc, f.RequestMirror, grpcr.Namespace))
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
				TypedPerFilterConfig:   perRouteFilterConfig,
				RateLimitActions:       rateLimitActions,
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
				TypedPerFilterConfig:   perRouteFilterConfig,
				RateLimitActions:       rateLimitActions,
			})
		}
	}

	return grpcRoutes
}
func toTLSRoutes(listener gatewayv1beta1.Listener, listenerHostnamesByProtocol map[gatewayv1.ProtocolType][]string, input []gatewayv1.TLSRoute, services []corev1.Service, serviceImports []mcsapiv1beta1.ServiceImport, grants []gatewayv1.ReferenceGrant) []model.TLSPassthroughRoute {
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
func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}



func getRateLimitPerRouteConfig(hr metav1.Object, targetKind string, policies []v2alpha1.CiliumRateLimitPolicy) map[string]*anypb.Any {
	if len(policies) == 0 {
		return nil
	}

	perFilterConfig := make(map[string]*anypb.Any)

	for _, policy := range policies {
		// Policy Attachment: Match namespace, group, kind, and name
		if policy.Namespace == hr.GetNamespace() &&
			policy.Spec.TargetRef.Group == gatewayv1.Group(gatewayv1.GroupName) &&
			string(policy.Spec.TargetRef.Kind) == targetKind &&
			string(policy.Spec.TargetRef.Name) == hr.GetName() {

			if policy.Spec.Local != nil {
				localConfig := &envoy_extensions_filters_http_local_ratelimit_v3.LocalRateLimit{
					StatPrefix: "local_rate_limit",
				}
				if anyConfig, err := anypb.New(localConfig); err == nil {
					perFilterConfig["envoy.filters.http.local_ratelimit"] = anyConfig
				}
			}

			if policy.Spec.Global != nil {
				globalConfig := &envoy_extensions_filters_http_ratelimit_v3.RateLimitPerRoute{
					VhRateLimits: envoy_extensions_filters_http_ratelimit_v3.RateLimitPerRoute_INCLUDE_VH_RATE_LIMITS,
				}
				if anyConfig, err := anypb.New(globalConfig); err == nil {
					perFilterConfig["envoy.filters.http.ratelimit"] = anyConfig
				}
			}
			break
		}
	}

	if len(perFilterConfig) == 0 {
		return nil
	}
	return perFilterConfig
}

func getRateLimitPerRouteConfigForGRPC(grpcr gatewayv1.GRPCRoute, policies []v2alpha1.CiliumRateLimitPolicy) map[string]*anypb.Any {
	return getRateLimitPerRouteConfig(&grpcr, "GRPCRoute", policies)
}}

// getRateLimitConfigs searches for a CiliumRateLimitPolicy that targets a specific route (HTTP or GRPC)
// and returns the translated Envoy configuration for both Local and Global rate limiting.
func getRateLimitConfigs(name string, namespace string, kind string, policies []v2alpha1.CiliumRateLimitPolicy) (map[string]*anypb.Any, []model.RateLimitAction) {
	if len(policies) == 0 {
		return nil, nil
	}

	perFilterConfig := make(map[string]*anypb.Any)
	var actions []model.RateLimitAction

	for _, policy := range policies {
		// 1. Policy Attachment Logic: Ensure the policy is in the same namespace 
		// and targets the specific Route by Kind and Name.
		if policy.Namespace == namespace &&
			policy.Spec.TargetRef.Group == gatewayv1.Group(gatewayv1.GroupName) &&
			string(policy.Spec.TargetRef.Kind) == kind &&
			string(policy.Spec.TargetRef.Name) == name {

			// 2. Handle Local Rate Limiting (In-Memory)
			// Translates CRD fields into Envoy's TokenBucket algorithm.
			if policy.Spec.Local != nil {
				localProto := &envoy_extensions_filters_http_local_ratelimit_v3.LocalRateLimit{
					StatPrefix: "local_rate_limit",
				}

				if policy.Spec.Local.DefaultLimit != nil {
					reqs := policy.Spec.Local.DefaultLimit.Requests
					unit := policy.Spec.Local.DefaultLimit.Unit

					localProto.TokenBucket = &envoy_type_v3.TokenBucket{
						MaxTokens: reqs,
						FillInterval: &durationpb.Duration{
							Seconds: getSecondsForUnit(unit),
						},
						TokensPerFill: &wrapperspb.UInt32Value{Value: reqs},
					}
				}

				if anyConfig, err := anypb.New(localProto); err == nil {
					perFilterConfig["envoy.filters.http.local_ratelimit"] = anyConfig
				}
			}

			// 3. Handle Global Rate Limiting (External RLS)
			// Maps CRD actions to internal model actions for the Translator to process.
			if policy.Spec.Global != nil {
				// Signal Envoy to enable global rate limit for this route
				globalProto := &envoy_extensions_filters_http_ratelimit_v3.RateLimitPerRoute{
					VhRateLimits: envoy_extensions_filters_http_ratelimit_v3.RateLimitPerRoute_INCLUDE_VH_RATE_LIMITS,
				}
				if anyConfig, err := anypb.New(globalProto); err == nil {
					perFilterConfig["envoy.filters.http.ratelimit"] = anyConfig
				}

				// Deep copy actions from CRD to Internal Model
				for _, a := range policy.Spec.Global.Actions {
					modelAction := model.RateLimitAction{Type: a.Type}
					if a.RequestHeader != nil {
						modelAction.RequestHeader = &model.RequestHeaderAction{
							HeaderName:    a.RequestHeader.HeaderName,
							DescriptorKey: a.RequestHeader.DescriptorKey,
						}
					}
					if a.GenericKey != nil {
						modelAction.GenericKey = a.GenericKey
					}
					if a.HeaderValueMatch != nil {
						hvm := &model.HeaderValueMatchAction{
							DescriptorValue: a.HeaderValueMatch.DescriptorValue,
						}
						for _, h := range a.HeaderValueMatch.Headers {
							hvm.Headers = append(hvm.Headers, model.HeaderMatchCondition{
								Name:  h.Name,
								Value: h.Value,
							})
						}
						modelAction.HeaderValueMatch = hvm
					}
					actions = append(actions, modelAction)
				}
			}

			// Enforcement: Only the first matching policy of this type is applied.
			break
		}
	}

	if len(perFilterConfig) == 0 {
		return nil, nil
	}

	return perFilterConfig, actions
}

// getSecondsForUnit converts Gateway API time units to seconds.
func getSecondsForUnit(unit string) int64 {
	switch unit {
	case "Second":
		return 1
	case "Minute":
		return 60
	case "Hour":
		return 3600
	case "Day":
		return 86400
	default:
		return 60
	}
}
