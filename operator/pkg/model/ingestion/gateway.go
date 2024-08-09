// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	allHosts = "*"
)

// Input is the input for GatewayAPI.
type Input struct {
	GatewayClass    gatewayv1.GatewayClass
	Gateway         gatewayv1.Gateway
	HTTPRoutes      []gatewayv1.HTTPRoute
	TLSRoutes       []gatewayv1alpha2.TLSRoute
	GRPCRoutes      []gatewayv1.GRPCRoute
	ReferenceGrants []gatewayv1beta1.ReferenceGrant
	Services        []corev1.Service
	ServiceImports  []mcsapiv1alpha1.ServiceImport
}

// GatewayAPI translates Gateway API resources into a model.
// TODO(tam): Support GatewayClass
func GatewayAPI(input Input) ([]model.HTTPListener, []model.TLSPassthroughListener) {
	var resHTTP []model.HTTPListener
	var resTLSPassthrough []model.TLSPassthroughListener

	var labels, annotations map[string]string
	if input.Gateway.Spec.Infrastructure != nil {
		labels = toMapString(input.Gateway.Spec.Infrastructure.Labels)
		annotations = toMapString(input.Gateway.Spec.Infrastructure.Annotations)
	}

	var infra *model.Infrastructure
	if labels != nil || annotations != nil {
		infra = &model.Infrastructure{
			Labels:      labels,
			Annotations: annotations,
		}
	}

	// Find all the listener host names, so that we can match them with the routes
	// Gateway API spec guarantees that the hostnames are unique across all listeners
	var allListenerHostNames []string
	for _, l := range input.Gateway.Spec.Listeners {
		if l.Hostname != nil {
			allListenerHostNames = append(allListenerHostNames, toHostname(l.Hostname))
		}
	}

	for _, l := range input.Gateway.Spec.Listeners {
		if l.Protocol != gatewayv1.HTTPProtocolType &&
			l.Protocol != gatewayv1.HTTPSProtocolType &&
			l.Protocol != gatewayv1.TLSProtocolType {
			continue
		}

		var httpRoutes []model.HTTPRoute
		httpRoutes = append(httpRoutes, toHTTPRoutes(l, allListenerHostNames, input.HTTPRoutes, input.Services, input.ServiceImports, input.ReferenceGrants)...)
		httpRoutes = append(httpRoutes, toGRPCRoutes(l, allListenerHostNames, input.GRPCRoutes, input.Services, input.ServiceImports, input.ReferenceGrants)...)
		resHTTP = append(resHTTP, model.HTTPListener{
			Name: string(l.Name),
			Sources: []model.FullyQualifiedResource{
				{
					Name:      input.Gateway.GetName(),
					Namespace: input.Gateway.GetNamespace(),
					Group:     input.Gateway.GroupVersionKind().Group,
					Version:   input.Gateway.GroupVersionKind().Version,
					Kind:      input.Gateway.GroupVersionKind().Kind,
					UID:       string(input.Gateway.GetUID()),
				},
			},
			Port:           uint32(l.Port),
			Hostname:       toHostname(l.Hostname),
			TLS:            toTLS(l.TLS, input.ReferenceGrants, input.Gateway.GetNamespace()),
			Routes:         httpRoutes,
			Infrastructure: infra,
		})

		resTLSPassthrough = append(resTLSPassthrough, model.TLSPassthroughListener{
			Name: string(l.Name),
			Sources: []model.FullyQualifiedResource{
				{
					Name:      input.Gateway.GetName(),
					Namespace: input.Gateway.GetNamespace(),
					Group:     input.Gateway.GroupVersionKind().Group,
					Version:   input.Gateway.GroupVersionKind().Version,
					Kind:      input.Gateway.GroupVersionKind().Kind,
					UID:       string(input.Gateway.GetUID()),
				},
			},
			Port:           uint32(l.Port),
			Hostname:       toHostname(l.Hostname),
			Routes:         toTLSRoutes(l, allListenerHostNames, input.TLSRoutes, input.Services, input.ServiceImports, input.ReferenceGrants),
			Infrastructure: infra,
		})
	}

	return resHTTP, resTLSPassthrough
}

func getBackendServiceName(namespace string, services []corev1.Service, serviceImports []mcsapiv1alpha1.ServiceImport, backendObjectReference gatewayv1.BackendObjectReference) (string, error) {
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

func toHTTPRoutes(listener gatewayv1.Listener,
	allListenerHostNames []string,
	input []gatewayv1.HTTPRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1alpha1.ServiceImport,
	grants []gatewayv1beta1.ReferenceGrant) []model.HTTPRoute {
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

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allListenerHostNames)
		// No matching host, skip this route
		if len(computedHost) == 0 {
			continue
		}

		if len(computedHost) == 1 && computedHost[0] == allHosts {
			computedHost = nil
		}

		httpRoutes = append(httpRoutes, extractRoutes(int32(listener.Port), computedHost, r, services, serviceImports, grants)...)

	}
	return httpRoutes
}

func extractRoutes(listenerPort int32, hostnames []string, hr gatewayv1.HTTPRoute, services []corev1.Service, serviceImports []mcsapiv1alpha1.ServiceImport, grants []gatewayv1beta1.ReferenceGrant) []model.HTTPRoute {
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
				bes = append(bes, backendToModelBackend(*svc, be.BackendRef, hr.Namespace))
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
				Timeout:                toTimeout(rule.Timeouts),
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
				Timeout:                toTimeout(rule.Timeouts),
			})
		}
	}
	return httpRoutes
}

func toTimeout(timeouts *gatewayv1.HTTPRouteTimeouts) model.Timeout {
	res := model.Timeout{}
	if timeouts == nil {
		return res
	}
	if timeouts.BackendRequest != nil {
		if duration, err := time.ParseDuration(string(*timeouts.BackendRequest)); err == nil {
			res.Backend = model.AddressOf(duration)
		}
	}
	if timeouts.Request != nil {
		if duration, err := time.ParseDuration(string(*timeouts.Request)); err == nil {
			res.Request = model.AddressOf(duration)
		}
	}
	return res
}

func toGRPCRoutes(listener gatewayv1beta1.Listener,
	allListenerHostNames []string,
	input []gatewayv1.GRPCRoute,
	services []corev1.Service,
	serviceImports []mcsapiv1alpha1.ServiceImport,
	grants []gatewayv1beta1.ReferenceGrant) []model.HTTPRoute {
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

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allListenerHostNames)
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
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be.BackendRef, gatewayv1beta1.SchemeGroupVersion.WithKind("GRPCRoute"), grants) {
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
				if be.BackendRef.Port == nil {
					// must have port for Service reference
					continue
				}
				svc := getServiceSpec(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services)
				if svc != nil {
					bes = append(bes, backendToModelBackend(*svc, be.BackendRef, r.Namespace))
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
					svc := getServiceSpec(string(f.RequestMirror.BackendRef.Name), helpers.NamespaceDerefOr(f.RequestMirror.BackendRef.Namespace, r.Namespace), services)
					if svc != nil {
						requestMirrors = append(requestMirrors, toHTTPRequestMirror(*svc, f.RequestMirror, r.Namespace))
					}
				}
			}

			if len(rule.Matches) == 0 {
				grpcRoutes = append(grpcRoutes, model.HTTPRoute{
					Hostnames:              computedHost,
					Backends:               bes,
					DirectResponse:         dr,
					RequestHeaderFilter:    requestHeaderFilter,
					ResponseHeaderModifier: responseHeaderFilter,
					RequestMirrors:         requestMirrors,
				})
			}

			for _, match := range rule.Matches {
				grpcRoutes = append(grpcRoutes, model.HTTPRoute{
					Hostnames:              computedHost,
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
	}
	return grpcRoutes
}

func toTLSRoutes(listener gatewayv1beta1.Listener, allListenerHostNames []string, input []gatewayv1alpha2.TLSRoute, services []corev1.Service, serviceImports []mcsapiv1alpha1.ServiceImport, grants []gatewayv1beta1.ReferenceGrant) []model.TLSPassthroughRoute {
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

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname), allListenerHostNames)
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
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be, gatewayv1alpha2.SchemeGroupVersion.WithKind("TLSRoute"), grants) {
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
			redirectPort = model.AddressOf(listenerPort)
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

func toHTTPRequestMirror(svc corev1.Service, mirror *gatewayv1.HTTPRequestMirrorFilter, ns string) *model.HTTPRequestMirror {
	return &model.HTTPRequestMirror{
		Backend: model.AddressOf(backendRefToModelBackend(svc, mirror.BackendRef, ns)),
	}
}

func toHostname(hostname *gatewayv1.Hostname) string {
	if hostname != nil {
		return (string)(*hostname)
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

func getServiceImport(svcName, svcNamespace string, serviceImports []mcsapiv1alpha1.ServiceImport) *mcsapiv1alpha1.ServiceImport {
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
	if match.Method == nil || match.Method.Service == nil {
		return model.StringMatch{}
	}

	t := gatewayv1.GRPCMethodMatchExact
	if match.Method.Type != nil {
		t = *match.Method.Type
	}

	path := ""
	if match.Method.Service != nil {
		path = path + "/" + *match.Method.Service
	}

	if match.Method.Method != nil {
		path = path + "/" + *match.Method.Method
	}

	switch t {
	case gatewayv1.GRPCMethodMatchExact:
		return model.StringMatch{
			Exact: path,
		}
	case gatewayv1.GRPCMethodMatchRegularExpression:
		return model.StringMatch{
			Regex: path,
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

func toTLS(tls *gatewayv1.GatewayTLSConfig, grants []gatewayv1beta1.ReferenceGrant, defaultNamespace string) []model.TLSSecret {
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

func toMapString(in map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

func toStringSlice(s []gatewayv1.Hostname) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}
