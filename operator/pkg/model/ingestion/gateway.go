// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	corev1 "k8s.io/api/core/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	allHosts = "*"
)

// Input is the input for GatewayAPI.
type Input struct {
	GatewayClass    gatewayv1beta1.GatewayClass
	Gateway         gatewayv1beta1.Gateway
	HTTPRoutes      []gatewayv1beta1.HTTPRoute
	TLSRoutes       []gatewayv1alpha2.TLSRoute
	ReferenceGrants []gatewayv1beta1.ReferenceGrant
	Services        []corev1.Service
}

// GatewayAPI translates Gateway API resources into a model.
// TODO(tam): Support GatewayClass
func GatewayAPI(input Input) ([]model.HTTPListener, []model.TLSListener) {
	var resHTTP []model.HTTPListener
	var resTLS []model.TLSListener

	for _, l := range input.Gateway.Spec.Listeners {
		if l.Protocol != gatewayv1beta1.HTTPProtocolType &&
			l.Protocol != gatewayv1beta1.HTTPSProtocolType &&
			l.Protocol != gatewayv1beta1.TLSProtocolType {
			continue
		}

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
			Port:     uint32(l.Port),
			Hostname: toHostname(l.Hostname),
			TLS:      toTLS(l.TLS, input.ReferenceGrants, input.Gateway.GetNamespace()),
			Routes:   toHTTPRoutes(l, input.HTTPRoutes, input.Services, input.ReferenceGrants),
		})

		resTLS = append(resTLS, model.TLSListener{
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
			Port:     uint32(l.Port),
			Hostname: toHostname(l.Hostname),
			Routes:   toTLSRoutes(l, input.TLSRoutes, input.Services, input.ReferenceGrants),
		})
	}

	return resHTTP, resTLS
}

func toHTTPRoutes(listener gatewayv1beta1.Listener, input []gatewayv1beta1.HTTPRoute, services []corev1.Service, grants []gatewayv1beta1.ReferenceGrant) []model.HTTPRoute {
	var httpRoutes []model.HTTPRoute
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

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname))
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
				if !helpers.IsBackendReferenceAllowed(r.GetNamespace(), be.BackendRef, gatewayv1beta1.SchemeGroupVersion.WithKind("HTTPRoute"), grants) {
					continue
				}
				if (be.Kind != nil && *be.Kind != "Service") || (be.Group != nil && *be.Group != corev1.GroupName) {
					continue
				}
				if be.BackendRef.Port == nil {
					// must have port for Service reference
					continue
				}
				if serviceExists(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services) {
					bes = append(bes, backendToModelBackend(be.BackendRef, r.Namespace))
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
				case gatewayv1beta1.HTTPRouteFilterRequestHeaderModifier:
					requestHeaderFilter = &model.HTTPHeaderFilter{
						HeadersToAdd:    toHTTPHeaders(f.RequestHeaderModifier.Add),
						HeadersToSet:    toHTTPHeaders(f.RequestHeaderModifier.Set),
						HeadersToRemove: f.RequestHeaderModifier.Remove,
					}
				case gatewayv1beta1.HTTPRouteFilterResponseHeaderModifier:
					responseHeaderFilter = &model.HTTPHeaderFilter{
						HeadersToAdd:    toHTTPHeaders(f.ResponseHeaderModifier.Add),
						HeadersToSet:    toHTTPHeaders(f.ResponseHeaderModifier.Set),
						HeadersToRemove: f.ResponseHeaderModifier.Remove,
					}
				case gatewayv1beta1.HTTPRouteFilterRequestRedirect:
					requestRedirectFilter = toHTTPRequestRedirectFilter(f.RequestRedirect)
				case gatewayv1beta1.HTTPRouteFilterURLRewrite:
					rewriteFilter = toHTTPRewriteFilter(f.URLRewrite)
				case gatewayv1beta1.HTTPRouteFilterRequestMirror:
					requestMirrors = append(requestMirrors, toHTTPRequestMirror(f.RequestMirror, r.Namespace))
				}
			}

			if len(rule.Matches) == 0 {
				httpRoutes = append(httpRoutes, model.HTTPRoute{
					Hostnames:              computedHost,
					Backends:               bes,
					DirectResponse:         dr,
					RequestHeaderFilter:    requestHeaderFilter,
					ResponseHeaderModifier: responseHeaderFilter,
					RequestRedirect:        requestRedirectFilter,
					Rewrite:                rewriteFilter,
					RequestMirrors:         requestMirrors,
				})
			}

			for _, match := range rule.Matches {
				httpRoutes = append(httpRoutes, model.HTTPRoute{
					Hostnames:              computedHost,
					PathMatch:              toPathMatch(match),
					HeadersMatch:           toHeaderMatch(match),
					QueryParamsMatch:       toQueryMatch(match),
					Method:                 (*string)(match.Method),
					Backends:               bes,
					DirectResponse:         dr,
					RequestHeaderFilter:    requestHeaderFilter,
					ResponseHeaderModifier: responseHeaderFilter,
					RequestRedirect:        requestRedirectFilter,
					Rewrite:                rewriteFilter,
					RequestMirrors:         requestMirrors,
				})
			}
		}
	}
	return httpRoutes
}

func toTLSRoutes(listener gatewayv1beta1.Listener, input []gatewayv1alpha2.TLSRoute, services []corev1.Service, grants []gatewayv1beta1.ReferenceGrant) []model.TLSRoute {
	var tlsRoutes []model.TLSRoute
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

		computedHost := model.ComputeHosts(toStringSlice(r.Spec.Hostnames), (*string)(listener.Hostname))
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
				if (be.Kind != nil && *be.Kind != "Service") || (be.Group != nil && *be.Group != corev1.GroupName) {
					continue
				}
				if serviceExists(string(be.Name), helpers.NamespaceDerefOr(be.Namespace, r.Namespace), services) {
					bes = append(bes, backendToModelBackend(be, r.Namespace))
				}
			}

			tlsRoutes = append(tlsRoutes, model.TLSRoute{
				Hostnames: computedHost,
				Backends:  bes,
			})

		}
	}
	return tlsRoutes
}

func toHTTPRequestRedirectFilter(redirect *gatewayv1beta1.HTTPRequestRedirectFilter) *model.HTTPRequestRedirectFilter {
	if redirect == nil {
		return nil
	}
	var pathModifier *model.StringMatch
	if redirect.Path != nil {
		pathModifier = &model.StringMatch{}

		switch redirect.Path.Type {
		case gatewayv1beta1.FullPathHTTPPathModifier:
			pathModifier.Exact = *redirect.Path.ReplaceFullPath
		case gatewayv1beta1.PrefixMatchHTTPPathModifier:
			pathModifier.Prefix = *redirect.Path.ReplacePrefixMatch
		}
	}
	return &model.HTTPRequestRedirectFilter{
		Scheme:     redirect.Scheme,
		Hostname:   (*string)(redirect.Hostname),
		Path:       pathModifier,
		Port:       (*int32)(redirect.Port),
		StatusCode: redirect.StatusCode,
	}
}

func toHTTPRewriteFilter(rewrite *gatewayv1beta1.HTTPURLRewriteFilter) *model.HTTPURLRewriteFilter {
	if rewrite == nil {
		return nil
	}
	var path *model.StringMatch
	if rewrite.Path != nil {
		switch rewrite.Path.Type {
		case gatewayv1beta1.FullPathHTTPPathModifier:
			if rewrite.Path.ReplaceFullPath != nil {
				path = &model.StringMatch{
					Exact: *rewrite.Path.ReplaceFullPath,
				}
			}
		case gatewayv1beta1.PrefixMatchHTTPPathModifier:
			if rewrite.Path.ReplacePrefixMatch != nil {
				path = &model.StringMatch{
					Prefix: *rewrite.Path.ReplacePrefixMatch,
				}
			}
		}
	}
	return &model.HTTPURLRewriteFilter{
		HostName: (*string)(rewrite.Hostname),
		Path:     path,
	}
}

func toHTTPRequestMirror(mirror *gatewayv1beta1.HTTPRequestMirrorFilter, ns string) *model.HTTPRequestMirror {
	return &model.HTTPRequestMirror{
		Backend: model.AddressOf(backendRefToModelBackend(mirror.BackendRef, ns)),
	}
}

func toHostname(hostname *gatewayv1beta1.Hostname) string {
	if hostname != nil {
		return (string)(*hostname)
	}
	return allHosts
}

func serviceExists(svcName, svcNamespace string, services []corev1.Service) bool {
	for _, svc := range services {
		if svc.GetName() == svcName && svc.GetNamespace() == svcNamespace {
			return true
		}
	}
	return false
}

func backendToModelBackend(be gatewayv1beta1.BackendRef, defaultNamespace string) model.Backend {
	res := backendRefToModelBackend(be.BackendObjectReference, defaultNamespace)
	res.Weight = be.Weight
	return res
}

func backendRefToModelBackend(be gatewayv1beta1.BackendObjectReference, defaultNamespace string) model.Backend {
	ns := helpers.NamespaceDerefOr(be.Namespace, defaultNamespace)
	var port *model.BackendPort

	if be.Port != nil {
		port = &model.BackendPort{
			Port: uint32(*be.Port),
		}
	}

	return model.Backend{
		Name:      string(be.Name),
		Namespace: ns,
		Port:      port,
	}
}

func toPathMatch(match gatewayv1beta1.HTTPRouteMatch) model.StringMatch {
	if match.Path == nil {
		return model.StringMatch{}
	}

	switch *match.Path.Type {
	case gatewayv1beta1.PathMatchExact:
		return model.StringMatch{
			Exact: *match.Path.Value,
		}
	case gatewayv1beta1.PathMatchPathPrefix:
		return model.StringMatch{
			Prefix: *match.Path.Value,
		}
	case gatewayv1beta1.PathMatchRegularExpression:
		return model.StringMatch{
			Regex: *match.Path.Value,
		}
	}
	return model.StringMatch{}
}

func toHeaderMatch(match gatewayv1beta1.HTTPRouteMatch) []model.KeyValueMatch {
	if len(match.Headers) == 0 {
		return nil
	}
	res := make([]model.KeyValueMatch, 0, len(match.Headers))
	for _, h := range match.Headers {
		t := gatewayv1beta1.HeaderMatchExact
		if h.Type != nil {
			t = *h.Type
		}
		switch t {
		case gatewayv1beta1.HeaderMatchExact:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Exact: h.Value,
				},
			})
		case gatewayv1beta1.HeaderMatchRegularExpression:
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

func toQueryMatch(match gatewayv1beta1.HTTPRouteMatch) []model.KeyValueMatch {
	if len(match.QueryParams) == 0 {
		return nil
	}
	res := make([]model.KeyValueMatch, 0, len(match.QueryParams))
	for _, h := range match.QueryParams {
		t := gatewayv1beta1.QueryParamMatchExact
		if h.Type != nil {
			t = *h.Type
		}
		switch t {
		case gatewayv1beta1.QueryParamMatchExact:
			res = append(res, model.KeyValueMatch{
				Key: string(h.Name),
				Match: model.StringMatch{
					Exact: h.Value,
				},
			})
		case gatewayv1beta1.QueryParamMatchRegularExpression:
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

func toTLS(tls *gatewayv1beta1.GatewayTLSConfig, grants []gatewayv1beta1.ReferenceGrant, defaultNamespace string) []model.TLSSecret {
	if tls == nil {
		return nil
	}

	res := make([]model.TLSSecret, 0, len(tls.CertificateRefs))
	for _, cert := range tls.CertificateRefs {
		if !helpers.IsSecretReferenceAllowed(defaultNamespace, cert, gatewayv1beta1.SchemeGroupVersion.WithKind("Gateway"), grants) {
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

func toHTTPHeaders(headers []gatewayv1beta1.HTTPHeader) []model.Header {
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

func toStringSlice(s []gatewayv1beta1.Hostname) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}
