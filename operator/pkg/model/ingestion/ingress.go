// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Ingress translates an Ingress resource to a HTTPListener.
// This function does not check IngressClass (via field or annotation).
// It's expected that only relevant Ingresses will have this function called on them.
func Ingress(ing networkingv1.Ingress, defaultSecretNamespace, defaultSecretName string, enforcedHTTPS bool, insecureListenerPort, secureListenerPort uint32, defaultRequestTimeout time.Duration) []model.HTTPListener {
	// First, we make a map of HTTPListeners, with the hostname
	// as the key, so that we can make sure we match up any
	// TLS config with rules that match it.
	// This is to approximate a set, keyed by hostname, so we can
	// coalesce the config from a single Ingress.
	// Coalescing the config from multiple Ingress resources is left for
	// the transform component that takes a model and outputs CiliumEnvoyConfig
	// or other resources.
	insecureListenerMap := make(map[string]model.HTTPListener)

	sourceResource := model.FullyQualifiedResource{
		Name:      ing.Name,
		Namespace: ing.Namespace,
		Group:     "",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       string(ing.UID),
	}

	// Setup timeout for use in all routes
	timeout := model.Timeout{}
	if defaultRequestTimeout != 0 {
		timeout.Request = ptr.To(defaultRequestTimeout)
	}
	if v, err := annotations.GetAnnotationRequestTimeout(&ing); err != nil {
		// If the annotation is invalid, we log a warning and use the default value
		log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
			Warn("Invalid request timeout annotation, using default value")
	} else if v != nil {
		timeout.Request = ptr.To(*v)
	}

	if ing.Spec.DefaultBackend != nil {
		// There's a default backend set up

		// get the details for the default backend

		backend := model.Backend{}
		backend.Name = ing.Spec.DefaultBackend.Service.Name
		backend.Namespace = ing.Namespace

		backend.Port = &model.BackendPort{}

		if ing.Spec.DefaultBackend.Service.Port.Name != "" {
			backend.Port.Name = ing.Spec.DefaultBackend.Service.Port.Name
		}

		if ing.Spec.DefaultBackend.Service.Port.Number != 0 {
			backend.Port.Port = uint32(ing.Spec.DefaultBackend.Service.Port.Number)
		}

		l := model.HTTPListener{
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Backends: []model.Backend{
						backend,
					},
					Timeout: timeout,
				},
			},
			Port:    insecureListenerPort,
			Service: getService(ing),
		}

		l.Sources = model.AddSource(l.Sources, sourceResource)

		insecureListenerMap["*"] = l
	}

	// Now, we range across the rules, adding them in as listeners.
	for _, rule := range ing.Spec.Rules {

		host := "*"

		if rule.Host != "" {
			host = rule.Host
		}

		l, ok := insecureListenerMap[host]
		l.Port = insecureListenerPort
		l.Sources = model.AddSource(l.Sources, sourceResource)
		if !ok {
			l.Name = "ing-" + ing.Name + "-" + ing.Namespace + "-" + host
		}

		l.Hostname = host
		if rule.HTTP == nil {
			log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
				Warn("Invalid Ingress rule without spec.rules.HTTP defined, skipping rule")
			continue
		}

		for _, path := range rule.HTTP.Paths {

			route := model.HTTPRoute{
				Timeout: timeout,
			}

			switch *path.PathType {
			case networkingv1.PathTypeExact:
				route.PathMatch.Exact = path.Path
			case networkingv1.PathTypePrefix:
				route.PathMatch.Prefix = path.Path
			case networkingv1.PathTypeImplementationSpecific:
				route.PathMatch.Regex = path.Path
			}

			backend := model.Backend{
				Name:      path.Backend.Service.Name,
				Namespace: ing.Namespace,
			}
			if path.Backend.Service != nil {
				backend.Port = &model.BackendPort{}
				if path.Backend.Service.Port.Name != "" {
					backend.Port.Name = path.Backend.Service.Port.Name
				}
				if path.Backend.Service.Port.Number != 0 {
					backend.Port.Port = uint32(path.Backend.Service.Port.Number)
				}
			}
			route.Backends = append(route.Backends, backend)
			l.Routes = append(l.Routes, route)
			l.Service = getService(ing)
		}

		insecureListenerMap[host] = l
	}

	secureListenerMap := make(map[string]model.HTTPListener)

	// Before we check for TLS config, we need to see if the force-https annotation
	// is set.
	forceHTTPsannotation := annotations.GetAnnotationForceHTTPSEnabled(&ing)
	forceHTTPs := false

	// We only care about enforcedHTTPS if the annotation is unset
	if (forceHTTPsannotation == nil && enforcedHTTPS) || (forceHTTPsannotation != nil && *forceHTTPsannotation) {
		forceHTTPs = true
	}

	// First, we check for TLS config, and set them up with Listeners to return.
	for _, tlsConfig := range ing.Spec.TLS {
		for _, host := range tlsConfig.Hosts {

			l, ok := secureListenerMap[host]
			if !ok {
				l, ok = insecureListenerMap[host]
				if !ok {
					l, ok = insecureListenerMap["*"]
					if !ok {
						continue
					}
				}
			}

			if tlsConfig.SecretName != "" {
				l.TLS = []model.TLSSecret{
					{
						Name: tlsConfig.SecretName,
						// Secret has to be in the same namespace as the Ingress.
						Namespace: ing.Namespace,
					},
				}
			} else if defaultSecretNamespace != "" && defaultSecretName != "" {
				l.TLS = []model.TLSSecret{
					{
						Name:      defaultSecretName,
						Namespace: defaultSecretNamespace,
					},
				}
			}

			l.Port = secureListenerPort
			l.Hostname = host
			l.Service = getService(ing)
			l.ForceHTTPtoHTTPSRedirect = forceHTTPs
			secureListenerMap[host] = l

			defaultListener, ok := insecureListenerMap["*"]
			if ok {
				// A default listener already exists, each Host in TLSConfig.Hosts
				// needs to have a Listener configured that's a copy of it.
				if tlsConfig.SecretName != "" {
					defaultListener.TLS = []model.TLSSecret{
						{
							Name: tlsConfig.SecretName,
							// Secret has to be in the same namespace as the Ingress.
							Namespace: ing.Namespace,
						},
					}
				} else if defaultSecretNamespace != "" && defaultSecretName != "" {
					defaultListener.TLS = []model.TLSSecret{
						{
							Name:      defaultSecretName,
							Namespace: defaultSecretNamespace,
						},
					}
				}
				defaultListener.Hostname = host
				defaultListener.Port = secureListenerPort
				secureListenerMap[host] = defaultListener

			}
		}
	}

	listenerSlice := make([]model.HTTPListener, 0, len(insecureListenerMap)+len(secureListenerMap))
	listenerSlice = appendValuesInKeyOrder(insecureListenerMap, listenerSlice)
	listenerSlice = appendValuesInKeyOrder(secureListenerMap, listenerSlice)

	return listenerSlice
}

// IngressPassthrough translates an Ingress resource with the tls-passthrough annotation to a TLSListener.
// This function does not check IngressClass (via field or annotation).
// It's expected that only relevant Ingresses will have this function called on them.
//
// Ingress objects with SSL Passthrough enabled have the following properties:
//
// * must have a host set
// * rules with paths other than '/' are ignored
// * default backends are ignored
func IngressPassthrough(ing networkingv1.Ingress, listenerPort uint32) []model.TLSPassthroughListener {
	// First, we make a map of TLSListeners, with the hostname
	// as the key, so that we can make sure we match up any
	// TLS config with rules that match it.
	// This is to approximate a set, keyed by hostname, so we can
	// coalesce the config from a single Ingress.
	// Coalescing the config from multiple Ingress resources is left for
	// the transform component that takes a model and outputs CiliumEnvoyConfig
	// or other resources.
	tlsListenerMap := make(map[string]model.TLSPassthroughListener)

	sourceResource := model.FullyQualifiedResource{
		Name:      ing.Name,
		Namespace: ing.Namespace,
		Group:     "",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       string(ing.UID),
	}

	// Note that there's no support for default backends in SSL Passthrough
	// mode.
	if ing.Spec.DefaultBackend != nil {
		log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
			Warn("Invalid SSL Passthrough Ingress rule with a default backend, skipping default backend config")
	}

	// Now, we range across the rules, adding them in as listeners.
	for _, rule := range ing.Spec.Rules {

		// SSL Passthrough Ingress objects must have a host set.
		if rule.Host == "" {
			log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
				Warn("Invalid SSL Passthrough Ingress rule without spec.rules.host defined, skipping rule")
			continue
		}

		host := rule.Host

		l, ok := tlsListenerMap[host]
		l.Port = listenerPort
		l.Sources = model.AddSource(l.Sources, sourceResource)
		if !ok {
			l.Name = "ing-" + ing.Name + "-" + ing.Namespace + "-" + host
		}

		l.Hostname = host

		if rule.HTTP == nil {
			log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
				Warn("Invalid SSL Passthrough Ingress rule without spec.rules.HTTP defined, skipping rule")
			continue
		}

		for _, path := range rule.HTTP.Paths {
			// SSL Passthrough objects must only have path of '/'
			if path.Path != "/" {
				log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
					Warn("Invalid SSL Passthrough Ingress rule with path not equal to '/', skipping rule")
				continue
			}

			route := model.TLSPassthroughRoute{
				Hostnames: []string{
					host,
				},
			}

			backend := model.Backend{
				Name:      path.Backend.Service.Name,
				Namespace: ing.Namespace,
			}
			if path.Backend.Service != nil {
				backend.Port = &model.BackendPort{}
				if path.Backend.Service.Port.Name != "" {
					backend.Port.Name = path.Backend.Service.Port.Name
				}
				if path.Backend.Service.Port.Number != 0 {
					backend.Port.Port = uint32(path.Backend.Service.Port.Number)
				}
			}
			route.Backends = append(route.Backends, backend)
			l.Routes = append(l.Routes, route)
			l.Service = getService(ing)
		}

		// If there aren't any routes, then don't add the Listener
		if len(l.Routes) == 0 {
			log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name).
				Warn("Invalid SSL Passthrough Ingress with no valid rules, skipping")
			continue
		}

		tlsListenerMap[host] = l
	}

	listenerSlice := make([]model.TLSPassthroughListener, 0, len(tlsListenerMap))
	listenerSlice = appendValuesInKeyOrder(tlsListenerMap, listenerSlice)

	return listenerSlice
}

func getService(ing networkingv1.Ingress) *model.Service {
	if annotations.GetAnnotationServiceType(&ing) != string(corev1.ServiceTypeNodePort) {
		return nil
	}

	m := &model.Service{
		Type: string(corev1.ServiceTypeNodePort),
	}
	scopedLog := log.WithField(logfields.Ingress, ing.Namespace+"/"+ing.Name)
	secureNodePort, err := annotations.GetAnnotationSecureNodePort(&ing)
	if err != nil {
		scopedLog.WithError(err).Warn("Invalid secure node port annotation, random port will be used")
	} else {
		m.SecureNodePort = secureNodePort
	}

	insureNodePort, err := annotations.GetAnnotationInsecureNodePort(&ing)
	if err != nil {
		scopedLog.WithError(err).Warn("Invalid insecure node port annotation, random port will be used")
	} else {
		m.InsecureNodePort = insureNodePort
	}

	return m
}

// appendValuesInKeyOrder ensures that the slice of listeners is stably sorted by
// appending the values of the map in order of the keys to the appendSlice.
func appendValuesInKeyOrder[T model.HTTPListener | model.TLSPassthroughListener](listenerMap map[string]T, appendSlice []T) []T {
	var keys []string

	for key := range listenerMap {
		keys = append(keys, key)
	}

	slices.Sort(keys)
	for _, key := range keys {
		appendSlice = append(appendSlice, listenerMap[key])
	}

	return appendSlice
}
