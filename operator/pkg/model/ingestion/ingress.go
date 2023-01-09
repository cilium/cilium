// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"fmt"
	"sort"

	"github.com/cilium/cilium/operator/pkg/ingress/annotations"
	"github.com/cilium/cilium/operator/pkg/model"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Ingress translates an Ingress resource to a HTTPListener.
// This function does not check IngressClass (via field or annotation).
// It's expected that only relevant Ingresses will have this function called on them.
func Ingress(ing slim_networkingv1.Ingress) []model.HTTPListener {

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
				}},
			Port:    80,
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
		l.Port = 80
		l.Sources = model.AddSource(l.Sources, sourceResource)
		if !ok {
			l.Name = fmt.Sprintf("ing-%s-%s-%s", ing.Name, ing.Namespace, host)
		}

		l.Hostname = host
		for _, path := range rule.HTTP.Paths {

			route := model.HTTPRoute{}

			switch *path.PathType {
			case slim_networkingv1.PathTypeExact:
				route.PathMatch.Exact = path.Path
			case slim_networkingv1.PathTypePrefix:
				route.PathMatch.Prefix = path.Path
			case slim_networkingv1.PathTypeImplementationSpecific:
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

			}
			l.Port = 443
			l.Hostname = host
			l.Service = getService(ing)
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
				}
				defaultListener.Hostname = host
				defaultListener.Port = 443
				secureListenerMap[host] = defaultListener

			}
		}

	}

	listenerSlice := make([]model.HTTPListener, 0, len(insecureListenerMap)+len(secureListenerMap))
	listenerSlice = appendValuesInKeyOrder(insecureListenerMap, listenerSlice)
	listenerSlice = appendValuesInKeyOrder(secureListenerMap, listenerSlice)

	return listenerSlice

}

func getService(ing slim_networkingv1.Ingress) *model.Service {
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
func appendValuesInKeyOrder(listenerMap map[string]model.HTTPListener, appendSlice []model.HTTPListener) []model.HTTPListener {

	var keys []string

	for key := range listenerMap {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	for _, key := range keys {
		appendSlice = append(appendSlice, listenerMap[key])
	}

	return appendSlice
}
