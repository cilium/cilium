// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"sort"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	secureHost   = "secure"
	insecureHost = "insecure"
)

var _ Translator = (*defaultTranslator)(nil)

// defaultTranslator is the translator from model to CiliumEnvoyConfig
//
// This translator is used for shared LB mode.
//   - only one instance of CiliumEnvoyConfig with two listeners (secure and
//     in-secure).
//   - no LB service and endpoint
type defaultTranslator struct {
	name             string
	namespace        string
	secretsNamespace string
	enforceHTTPs     bool

	// hostNameSuffixMatch is a flag to control whether the host name suffix match.
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	hostNameSuffixMatch bool
}

// NewTranslator returns a new translator
func NewTranslator(name, namespace, secretsNamespace string, enforceHTTPs bool, hostNameSuffixMatch bool) Translator {
	return &defaultTranslator{
		name:                name,
		namespace:           namespace,
		secretsNamespace:    secretsNamespace,
		enforceHTTPs:        enforceHTTPs,
		hostNameSuffixMatch: hostNameSuffixMatch,
	}
}

// Translate translates the model to CiliumEnvoyConfig.
func (i *defaultTranslator) Translate(model *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	cec := &ciliumv2.CiliumEnvoyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      i.name,
			Namespace: i.namespace,
		},
	}

	cec.Spec.BackendServices = i.getBackendServices(model)
	cec.Spec.Services = i.getServices(model)
	cec.Spec.Resources = i.getResources(model)

	ownerReferences := make([]metav1.OwnerReference, 0, len(model.HTTP))
	uniqueMap := map[string]struct{}{}
	for _, h := range model.HTTP {
		key := fmt.Sprintf("%s/%s/%s", h.Sources[0].Version, h.Sources[0].Kind, h.Sources[0].Name)
		if _, exists := uniqueMap[key]; exists {
			continue
		}
		uniqueMap[key] = struct{}{}
		ownerReferences = append(ownerReferences, metav1.OwnerReference{
			APIVersion: h.Sources[0].Version,
			Kind:       h.Sources[0].Kind,
			Name:       h.Sources[0].Name,
			UID:        types.UID(h.Sources[0].UID),
		})
	}
	cec.OwnerReferences = ownerReferences
	return cec, nil, nil, nil
}

func (i *defaultTranslator) getBackendServices(m *model.Model) []*ciliumv2.Service {
	var res []*ciliumv2.Service

	for ns, v := range getNamespaceNamePortsMap(m) {
		for name, ports := range v {
			res = append(res, &ciliumv2.Service{
				Name:      name,
				Namespace: ns,
				Ports:     ports,
			})
		}
	}

	// Make sure the result is sorted by namespace and name to avoid any
	// nondeterministic behavior.
	sort.Slice(res, func(i, j int) bool {
		if res[i].Namespace != res[j].Namespace {
			return res[i].Namespace < res[j].Namespace
		}
		if res[i].Name != res[j].Name {
			return res[i].Name < res[j].Name
		}
		return res[i].Ports[0] < res[j].Ports[0]
	})
	return res
}

func (i *defaultTranslator) getServices(_ *model.Model) []*ciliumv2.ServiceListener {
	return []*ciliumv2.ServiceListener{
		{
			Name:      i.name,
			Namespace: i.namespace,
		},
	}
}

func (i *defaultTranslator) getResources(m *model.Model) []ciliumv2.XDSResource {
	listener, routeConfig, clusters := i.getListener(m), i.getRouteConfiguration(m), i.getClusters(m)
	res := make([]ciliumv2.XDSResource, 0, len(listener)+len(routeConfig)+len(clusters))
	res = append(res, listener...)
	res = append(res, routeConfig...)
	res = append(res, clusters...)
	return res
}

// getListener returns the listener for the given model. Only one single
// listener is returned for shared LB mode, tls and non-tls filters are
// applied by default.
func (i *defaultTranslator) getListener(m *model.Model) []ciliumv2.XDSResource {
	var tlsMap = make(map[model.TLSSecret][]string)
	for _, h := range m.HTTP {
		for _, s := range h.TLS {
			tlsMap[s] = append(tlsMap[s], h.Hostname)
		}
	}

	l, _ := NewListenerWithDefaults("listener", i.secretsNamespace, tlsMap)
	return []ciliumv2.XDSResource{l}
}

// getRouteConfiguration returns the route configuration for the given model.
func (i *defaultTranslator) getRouteConfiguration(m *model.Model) []ciliumv2.XDSResource {
	portHostName := map[string][]string{}
	hostNameRoutes := map[string][]model.HTTPRoute{}

	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			port := "insecure"
			if l.TLS != nil {
				port = "secure"
			}

			if len(r.Hostnames) == 0 {
				portHostName[port] = append(portHostName[port], l.Hostname)
				hostNameRoutes[l.Hostname] = append(hostNameRoutes[l.Hostname], r)
				continue
			}
			for _, h := range r.Hostnames {
				portHostName[port] = append(portHostName[port], h)
				hostNameRoutes[h] = append(hostNameRoutes[h], r)
			}
		}
	}

	var res []ciliumv2.XDSResource

	for _, port := range []string{insecureHost, secureHost} {
		hostNames, exists := portHostName[port]
		if !exists {
			continue
		}
		var virtualhosts []*envoy_config_route_v3.VirtualHost

		redirectedHost := map[string]struct{}{}
		// Add HTTPs redirect virtual host for secure host
		if port == insecureHost && i.enforceHTTPs {
			for _, h := range unique(portHostName[secureHost]) {
				vhs, _ := NewVirtualHostWithDefaults([]string{h}, true, i.hostNameSuffixMatch, hostNameRoutes[h])
				virtualhosts = append(virtualhosts, vhs)
				redirectedHost[h] = struct{}{}
			}
		}
		for _, h := range unique(hostNames) {
			if port == insecureHost {
				if _, ok := redirectedHost[h]; ok {
					continue
				}
			}
			routes, exists := hostNameRoutes[h]
			if !exists {
				continue
			}
			vhs, _ := NewVirtualHostWithDefaults([]string{h}, false, i.hostNameSuffixMatch, routes)
			virtualhosts = append(virtualhosts, vhs)
		}

		// the route name should match the value in http connection manager
		// otherwise the request will be dropped by envoy
		routeName := fmt.Sprintf("listener-%s", port)
		rc, _ := NewRouteConfiguration(routeName, virtualhosts)
		res = append(res, rc)
	}
	return res
}

func (i *defaultTranslator) getClusters(m *model.Model) []ciliumv2.XDSResource {
	namespaceNamePortMap := getNamespaceNamePortsMap(m)

	var sortedClusterNames []string
	for ns, v := range namespaceNamePortMap {
		for name, ports := range v {
			for _, port := range ports {
				// the name is having the format of "namespace/name:port"
				sortedClusterNames = append(sortedClusterNames, fmt.Sprintf("%s/%s:%s", ns, name, port))
			}
		}
	}
	sort.Strings(sortedClusterNames)

	res := make([]ciliumv2.XDSResource, 0, len(sortedClusterNames))
	for _, name := range sortedClusterNames {
		c, _ := NewClusterWithDefaults(name)
		res = append(res, c)
	}

	return res
}

// getNamespaceNamePortsMap returns a map of namespace -> name -> ports.
// The ports are sorted and unique.
func getNamespaceNamePortsMap(m *model.Model) map[string]map[string][]string {
	namespaceNamePortMap := map[string]map[string][]string{}
	for _, l := range m.HTTP {
		for _, r := range l.Routes {
			for _, be := range r.Backends {
				namePortMap, exist := namespaceNamePortMap[be.Namespace]
				if exist {
					namePortMap[be.Name] = sortAndUnique(append(namePortMap[be.Name], be.Port.GetPort()))
				} else {
					namePortMap = map[string][]string{
						be.Name: {be.Port.GetPort()},
					}
				}
				namespaceNamePortMap[be.Namespace] = namePortMap
			}
		}
	}
	return namespaceNamePortMap
}

func sortAndUnique(arr []string) []string {
	res := unique(arr)
	sort.Strings(res)
	return res
}

// unique returns a unique slice of strings. The order of the elements is
// preserved.
func unique(arr []string) []string {
	m := map[string]struct{}{}
	for _, s := range arr {
		m[s] = struct{}{}
	}

	res := make([]string, 0, len(m))
	for _, v := range arr {
		if _, exists := m[v]; !exists {
			continue
		}
		res = append(res, v)
		delete(m, v)
	}
	return res
}
